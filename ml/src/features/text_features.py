"""Feature group A — text / intent (plan §11).

Frozen MiniLM sentence embeddings (never fine-tuned) + cosine similarities + lexical features.
"""
from __future__ import annotations

import hashlib
import math
import re
from collections import OrderedDict
from pathlib import Path

import numpy as np

from ..config import EMBEDDING_DIM, EMBEDDING_MODEL
from ..data.cleaning import EMAIL_RE, URL_RE, email_domain

SIMILARITY_FEATURES = [
    "task_observation_similarity",
    "task_action_similarity",
    "task_tool_description_similarity",
    "observation_action_similarity",
]
LEXICAL_FEATURES = [
    "instruction_keyword_count",
    "imperative_keyword_count",
    "external_destination_count",
    "url_count",
    "email_count",
    "encoded_string_count",
    "argument_length",
    "observation_length",
]

_INSTRUCTION_WORDS = [
    "ignore", "disregard", "instead", "override", "instruction", "instructions", "system", "assistant",
    "must", "required", "requires", "mandatory", "policy", "correction", "important", "urgent",
    "immediately", "note", "notice", "attention", "update", "updated", "per", "compliance",
    "security", "audit", "verify", "verification", "recommended", "recommend", "should", "also",
    "new", "previous", "forget", "admin", "administrator", "protocol", "action required",
]
_IMPERATIVE_WORDS = [
    "send", "forward", "transfer", "delete", "remove", "add", "execute", "run", "share", "upload",
    "pay", "click", "download", "change", "grant", "export", "email", "reply", "cc", "bcc",
    "wire", "move", "copy", "post", "push", "install", "disable", "submit", "approve", "create",
]
_INSTR_RE = re.compile(r"\b(" + "|".join(re.escape(w) for w in _INSTRUCTION_WORDS) + r")\b", re.IGNORECASE)
_IMPER_RE = re.compile(r"\b(" + "|".join(re.escape(w) for w in _IMPERATIVE_WORDS) + r")\b", re.IGNORECASE)
_B64_RE = re.compile(r"\b[A-Za-z0-9+/]{24,}={0,2}")
_HEX_RE = re.compile(r"\b(?:0x)?[0-9a-fA-F]{32,}\b")
_PCT_RE = re.compile(r"(?:%[0-9a-fA-F]{2}){3,}")
_URL_HOST_RE = re.compile(r"(?:https?://)?(?:www\.)?([^/\s:?#]+)", re.IGNORECASE)


def tool_description(tool_name: str, domain: str = "") -> str:
    """AgentDrift ships no tool descriptions; derive a deterministic one from the tool name."""
    words = tool_name.replace("_", " ").replace("-", " ").strip()
    return f"{words} ({domain} tool)" if domain else words


def action_text(tool_name: str, canonical_args: str) -> str:
    return f"{tool_name.replace('_', ' ')} {canonical_args}"


def extract_destinations(text: str) -> list[str]:
    """Destination identifiers (email addresses + URL hosts), lower-cased."""
    dests = [m.lower() for m in EMAIL_RE.findall(text)]
    for u in URL_RE.findall(text):
        m = _URL_HOST_RE.match(u)
        if m:
            dests.append(m.group(1).lower())
    return dests


def is_external(dest: str, known_domains: set[str], known_emails: set[str]) -> bool:
    if "@" in dest:
        return dest not in known_emails and email_domain(dest) not in known_domains
    return not any(dest == d or dest.endswith("." + d) for d in known_domains)


def encoded_string_count(text: str) -> int:
    return len(_B64_RE.findall(text)) + len(_HEX_RE.findall(text)) + len(_PCT_RE.findall(text))


def lexical_features(observation: str, args_json: str, known_domains: set[str],
                     known_emails: set[str]) -> dict[str, float]:
    """Computed on cleaned (NOT anonymized) text so destination information is preserved."""
    both = f"{observation} {args_json}"
    dests = extract_destinations(both)
    return {
        "instruction_keyword_count": float(len(_INSTR_RE.findall(observation))),
        "imperative_keyword_count": float(len(_IMPER_RE.findall(both))),
        "external_destination_count": float(len({d for d in dests if is_external(d, known_domains, known_emails)})),
        "url_count": float(len(URL_RE.findall(both))),
        "email_count": float(len(EMAIL_RE.findall(both))),
        "encoded_string_count": float(encoded_string_count(both)),
        "argument_length": math.log1p(len(args_json)),
        "observation_length": math.log1p(len(observation)),
    }


def cosine_rows(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    """Row-wise cosine similarity, clipped to [-1, 1]. Zero vectors -> 0."""
    na = np.linalg.norm(a, axis=-1)
    nb = np.linalg.norm(b, axis=-1)
    denom = na * nb
    sim = np.where(denom > 0, np.sum(a * b, axis=-1) / np.where(denom > 0, denom, 1.0), 0.0)
    return np.clip(sim, -1.0, 1.0)


class Embedder:
    """Frozen MiniLM encoder with an in-memory LRU cache and an optional on-disk cache."""

    def __init__(self, model_name: str = EMBEDDING_MODEL, cache_size: int = 4096, device: str = "cpu"):
        self.model_name = model_name
        self.device = device
        self._model = None
        self._lru: OrderedDict[str, np.ndarray] = OrderedDict()
        self._cache_size = cache_size
        self.dim = EMBEDDING_DIM

    max_seq_length = 256

    @property
    def model(self):
        """(tokenizer, encoder). Uses ``transformers`` directly: sentence-transformers 6.1 cannot build the
        Pooling module of this checkpoint on this stack (see madhuri.md D4). Mean pooling + L2 norm is
        exactly the all-MiniLM-L6-v2 sentence-embedding recipe."""
        if self._model is None:
            from transformers import AutoModel, AutoTokenizer
            try:
                tok = AutoTokenizer.from_pretrained(self.model_name, local_files_only=True)
                enc = AutoModel.from_pretrained(self.model_name, local_files_only=True)
            except OSError:
                tok = AutoTokenizer.from_pretrained(self.model_name)
                enc = AutoModel.from_pretrained(self.model_name)
            enc.eval()
            self._model = (tok, enc)
            self.dim = int(enc.config.hidden_size)
        return self._model

    def _encode(self, texts: list[str], batch_size: int = 64, show_progress: bool = False) -> np.ndarray:
        if not texts:
            return np.zeros((0, self.dim), dtype=np.float32)
        import torch
        tok, enc = self.model
        # sort by length for efficient padding, restore order afterwards
        order = np.argsort([len(t) for t in texts])
        out = np.zeros((len(texts), self.dim), dtype=np.float32)
        n_batches = (len(texts) + batch_size - 1) // batch_size
        with torch.inference_mode():
            for bi in range(n_batches):
                idx = order[bi * batch_size:(bi + 1) * batch_size]
                batch = tok([texts[i] for i in idx], padding=True, truncation=True,
                            max_length=self.max_seq_length, return_tensors="pt")
                hidden = enc(**batch).last_hidden_state
                mask = batch["attention_mask"].unsqueeze(-1).to(hidden.dtype)
                pooled = (hidden * mask).sum(1) / mask.sum(1).clamp(min=1e-9)
                pooled = torch.nn.functional.normalize(pooled, p=2, dim=1)
                out[idx] = pooled.numpy()
                if show_progress and (bi % 50 == 0 or bi == n_batches - 1):
                    print(f"    embedded batch {bi + 1}/{n_batches}", flush=True)
        return out

    def encode(self, texts: list[str]) -> np.ndarray:
        """Inference path: LRU-cached, empty strings map to the zero vector."""
        out = np.zeros((len(texts), self.dim), dtype=np.float32)
        missing: dict[str, list[int]] = {}
        for i, t in enumerate(texts):
            if not t:
                continue
            v = self._lru.get(t)
            if v is not None:
                self._lru.move_to_end(t)
                out[i] = v
            else:
                missing.setdefault(t, []).append(i)
        if missing:
            uniq = list(missing)
            vecs = self._encode(uniq)
            for t, v in zip(uniq, vecs):
                for i in missing[t]:
                    out[i] = v
                self._lru[t] = v
                if len(self._lru) > self._cache_size:
                    self._lru.popitem(last=False)
        return out

    def encode_corpus(self, texts: list[str], cache_file: Path | None = None) -> np.ndarray:
        """Training path: de-duplicates, encodes in large batches, caches to disk by content hash."""
        uniq = sorted({t for t in texts if t})
        key = hashlib.sha256(("\n\x00".join(uniq) + self.model_name).encode("utf-8")).hexdigest()[:16]
        table: dict[str, np.ndarray]
        if cache_file is not None:
            path = Path(f"{cache_file}_{key}.npz")
            if path.exists():
                z = np.load(path, allow_pickle=False)
                table = dict(zip(z["texts"].tolist(), z["emb"]))
            else:
                emb = self._encode(uniq, batch_size=128, show_progress=True)
                path.parent.mkdir(parents=True, exist_ok=True)
                np.savez(path, texts=np.array(uniq, dtype=object).astype(str), emb=emb)
                table = dict(zip(uniq, emb))
        else:
            table = dict(zip(uniq, self._encode(uniq, batch_size=128)))
        out = np.zeros((len(texts), self.dim), dtype=np.float32)
        for i, t in enumerate(texts):
            if t:
                out[i] = table[t]
        return out
