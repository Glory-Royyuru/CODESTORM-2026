"""SATGMLModel — the single stable inference API (plan §25).

    model = SATGMLModel()
    model.load("artifacts")
    result = model.predict(request)      # MLRequest -> MLRiskResult

No training code runs here. The ML layer never authorises execution; it only returns risk intelligence.
"""
from __future__ import annotations

import json
import os
import time
import warnings
from pathlib import Path

os.environ.setdefault("TRANSFORMERS_VERBOSITY", "error")
os.environ.setdefault("HF_HUB_DISABLE_SYMLINKS_WARNING", "1")
warnings.filterwarnings("ignore", category=UserWarning)

import joblib
import numpy as np
import xgboost as xgb

from ..config import ARTIFACT_DIR, EMBEDDING_MODEL, FUSION_FEATURES
from ..features.pipeline import (compute_from_prepared, prepare, session_prefix_requests,
                                 trajectory_to_requests)
from ..features.sequence_features import TrigramModel
from ..features.statistical_features import CusumConfig
from ..features.text_features import Embedder
from ..models.conformal import ConformalAbstainer
from ..models.fusion import fusion_contributions, top_risk_features
from ..models.signals import compute_signals
from .schema import MLRequest, MLRiskResult


class _OnnxEmbedder(Embedder):
    """Same MiniLM recipe executed by ONNX Runtime (exported graph includes pooling + normalisation)."""

    def __init__(self, onnx_path: Path, tokenizer_dir: Path, cache_size: int = 4096):
        super().__init__(str(tokenizer_dir), cache_size=cache_size)
        import onnxruntime as ort
        from transformers import AutoTokenizer
        so = ort.SessionOptions()
        so.intra_op_num_threads = min(6, os.cpu_count() or 1)  # thread sweep: 1=128ms, 4=23ms, 6=16ms p95
        self._sess = ort.InferenceSession(str(onnx_path), so, providers=["CPUExecutionProvider"])
        self._tok = AutoTokenizer.from_pretrained(str(tokenizer_dir))

    def _encode(self, texts, batch_size: int = 64, show_progress: bool = False):
        if not texts:
            return np.zeros((0, self.dim), dtype=np.float32)
        out = np.zeros((len(texts), self.dim), dtype=np.float32)
        order = np.argsort([len(t) for t in texts])
        for s in range(0, len(texts), batch_size):
            idx = order[s:s + batch_size]
            b = self._tok([texts[i] for i in idx], padding=True, truncation=True,
                          max_length=self.max_seq_length, return_tensors="np")
            feeds = {k: b[k].astype(np.int64) for k in ("input_ids", "attention_mask", "token_type_ids")}
            out[idx] = self._sess.run(None, feeds)[0]
        return out


class _OnnxClassifier:
    """sklearn-compatible predict_proba backed by the exported ONNX graph."""

    def __init__(self, path: Path):
        import onnxruntime as ort
        self._sess = ort.InferenceSession(str(path), providers=["CPUExecutionProvider"])
        self._in = self._sess.get_inputs()[0].name
        outs = [o.name for o in self._sess.get_outputs()]
        self._out = "probabilities" if "probabilities" in outs else outs[-1]

    def predict_proba(self, X):
        return np.asarray(self._sess.run([self._out], {self._in: X.astype(np.float32)})[0])


class SATGMLModel:
    def __init__(self, use_onnx: bool | str = "auto"):
        self.use_onnx = use_onnx
        self.loaded = False
        self.backends: dict[str, str] = {}

    # ------------------------------------------------------------------ load
    def load(self, artifact_dir: str | Path = ARTIFACT_DIR) -> "SATGMLModel":
        art = Path(artifact_dir)
        if not art.is_absolute() and not art.exists():
            art = Path(__file__).resolve().parents[2] / art
        self.artifact_dir = art
        self.metadata = json.loads((art / "model_metadata.json").read_text(encoding="utf-8"))
        self.schema = json.loads((art / "feature_schema.json").read_text(encoding="utf-8"))
        if self.schema["fusion_features"] != FUSION_FEATURES:
            raise ValueError("feature_schema.json does not match the code's fusion feature ordering")
        onnx_ok = self.use_onnx is True or (self.use_onnx == "auto" and _has_onnxruntime())

        self.inj_model = joblib.load(art / "injection_model.joblib")
        self.backends["injection"] = "sklearn"
        if onnx_ok and (art / "injection_model.onnx").exists():
            self.inj_model = _OnnxClassifier(art / "injection_model.onnx")
            self.backends["injection"] = "onnxruntime"
        self.mis_model = joblib.load(art / "misalignment_model.joblib")
        self.anomaly = joblib.load(art / "isolation_forest.joblib")
        if getattr(self.anomaly, "_compiled", None) is None:
            self.anomaly.compile()   # vectorised exact scorer (see src/models/anomaly.py)
        self.trigram = TrigramModel.load(art / "trigram_model.json")
        self.cusum = CusumConfig.load(art / "cusum_config.json")
        self.booster = xgb.Booster()
        self.booster.load_model(art / "fusion_model.json")
        self.booster.feature_names = FUSION_FEATURES
        self.calibrator = joblib.load(art / "calibration.joblib")
        self.conformal = ConformalAbstainer.load(art / "conformal_config.json")

        emb_dir = art / "embedding_model"
        if onnx_ok and (art / "embedding_model.onnx").exists() and (emb_dir / "tokenizer.json").exists():
            self.embedder = _OnnxEmbedder(art / "embedding_model.onnx", emb_dir)
            self.backends["embedding"] = "onnxruntime"
        else:
            self.embedder = Embedder(str(emb_dir) if (emb_dir / "config.json").exists() else EMBEDDING_MODEL)
            self.backends["embedding"] = "torch"
        self.model_version = self.metadata["model_version"]
        self.feature_version = self.metadata["feature_version"]
        self.loaded = True
        return self

    def warmup(self) -> None:
        self.predict(MLRequest(request_id="warmup", task_text="check my balance", tool_name="get_balance"))
        self.embedder._lru.clear()

    # ------------------------------------------------------------------ core
    def _fuse(self, X: np.ndarray):
        raw = self.booster.predict(xgb.DMatrix(X, feature_names=FUSION_FEATURES))
        return raw, self.calibrator.transform(raw)

    def predict(self, request: MLRequest | dict) -> MLRiskResult:
        if not self.loaded:
            raise RuntimeError("call load(artifact_dir) first")
        if isinstance(request, dict):
            request = MLRequest.from_dict(request)
        t0 = time.perf_counter()
        reqs = session_prefix_requests(request)
        prepared = [prepare(r) for r in reqs]
        t1 = time.perf_counter()
        # embedding (LRU-cached: earlier session steps are usually already cached)
        self.embedder.encode([p.task_anon for p in prepared] + [p.obs_anon for p in prepared]
                             + [p.action_anon for p in prepared] + [p.tool_desc for p in prepared])
        t2 = time.perf_counter()
        bf = compute_from_prepared(prepared, self.embedder, self.trigram)
        t3 = time.perf_counter()
        X, sig = compute_signals(bf, np.zeros(len(prepared), dtype=int), self.inj_model, self.mis_model,
                                 self.anomaly, self.cusum)
        raw, cal = self._fuse(X[-1:])
        fused = float(cal[0])
        abstain = bool(self.conformal.abstain(fused)[0])
        contrib = fusion_contributions(self.booster, X[-1:])[0]
        t4 = time.perf_counter()
        row = X[-1]
        risk_vector = {name: round(float(v), 6) for name, v in zip(FUSION_FEATURES, row)}
        risk_vector.update({
            "fusion_raw_probability": round(float(raw[0]), 6),
            "conformal_prediction_set": self.conformal.prediction_set(fused),
            "context_shift_history": [round(float(v), 4) for v in sig["context_shift"]],
            "backends": dict(self.backends),
        })
        return MLRiskResult(
            p_inject=row[0], p_misaligned=row[1], anomaly_score=row[2], sequence_surprisal=row[3],
            context_shift=row[4], fused_risk=fused, risk_vector=risk_vector, conformal_abstain=abstain,
            model_version=self.model_version, feature_version=self.feature_version,
            request_id=request.request_id, top_risk_features=top_risk_features(row, contrib),
            latency_ms={"preprocess": round((t1 - t0) * 1e3, 3), "embedding": round((t2 - t1) * 1e3, 3),
                        "features": round((t3 - t2) * 1e3, 3), "model": round((t4 - t3) * 1e3, 3),
                        "total": round((t4 - t0) * 1e3, 3)},
        )

    # ------------------------------------------------------------------ batch path (evaluation)
    def score_trajectories(self, trajectories, corpus_cache: str | None = None) -> dict:
        """Vectorised scoring of every step of every trajectory; identical maths to ``predict``."""
        reqs, traj_idx = [], []
        for i, t in enumerate(trajectories):
            r = trajectory_to_requests(t)
            reqs.extend(r)
            traj_idx.extend([i] * len(r))
        traj_idx = np.asarray(traj_idx)
        prepared = [prepare(r) for r in reqs]
        bf = compute_from_prepared(prepared, self.embedder, self.trigram, corpus_cache=corpus_cache)
        X, sig = compute_signals(bf, traj_idx, self.inj_model, self.mis_model, self.anomaly, self.cusum)
        raw, cal = self._fuse(X)
        return {"X": X, "signals": sig, "fused_raw": raw, "fused_risk": cal,
                "abstain": self.conformal.abstain(cal), "traj_idx": traj_idx}


def _has_onnxruntime() -> bool:
    try:
        import onnxruntime  # noqa: F401
        return True
    except ImportError:
        return False
