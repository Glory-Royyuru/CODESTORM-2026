"""Shared, deterministic feature pipeline used by BOTH training and inference.

Training converts every AgentDrift step into an ``MLRequest`` (task, tool, arguments, observation,
previous steps, world as ``known_entities``) and runs exactly the same code as ``SATGMLModel.predict``.
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from ..data.cleaning import WorldAnonymizer, canonical_json, clean_arguments, normalize_text
from ..data.schema import Trajectory
from ..inference.schema import MLRequest
from .sequence_features import TrigramModel
from .session_features import BEHAVIOR_FEATURES, session_features
from .text_features import (LEXICAL_FEATURES, SIMILARITY_FEATURES, Embedder, action_text,
                            cosine_rows, lexical_features, tool_description)


def _step_get(step: dict, *keys, default=None):
    for k in keys:
        if k in step and step[k] is not None:
            return step[k]
    return default


@dataclass
class PreparedStep:
    """Cleaned view of one request (current step + causal history)."""
    task_anon: str
    obs_anon: str
    action_anon: str
    tool_desc: str
    tools: list
    args_json: list
    observations: list
    known_domains: set
    known_emails: set


def prepare(req: MLRequest) -> PreparedStep:
    known = req.session_features.get("known_entities") or {}
    anon = WorldAnonymizer(known)
    domain = normalize_text(req.session_features.get("domain", ""))
    tools, args_json, observations = [], [], []
    for s in req.previous_steps or []:
        if not isinstance(s, dict):
            continue
        tools.append(normalize_text(_step_get(s, "tool_name", "tool", default="")))
        args_json.append(canonical_json(clean_arguments(_step_get(s, "arguments", "args", default={}))))
        observations.append(normalize_text(_step_get(s, "observation", "obs", default="")))
    tool = normalize_text(req.tool_name)
    args = canonical_json(clean_arguments(req.arguments))
    obs = normalize_text(req.current_observation)
    tools.append(tool)
    args_json.append(args)
    observations.append(obs)
    desc = normalize_text(req.tool_description) or tool_description(tool, domain)
    return PreparedStep(
        task_anon=anon(normalize_text(req.task_text)),
        obs_anon=anon(obs),
        action_anon=anon(action_text(tool, args)),
        tool_desc=desc,
        tools=tools, args_json=args_json, observations=observations,
        known_domains=anon.known_domains, known_emails=anon.known_emails,
    )


@dataclass
class BaseFeatures:
    emb_task: np.ndarray
    emb_obs: np.ndarray
    emb_action: np.ndarray
    sims: np.ndarray        # (N, 4)  SIMILARITY_FEATURES
    lexical: np.ndarray     # (N, 8)  LEXICAL_FEATURES
    behaviour: np.ndarray   # (N, 11) BEHAVIOR_FEATURES
    context: np.ndarray     # (N, 6)  config.CONTEXT_FEATURES
    surprisal: np.ndarray   # (N,)    normalised trigram surprisal

    def __len__(self):
        return len(self.surprisal)


def injection_matrix(bf: BaseFeatures) -> np.ndarray:
    """p_inject input: MiniLM(observation) + MiniLM(action) + similarities + lexical (plan §13)."""
    return np.hstack([bf.emb_obs, bf.emb_action, bf.sims, bf.lexical]).astype(np.float32)


def misalignment_matrix(bf: BaseFeatures) -> np.ndarray:
    """p_misaligned input: semantic alignment features only (plan §12)."""
    return np.hstack([bf.sims, bf.lexical, bf.emb_task * bf.emb_action]).astype(np.float32)


def compute_base_features(requests: list[MLRequest], embedder: Embedder, trigram: TrigramModel | None,
                          corpus_cache: str | None = None) -> BaseFeatures:
    prepared = [prepare(r) for r in requests]
    return compute_from_prepared(prepared, embedder, trigram, corpus_cache)


def compute_from_prepared(prepared: list[PreparedStep], embedder: Embedder, trigram: TrigramModel | None,
                          corpus_cache: str | None = None) -> BaseFeatures:
    texts_task = [p.task_anon for p in prepared]
    texts_obs = [p.obs_anon for p in prepared]
    texts_act = [p.action_anon for p in prepared]
    texts_desc = [p.tool_desc for p in prepared]
    if corpus_cache:
        from pathlib import Path
        all_texts = texts_task + texts_obs + texts_act + texts_desc
        emb = embedder.encode_corpus(all_texts, cache_file=Path(corpus_cache))
    else:
        emb = embedder.encode(texts_task + texts_obs + texts_act + texts_desc)
    n = len(prepared)
    e_task, e_obs, e_act, e_desc = emb[:n], emb[n:2 * n], emb[2 * n:3 * n], emb[3 * n:]
    sims = np.stack([
        cosine_rows(e_task, e_obs),
        cosine_rows(e_task, e_act),
        cosine_rows(e_task, e_desc),
        cosine_rows(e_obs, e_act),
    ], axis=1).astype(np.float32)
    lex = np.array([[lexical_features(p.observations[-1], p.args_json[-1], p.known_domains,
                                      p.known_emails)[k] for k in LEXICAL_FEATURES] for p in prepared],
                   dtype=np.float32).reshape(n, len(LEXICAL_FEATURES))
    beh, ctx, sur = sequence_parts(prepared, trigram)
    return BaseFeatures(emb_task=e_task, emb_obs=e_obs, emb_action=e_act, sims=sims, lexical=lex,
                        behaviour=beh, context=ctx, surprisal=sur)


def sequence_parts(prepared: list[PreparedStep], trigram: TrigramModel | None):
    """Trigram-dependent parts: behaviour features, context features, normalised surprisal."""
    beh, ctx, sur = [], [], []
    for p in prepared:
        b, c = session_features(p.tools, p.args_json, p.observations, p.known_domains, p.known_emails, trigram)
        beh.append([b[k] for k in BEHAVIOR_FEATURES])
        ctx.append(list(c.values()))
        sur.append(trigram.normalized_surprisal(p.tools[:-1], p.tools[-1]) if trigram is not None else 0.0)
    n = len(prepared)
    return (np.asarray(beh, dtype=np.float32).reshape(n, len(BEHAVIOR_FEATURES)),
            np.asarray(ctx, dtype=np.float32).reshape(n, 6),
            np.asarray(sur, dtype=np.float32))


def trajectory_to_requests(traj: Trajectory) -> list[MLRequest]:
    """One MLRequest per step, with the causal history as ``previous_steps``."""
    reqs = []
    prev: list[dict] = []
    for s in traj.steps:
        reqs.append(MLRequest(
            request_id=f"{traj.trajectory_id}#{s.index}",
            task_text=traj.task_text,
            tool_name=s.tool,
            tool_description="",
            arguments=s.arguments,
            current_observation=s.observation,
            previous_steps=list(prev),
            session_features={"known_entities": traj.world, "domain": traj.domain},
        ))
        prev.append({"tool_name": s.tool, "arguments": s.arguments, "observation": s.observation})
    return reqs


def session_prefix_requests(req: MLRequest) -> list[MLRequest]:
    """Expands a request into one request per session step (history prefixes) for CUSUM."""
    out = []
    steps = [s for s in (req.previous_steps or []) if isinstance(s, dict)]
    for i, s in enumerate(steps):
        out.append(MLRequest(
            request_id=f"{req.request_id}#h{i}",
            task_text=req.task_text,
            tool_name=_step_get(s, "tool_name", "tool", default=""),
            tool_description=_step_get(s, "tool_description", default="") or "",
            arguments=_step_get(s, "arguments", "args", default={}) or {},
            current_observation=_step_get(s, "observation", "obs", default="") or "",
            previous_steps=steps[:i],
            session_features=req.session_features,
        ))
    out.append(req)
    return out


__all__ = ["BaseFeatures", "compute_base_features", "compute_from_prepared", "prepare", "injection_matrix",
           "misalignment_matrix", "trajectory_to_requests", "session_prefix_requests",
           "SIMILARITY_FEATURES", "LEXICAL_FEATURES", "BEHAVIOR_FEATURES"]
