"""Integration adapter: deterministic decision + MLRiskResult -> final decision (plan §23, §32).

Security invariant: ML can escalate; ML can NEVER turn a deterministic BLOCK into ALLOW.
The fused decision is max(deterministic_level, ml_level) over a monotone hierarchy, so it can only move
towards more restriction. If the ML layer is unavailable/errors, the deterministic decision stands.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from ..config import CONFIG_DIR
from .schema import MLRiskResult

HIERARCHY = ["ALLOW", "MONITOR", "STEP_UP", "HUMAN_APPROVAL", "QUARANTINE", "BLOCK"]
LEVEL = {d: i for i, d in enumerate(HIERARCHY)}


@lru_cache(maxsize=1)
def load_thresholds(path: str | None = None) -> dict:
    p = Path(path) if path else CONFIG_DIR / "decision_thresholds.json"
    return json.loads(p.read_text(encoding="utf-8"))


def ml_level(ml: MLRiskResult, thresholds: dict | None = None) -> str:
    th = thresholds or load_thresholds()
    level = "ALLOW"
    for name in ("MONITOR", "STEP_UP", "HUMAN_APPROVAL", "QUARANTINE", "BLOCK"):
        if ml.fused_risk >= th["fused_risk"][name]:
            level = name
    if ml.conformal_abstain and LEVEL[level] < LEVEL[th["abstain_minimum_level"]]:
        level = th["abstain_minimum_level"]
    return level


def fuse_decision(deterministic_decision: str, ml: MLRiskResult | None, binary_gateway: bool = False,
                  thresholds: dict | None = None) -> str:
    det = deterministic_decision.upper()
    if det not in LEVEL:
        raise ValueError(f"unknown deterministic decision {deterministic_decision!r}")
    if det == "BLOCK":
        return "BLOCK"                      # hard veto: never consult ML
    if ml is None:
        final = det                         # ML unavailable -> deterministic decision stands
    else:
        lvl = ml_level(ml, thresholds)
        final = HIERARCHY[max(LEVEL[det], LEVEL[lvl])]
    if binary_gateway:                      # existing gateway only knows ALLOW / BLOCK
        th = thresholds or load_thresholds()
        return "BLOCK" if LEVEL[final] >= LEVEL[th["binary_block_at_or_above"]] else "ALLOW"
    return final
