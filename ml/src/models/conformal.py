"""Lightweight split-conformal abstention (plan §22).

Method (Mondrian / class-conditional split conformal, LAC score):
  * nonconformity of a calibration example with true label y: s = 1 - p_y   (p = calibrated fused risk)
  * per class y: q_y = the ceil((n_y + 1)(1 - alpha)) / n_y empirical quantile of s over class-y examples
  * prediction set for a new point: {y : 1 - p_y <= q_y}
  * conformal_abstain = True  iff the prediction set is not a singleton (both labels plausible, or none)
This is a split-conformal *style* uncertainty flag, not a full conformal risk-control framework.
"""
from __future__ import annotations

import json
import math
from pathlib import Path

import numpy as np


class ConformalAbstainer:
    def __init__(self, alpha: float = 0.1):
        self.alpha = alpha
        self.q = {0: 1.0, 1: 1.0}
        self.n = {0: 0, 1: 0}

    def fit(self, p: np.ndarray, y: np.ndarray) -> "ConformalAbstainer":
        p = np.asarray(p, dtype=float)
        y = np.asarray(y, dtype=int)
        for cls in (0, 1):
            s = (1 - p[y == 1]) if cls == 1 else p[y == 0]  # 1 - p_y
            n = len(s)
            self.n[cls] = int(n)
            if n == 0:
                self.q[cls] = 1.0
                continue
            level = min(1.0, math.ceil((n + 1) * (1 - self.alpha)) / n)
            self.q[cls] = float(np.quantile(s, level, method="higher"))
        return self

    def prediction_set(self, p: float) -> list[int]:
        out = []
        if p <= self.q[0]:          # 1 - p_0 = p
            out.append(0)
        if (1 - p) <= self.q[1]:    # 1 - p_1 = 1 - p
            out.append(1)
        return out

    def abstain(self, p) -> np.ndarray:
        p = np.atleast_1d(np.asarray(p, dtype=float))
        in0 = p <= self.q[0]
        in1 = (1 - p) <= self.q[1]
        return ~(in0 ^ in1)

    def uncertainty_region(self) -> list[float]:
        """Fused-risk interval in which the flag is raised (both labels in the set)."""
        lo, hi = 1 - self.q[1], self.q[0]
        return [float(lo), float(hi)] if lo <= hi else [float(hi), float(lo)]

    def to_json(self) -> dict:
        return {
            "method": "Mondrian (class-conditional) split conformal, LAC nonconformity s = 1 - p_y",
            "alpha": self.alpha,
            "target_coverage": 1 - self.alpha,
            "q_class0": self.q[0], "q_class1": self.q[1],
            "n_class0": self.n[0], "n_class1": self.n[1],
            "abstain_rule": "abstain iff prediction set {y : 1 - p_y <= q_y} is not a singleton",
            "uncertainty_region_fused_risk": self.uncertainty_region(),
            "calibration_set": "validation part B (task-disjoint from fusion fitting and from isotonic calibration)",
            "note": "Split-conformal style uncertainty flag; not a full conformal risk-control framework.",
        }

    def save(self, path: Path) -> None:
        Path(path).write_text(json.dumps(self.to_json(), indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> "ConformalAbstainer":
        d = json.loads(Path(path).read_text(encoding="utf-8"))
        c = cls(alpha=d["alpha"])
        c.q = {0: d["q_class0"], 1: d["q_class1"]}
        c.n = {0: d["n_class0"], 1: d["n_class1"]}
        return c
