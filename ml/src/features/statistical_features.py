"""Feature group F — CUSUM context shift (plan §17).

S_t = max(0, S_{t-1} + x_t - target - drift), reset at the start of every session.
Normalised: context_shift = 1 - exp(-S_t / h) in [0, 1), where h is the decision interval fitted on
benign sessions (95th percentile of benign S_t).
"""
from __future__ import annotations

import json
import math
from dataclasses import asdict, dataclass
from pathlib import Path

import numpy as np


@dataclass
class CusumConfig:
    target: float = 0.0
    drift: float = 0.05
    h: float = 1.0
    input_signal: str = "max(p_inject, p_misaligned)"

    @classmethod
    def fit(cls, benign_sessions: list[list[float]], drift_std_mult: float = 0.5,
            h_quantile: float = 0.95) -> "CusumConfig":
        xs = np.concatenate([np.asarray(s, dtype=float) for s in benign_sessions if len(s)])
        target = float(np.mean(xs))
        drift = float(drift_std_mult * np.std(xs))
        cfg = cls(target=target, drift=drift, h=1.0)
        finals = []
        for s in benign_sessions:
            finals.extend(cfg.run(s))
        h = float(np.quantile(finals, h_quantile)) if finals else 1.0
        cfg.h = max(h, 0.05)  # floor: avoids a degenerate interval when benign S_t is almost always 0
        return cfg

    def update(self, s_prev: float, x: float) -> float:
        return max(0.0, s_prev + float(x) - self.target - self.drift)

    def run(self, xs: list[float]) -> list[float]:
        s, out = 0.0, []
        for x in xs:
            s = self.update(s, x)
            out.append(s)
        return out

    def normalize(self, s: float) -> float:
        return float(1.0 - math.exp(-max(0.0, s) / self.h))

    def save(self, path: Path) -> None:
        d = asdict(self)
        d["formula"] = "S_t = max(0, S_{t-1} + x_t - target - drift); context_shift = 1 - exp(-S_t / h)"
        d["reset"] = "S_0 = 0 at the beginning of every session"
        Path(path).write_text(json.dumps(d, indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> "CusumConfig":
        d = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(target=d["target"], drift=d["drift"], h=d["h"], input_signal=d.get("input_signal", ""))
