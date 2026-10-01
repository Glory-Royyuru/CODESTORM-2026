"""Probability calibration (plan §21): isotonic vs sigmoid (Platt), fitted on a held-out set."""
from __future__ import annotations

import numpy as np
from sklearn.isotonic import IsotonicRegression
from sklearn.linear_model import LogisticRegression

EPS = 1e-4


def _logit(p: np.ndarray) -> np.ndarray:
    p = np.clip(p, EPS, 1 - EPS)
    return np.log(p / (1 - p))


class Calibrator:
    def __init__(self, method: str):
        assert method in ("isotonic", "sigmoid")
        self.method = method
        self.model = None

    def fit(self, raw: np.ndarray, y: np.ndarray) -> "Calibrator":
        if self.method == "isotonic":
            self.model = IsotonicRegression(y_min=0.0, y_max=1.0, increasing=True, out_of_bounds="clip")
            self.model.fit(raw, y)
        else:
            self.model = LogisticRegression(C=1e6, max_iter=1000)
            self.model.fit(_logit(raw).reshape(-1, 1), y)
        return self

    def transform(self, raw: np.ndarray) -> np.ndarray:
        raw = np.asarray(raw, dtype=float)
        if self.method == "isotonic":
            p = self.model.predict(raw)
        else:
            p = self.model.predict_proba(_logit(raw).reshape(-1, 1))[:, 1]
        return np.clip(p, EPS, 1 - EPS)
