"""p_inject (plan §13) and p_misaligned (plan §12): class-balanced LogisticRegression models."""
from __future__ import annotations

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from ..config import SEED


def make_injection_model() -> Pipeline:
    """MiniLM embeddings + engineered text features -> LogisticRegression."""
    return Pipeline([
        ("scaler", StandardScaler()),
        ("lr", LogisticRegression(C=0.05, class_weight="balanced", max_iter=2000, random_state=SEED)),
    ])


def make_misalignment_model() -> Pipeline:
    """Semantic/text alignment features -> LogisticRegression (no deep classifier)."""
    return Pipeline([
        ("scaler", StandardScaler()),
        ("lr", LogisticRegression(C=0.1, class_weight="balanced", max_iter=2000, random_state=SEED)),
    ])


def predict_positive(model, X: np.ndarray) -> np.ndarray:
    return np.clip(model.predict_proba(X)[:, 1], 0.0, 1.0)
