"""M7 risk fusion (plan §19–20, §24): monotone XGBoost over the M6 feature vector."""
from __future__ import annotations

import numpy as np
import xgboost as xgb
from sklearn.metrics import average_precision_score

from ..config import FUSION_FEATURES, MONOTONE_CONSTRAINTS, XGB_CANDIDATES, XGB_COMMON


def make_fusion(params: dict, scale_pos_weight: float = 1.0) -> xgb.XGBClassifier:
    return xgb.XGBClassifier(**params, **XGB_COMMON, scale_pos_weight=scale_pos_weight,
                             monotone_constraints="(" + ",".join(map(str, MONOTONE_CONSTRAINTS)) + ")")


def train_fusion(X: np.ndarray, y: np.ndarray, X_sel: np.ndarray, y_sel: np.ndarray):
    """Fits the tiny predefined candidate set; selects by PR-AUC on the selection (validation) set."""
    results = []
    best, best_score = None, -1.0
    for params in XGB_CANDIDATES:
        m = make_fusion(params)
        m.fit(X, y)
        ap = float(average_precision_score(y_sel, m.predict_proba(X_sel)[:, 1]))
        results.append({"params": params, "val_pr_auc": ap})
        if ap > best_score:
            best, best_score = m, ap
    return best, results


def fusion_contributions(booster: xgb.Booster, X: np.ndarray) -> np.ndarray:
    """Per-feature additive log-odds contributions (XGBoost native TreeSHAP, last column = bias)."""
    return booster.predict(xgb.DMatrix(X, feature_names=FUSION_FEATURES), pred_contribs=True)


def top_risk_features(x_row: np.ndarray, contrib_row: np.ndarray, k: int = 5) -> list[dict]:
    """Features ranked by their positive contribution to risk (normalised share of |contributions|)."""
    c = contrib_row[:-1]
    total = float(np.sum(np.abs(c))) or 1.0
    order = np.argsort(-c)
    out = []
    for i in order[:k]:
        out.append({"feature": FUSION_FEATURES[i], "value": round(float(x_row[i]), 4),
                    "contribution": round(float(c[i]) / total, 4)})
    return out
