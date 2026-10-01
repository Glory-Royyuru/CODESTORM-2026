"""Assembles the five M6 signals and the fusion feature vector (plan §18).

Shared by training (with out-of-fold component models) and inference (with the final artifacts).
"""
from __future__ import annotations

import numpy as np

from ..config import FUSION_FEATURES
from ..features.pipeline import BaseFeatures, injection_matrix, misalignment_matrix
from ..features.statistical_features import CusumConfig
from .text_classifiers import predict_positive


def cusum_input(p_inject: np.ndarray, p_misaligned: np.ndarray) -> np.ndarray:
    """Per-step behavioural risk x_t fed to CUSUM."""
    return np.maximum(p_inject, p_misaligned)


def run_cusum(x: np.ndarray, session_ids: np.ndarray, cfg: CusumConfig) -> np.ndarray:
    """CUSUM over rows ordered by (session, step); resets whenever the session id changes."""
    out = np.zeros(len(x), dtype=np.float32)
    s, prev = 0.0, None
    for i, (xi, sid) in enumerate(zip(x, session_ids)):
        if sid != prev:
            s, prev = 0.0, sid
        s = cfg.update(s, xi)
        out[i] = cfg.normalize(s)
    return out


def assemble(p_inject, p_misaligned, anomaly, surprisal, context_shift, context) -> np.ndarray:
    X = np.column_stack([p_inject, p_misaligned, anomaly, surprisal, context_shift, context]).astype(np.float32)
    assert X.shape[1] == len(FUSION_FEATURES)
    return X


def compute_signals(bf: BaseFeatures, session_ids: np.ndarray, inj_model, mis_model, anomaly_model,
                    cusum_cfg: CusumConfig) -> tuple[np.ndarray, dict]:
    """Returns (fusion matrix N x 11, dict of the five signal arrays)."""
    p_inj = predict_positive(inj_model, injection_matrix(bf))
    p_mis = predict_positive(mis_model, misalignment_matrix(bf))
    anom = anomaly_model.score(bf.behaviour)
    shift = run_cusum(cusum_input(p_inj, p_mis), session_ids, cusum_cfg)
    X = assemble(p_inj, p_mis, anom, bf.surprisal, shift, bf.context)
    return X, {"p_inject": p_inj, "p_misaligned": p_mis, "anomaly_score": anom,
               "sequence_surprisal": bf.surprisal, "context_shift": shift}
