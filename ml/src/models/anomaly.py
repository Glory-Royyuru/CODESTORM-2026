"""Feature group D — IsolationForest behavioural baseline (plan §15).

Fitted on benign behaviour only. The raw score (-decision_function) is NOT a probability; it is mapped to
[0, 1] with the empirical CDF of benign training scores (0 = typical, 1 = more isolated than any benign).

Inference speed: sklearn scores the 200 trees in a Python/joblib loop (~57 ms per request). ``compile()``
flattens the fitted forest into numpy arrays and traverses all trees at once, level by level, reproducing
sklearn's formula exactly (parity is unit-tested): ~0.2 ms per request.
"""
from __future__ import annotations

import numpy as np
from sklearn.ensemble import IsolationForest

from ..config import SEED


def _avg_path_length(n: np.ndarray) -> np.ndarray:
    """c(n): average path length of an unsuccessful BST search (sklearn's _average_path_length)."""
    n = np.asarray(n, dtype=float)
    out = np.zeros_like(n)
    m1 = n <= 1
    m2 = n == 2
    m = ~(m1 | m2)
    out[m2] = 1.0
    out[m] = 2.0 * (np.log(n[m] - 1.0) + np.euler_gamma) - 2.0 * (n[m] - 1.0) / n[m]
    return out


class AnomalyModel:
    def __init__(self, n_estimators: int = 200):
        self.forest = IsolationForest(n_estimators=n_estimators, max_samples=256, contamination="auto",
                                      random_state=SEED, n_jobs=4)
        self.reference: np.ndarray | None = None
        self._compiled: dict | None = None

    def fit(self, X_benign: np.ndarray) -> "AnomalyModel":
        self.forest.fit(X_benign)
        self.compile()
        raw = self.raw_score(X_benign)
        self.reference = np.quantile(raw, np.linspace(0.0, 1.0, 1001))
        return self

    def compile(self) -> "AnomalyModel":
        lefts, rights, feats, thrs, leafval, offsets = [], [], [], [], [], []
        off, max_depth = 0, 0
        for tree, fidx in zip(self.forest.estimators_, self.forest.estimators_features_):
            t = tree.tree_
            n = t.node_count
            depth = np.zeros(n)
            stack = [0]
            while stack:                      # node depths (parents precede children in sklearn trees)
                i = stack.pop()
                for c in (t.children_left[i], t.children_right[i]):
                    if c != -1:
                        depth[c] = depth[i] + 1
                        stack.append(c)
            is_leaf = t.children_left == -1
            max_depth = max(max_depth, int(depth.max()))
            lefts.append(np.where(is_leaf, np.arange(n), t.children_left) + off)
            rights.append(np.where(is_leaf, np.arange(n), t.children_right) + off)
            feats.append(np.where(is_leaf, 0, np.asarray(fidx)[np.maximum(t.feature, 0)]))
            thrs.append(t.threshold)
            # sklearn: nodes on the path (root depth = 1) + c(n_leaf) - 1  ==  edge depth + c(n_leaf)
            leafval.append(np.where(is_leaf, depth + _avg_path_length(t.n_node_samples), 0.0))
            offsets.append(off)
            off += n
        self._compiled = {
            "left": np.concatenate(lefts).astype(np.int64), "right": np.concatenate(rights).astype(np.int64),
            "feature": np.concatenate(feats).astype(np.int64), "threshold": np.concatenate(thrs),
            "leaf_value": np.concatenate(leafval), "roots": np.asarray(offsets, dtype=np.int64),
            "max_depth": max_depth,
            "denominator": len(self.forest.estimators_) * float(_avg_path_length(np.array([self.forest.max_samples_]))[0]),
            "offset": float(self.forest.offset_),
        }
        return self

    def _raw_compiled(self, X: np.ndarray) -> np.ndarray:
        c = self._compiled
        X = np.asarray(X, dtype=np.float32)
        n = X.shape[0]
        idx = np.broadcast_to(c["roots"], (n, len(c["roots"]))).copy()
        rows = np.arange(n)[:, None]
        for _ in range(c["max_depth"]):
            go_left = X[rows, c["feature"][idx]] <= c["threshold"][idx]
            idx = np.where(go_left, c["left"][idx], c["right"][idx])  # leaves point to themselves
        depths = c["leaf_value"][idx].sum(axis=1)
        score_samples = -(2.0 ** (-depths / c["denominator"]))
        return -(score_samples - c["offset"])          # = -decision_function

    def raw_score(self, X: np.ndarray) -> np.ndarray:
        if getattr(self, "_compiled", None) is not None:
            return self._raw_compiled(X)
        return -self.forest.decision_function(X)

    def score(self, X: np.ndarray) -> np.ndarray:
        raw = self.raw_score(X)
        return np.clip(np.searchsorted(self.reference, raw, side="right") / len(self.reference), 0.0, 1.0)
