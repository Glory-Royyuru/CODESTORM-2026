"""Central configuration: paths, versions and fixed hyper-parameters."""
from __future__ import annotations

from pathlib import Path

ML_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ML_ROOT / "data"
RAW_DIR = DATA_DIR / "raw"
PROCESSED_DIR = DATA_DIR / "processed"
SPLITS_DIR = DATA_DIR / "splits"
CACHE_DIR = DATA_DIR / "cache"
MODELS_DIR = ML_ROOT / "models"
ARTIFACT_DIR = ML_ROOT / "artifacts"
CONFIG_DIR = ML_ROOT / "configs"

AGENTDRIFT_DIR = RAW_DIR / "AgentDrift"
AGENTDRIFT_SPLIT = "data_taskdisjoint"  # plan §9: task-disjoint split, never a random step split

MODEL_VERSION = "satg-ml-v0.1"
FEATURE_VERSION = "1.0"
EMBEDDING_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
EMBEDDING_DIM = 384
SEED = 42

# Plan §8 target A (step level)
STEP_LABEL_MAP = {
    "benign": 0,
    "failed_injection": 0,
    "injection_point": 1,
    "hijacked": 1,
}
VALID_CATEGORIES = {"benign", "attacked", "failed_attack", "hard_negative"}

# Plan §18: exact M6 fusion feature ordering (persisted to artifacts/feature_schema.json)
SIGNAL_FEATURES = [
    "p_inject",
    "p_misaligned",
    "anomaly_score",
    "sequence_surprisal",
    "context_shift",
]
CONTEXT_FEATURES = [
    "tool_risk_tier",
    "session_step_count",
    "unique_tool_count",
    "destination_change_count",
    "argument_size",
    "observation_size",
]
FUSION_FEATURES = SIGNAL_FEATURES + CONTEXT_FEATURES
# Plan §20: +1 for the five security signals, 0 (unconstrained) for context features
MONOTONE_CONSTRAINTS = [1] * len(SIGNAL_FEATURES) + [0] * len(CONTEXT_FEATURES)

# Plan §19: tiny predefined candidate set, no big search
XGB_CANDIDATES = [
    dict(n_estimators=150, max_depth=3, learning_rate=0.1),
    dict(n_estimators=250, max_depth=4, learning_rate=0.05),
    dict(n_estimators=200, max_depth=5, learning_rate=0.03),
]
XGB_COMMON = dict(subsample=0.8, colsample_bytree=0.8, eval_metric="logloss",
                  tree_method="hist", random_state=SEED, n_jobs=4)

ISOTONIC_MIN_CAL_SAMPLES = 1000  # plan §21: isotonic only if the calibration set is large enough
CONFORMAL_ALPHA = 0.05           # plan §22 "conservative quantile": 95% per-class coverage (0.10 gave an empty region, see madhuri.md E6)
