"""Centralised gateway configuration, read from environment variables.

Every value has a restrictive default. Invalid values raise at load time
rather than being silently replaced.
"""

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

SANDBOX_MODES = ("docker", "off")
# required: ML failure or timeout blocks (ML-003, fail closed). Shipped default.
# advisory: ML failure keeps the deterministic decision (ml/integration_contract.md §1.4)
# off:      ML is not consulted
ML_MODES = ("advisory", "required", "off")


@dataclass(frozen=True)
class Settings:
    # "off" returns verdicts only and never starts a container.
    sandbox_mode: str
    sandbox_image: str
    sandbox_memory: str
    sandbox_cpus: str
    sandbox_pids_limit: int
    sandbox_timeout: float
    sandbox_max_output_bytes: int
    docker_bin: str

    ml_mode: str
    ml_package_dir: Path
    ml_model_path: Path
    ml_model_version: str
    # fused_risk >= high -> ESCALATE (review; never executed)
    ml_high_risk_threshold: float
    # fused_risk >= critical -> BLOCK
    ml_critical_risk_threshold: float
    # Upper bound on one prediction (model loading is not included).
    ml_timeout_seconds: float


def _env(name: str, default: str) -> str:
    value = os.environ.get(name)
    return default if value is None or value.strip() == "" else value.strip()


def _choice(name: str, default: str, allowed: tuple) -> str:
    value = _env(name, default).lower()
    if value not in allowed:
        raise ValueError(f"{name} must be one of {allowed}, got {value!r}")
    return value


def _number(name: str, default: str, cast, low, high):
    raw = _env(name, default)
    try:
        value = cast(raw)
    except ValueError:
        raise ValueError(f"{name} must be a number, got {raw!r}") from None
    if not low <= value <= high:
        raise ValueError(f"{name} must be within [{low}, {high}], got {value}")
    return value


def load_settings() -> Settings:
    high = _number("ML_HIGH_RISK_THRESHOLD", "0.60", float, 0.0, 1.0)
    critical = _number("ML_CRITICAL_RISK_THRESHOLD", "0.80", float, 0.0, 1.0)
    if high > critical:
        raise ValueError("ML_HIGH_RISK_THRESHOLD must not exceed ML_CRITICAL_RISK_THRESHOLD")
    memory = _env("SANDBOX_MEMORY", "256m")
    cpus = _env("SANDBOX_CPUS", "0.5")
    if not memory[:-1].isdigit() or memory[-1].lower() not in "kmg":
        raise ValueError(f"SANDBOX_MEMORY must look like 256m, got {memory!r}")
    _number("SANDBOX_CPUS", cpus, float, 0.05, 4.0)
    ml_dir = Path(_env("ML_PACKAGE_DIR", str(REPO_ROOT / "ml")))
    return Settings(
        sandbox_mode=_choice("SANDBOX_MODE", "docker", SANDBOX_MODES),
        sandbox_image=_env("SANDBOX_IMAGE", "satg-sandbox:0.1"),
        sandbox_memory=memory,
        sandbox_cpus=cpus,
        sandbox_pids_limit=_number("SANDBOX_PIDS_LIMIT", "64", int, 8, 1024),
        sandbox_timeout=_number("SANDBOX_TIMEOUT", "10", float, 1.0, 120.0),
        sandbox_max_output_bytes=_number("SANDBOX_MAX_OUTPUT_BYTES", "16384", int, 1024, 1_048_576),
        docker_bin=_env("DOCKER_BIN", "docker"),
        ml_mode=_choice("ML_MODE", "required", ML_MODES),
        ml_package_dir=ml_dir,
        ml_model_path=Path(_env("ML_MODEL_PATH", str(ml_dir / "artifacts"))),
        ml_model_version=_env("ML_MODEL_VERSION", "satg-ml-v0.1"),
        ml_high_risk_threshold=high,
        ml_critical_risk_threshold=critical,
        ml_timeout_seconds=_number("ML_TIMEOUT_SECONDS", "3.0", float, 0.1, 30.0),
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return load_settings()
