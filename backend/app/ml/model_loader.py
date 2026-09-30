"""Load the SATG ML package (ml/) once per process and reuse it.

The package's public API (ml/src/inference) is used as-is; nothing here
trains or modifies the model. A failed load is remembered, so a missing or
corrupted model is not re-read on every request; `reset()` clears it.
"""

import importlib
import logging
import sys
import threading
from dataclasses import dataclass
from typing import Any, Optional

from app.config import Settings

_log = logging.getLogger("satg.ml")


class ModelUnavailable(Exception):
    """The model could not be loaded; the reason is safe to show."""


@dataclass
class LoadedModel:
    model: Any
    ml_level: Any  # gateway_adapter.ml_level(result) -> SATG level name
    model_version: str
    feature_version: str


_lock = threading.Lock()
_loaded: Optional[LoadedModel] = None
_failure: Optional[str] = None


def get_model(settings: Settings) -> LoadedModel:
    global _loaded, _failure
    if _loaded is not None:
        return _loaded
    with _lock:
        if _loaded is not None:
            return _loaded
        if _failure is not None:
            raise ModelUnavailable(_failure)
        try:
            _loaded = _load(settings)
            _log.info("ML model %s loaded from %s", _loaded.model_version, settings.ml_model_path)
            return _loaded
        except ModelUnavailable as error:
            _failure = str(error)
        except Exception as error:  # corrupted artifact, missing dependency, ...
            _log.exception("ML model failed to load")
            _failure = f"model failed to load ({type(error).__name__})"
        raise ModelUnavailable(_failure)


def _load(settings: Settings) -> LoadedModel:
    if not (settings.ml_package_dir / "src" / "inference" / "engine.py").is_file():
        raise ModelUnavailable("ML package not found (ML_PACKAGE_DIR)")
    if not (settings.ml_model_path / "model_metadata.json").is_file():
        raise ModelUnavailable("model artifacts not found (ML_MODEL_PATH)")
    package_dir = str(settings.ml_package_dir)
    if package_dir not in sys.path:
        sys.path.insert(0, package_dir)
    engine = importlib.import_module("src.inference.engine")
    adapter = importlib.import_module("src.inference.gateway_adapter")
    model = engine.SATGMLModel()
    model.load(settings.ml_model_path)
    if model.model_version != settings.ml_model_version:
        raise ModelUnavailable(f"model version {model.model_version} != expected ML_MODEL_VERSION {settings.ml_model_version}")
    return LoadedModel(model, adapter.ml_level, model.model_version, model.feature_version)


def reset() -> None:
    """Forget the loaded model or the remembered failure (tests, reloads)."""
    global _loaded, _failure
    with _lock:
        _loaded = None
        _failure = None
