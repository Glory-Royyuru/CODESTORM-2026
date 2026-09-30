"""MLRiskEngine: turn a canonical, deterministically-allowed call into an
auditable MLAssessment. It never decides ALLOW/BLOCK (decision_engine.py
does), never executes anything, and never raises: failures come back as an
assessment with status "unavailable" or "error"."""

import logging
import math
import time

from app.config import Settings
from app.gateway.registry import RegisteredTool
from app.ml.feature_extractor import build_ml_request
from app.ml.model_loader import ModelUnavailable, get_model
from app.models.envelope import ToolCallEnvelope
from app.models.verdict import MLAssessment, MLFactor

_log = logging.getLogger("satg.ml")

SIGNALS = ("p_inject", "p_misaligned", "anomaly_score", "sequence_surprisal", "context_shift")
# Threshold the ML package used for its reported precision/recall (ml/README.md §9).
PREDICTION_THRESHOLD = 0.5


def _finite(value) -> float:
    value = float(value)
    if not math.isfinite(value):
        raise ValueError("non-finite model output")
    return round(value, 6)


class MLRiskEngine:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def assess(self, envelope: ToolCallEnvelope, tool: RegisteredTool) -> MLAssessment:
        mode = self.settings.ml_mode
        if mode == "off":
            return MLAssessment(status="disabled", mode=mode)
        try:
            loaded = get_model(self.settings)
        except ModelUnavailable as error:
            return MLAssessment(status="unavailable", mode=mode, detail=str(error))

        request, context_used = build_ml_request(envelope, tool)
        started = time.perf_counter()
        try:
            result = loaded.model.predict(request)
            risk = _finite(result.fused_risk)
            if not 0.0 <= risk <= 1.0:
                raise ValueError("fused_risk outside [0, 1]")
            signals = {name: _finite(getattr(result, name)) for name in SIGNALS}
            features = {
                name: _finite(value)
                for name, value in result.risk_vector.items()
                if isinstance(value, (int, float)) and not isinstance(value, bool)
            }
            factors = [
                MLFactor(feature=str(f["feature"]), value=_finite(f["value"]), contribution=_finite(f["contribution"]))
                for f in result.top_risk_features
            ]
            level = loaded.ml_level(result)
        except Exception as error:
            _log.exception("ML inference failed for %s", envelope.request_id)
            return MLAssessment(
                status="error", mode=mode, model_version=loaded.model_version,
                feature_version=loaded.feature_version, detail=f"inference failed ({type(error).__name__})",
            )
        return MLAssessment(
            status="ok",
            mode=mode,
            model_version=result.model_version,
            feature_version=result.feature_version,
            risk_score=risk,
            risk_level=level,
            prediction="risky" if risk >= PREDICTION_THRESHOLD else "benign",
            conformal_abstain=bool(result.conformal_abstain),
            signals=signals,
            features=features,
            top_factors=factors,
            context_used=context_used,
            latency_ms=round((time.perf_counter() - started) * 1000, 1),
        )
