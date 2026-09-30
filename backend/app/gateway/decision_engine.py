"""Final decision: deterministic policy first, then ML.

  deterministic BLOCK                       -> BLOCK (ML is not consulted)
  ML fused_risk >= ML_CRITICAL_RISK_THRESHOLD -> BLOCK    (ML-002)
  ML fused_risk >= ML_HIGH_RISK_THRESHOLD     -> ESCALATE (ML-001; held for review, never executed)
  ML unavailable, ML_MODE=required           -> BLOCK    (ML-003, fail closed)
  ML unavailable, ML_MODE=advisory           -> deterministic decision stands (ml/integration_contract.md §1.4)
  otherwise                                  -> ALLOW

ML can only make a decision more restrictive. The default thresholds are
the existing HUMAN_APPROVAL (0.60) and QUARANTINE / binary-block (0.80)
levels of ml/configs/decision_thresholds.json.
"""

from typing import Optional

from app.config import Settings
from app.models.verdict import DecisionTrace, MLAssessment, Severity, Verdict, VerdictType


def _describe_factors(ml: MLAssessment) -> str:
    names = [f.feature for f in ml.top_factors[:3]]
    return f"; top factors: {', '.join(names)}" if names else ""


def final_verdict(deterministic: Verdict, ml: Optional[MLAssessment], settings: Settings) -> Verdict:
    """Apply the ML assessment to a deterministic verdict and record how.
    `ml` is None exactly when the deterministic verdict is not ALLOW."""

    def trace(final: VerdictType, rule_id: str) -> DecisionTrace:
        return DecisionTrace(
            deterministic_verdict=deterministic.verdict.value,
            deterministic_rule_id=deterministic.rule_id,
            ml_mode=settings.ml_mode,
            ml_high_risk_threshold=settings.ml_high_risk_threshold,
            ml_critical_risk_threshold=settings.ml_critical_risk_threshold,
            final_verdict=final.value,
            final_rule_id=rule_id,
        )

    if deterministic.verdict != VerdictType.ALLOW or ml is None:
        # Hard veto: the ML layer never sees a deterministically blocked call.
        return deterministic.model_copy(
            update={"ml": MLAssessment(status="not_consulted", mode=settings.ml_mode), "decision": trace(deterministic.verdict, deterministic.rule_id)}
        )

    def outcome(verdict: VerdictType, rule_id: str, reason: str, severity: Severity) -> Verdict:
        return deterministic.model_copy(
            update={
                "verdict": verdict, "rule_id": rule_id, "reason": reason, "severity": severity,
                "stage": "ml", "ml": ml, "decision": trace(verdict, rule_id),
            }
        )

    if ml.status == "ok" and ml.risk_score is not None:
        if ml.risk_score >= settings.ml_critical_risk_threshold:
            return outcome(
                VerdictType.BLOCK, "ML-002",
                f"ML risk {ml.risk_score:.3f} >= critical threshold {settings.ml_critical_risk_threshold}{_describe_factors(ml)}",
                Severity.HIGH,
            )
        if ml.risk_score >= settings.ml_high_risk_threshold:
            return outcome(
                VerdictType.ESCALATE, "ML-001",
                f"ML risk {ml.risk_score:.3f} >= high threshold {settings.ml_high_risk_threshold}; held for review{_describe_factors(ml)}",
                Severity.MEDIUM,
            )
    elif ml.status in ("unavailable", "error") and settings.ml_mode == "required":
        return outcome(VerdictType.BLOCK, "ML-003", f"ML risk assessment required but {ml.status}; blocked (fail closed)", Severity.HIGH)

    return deterministic.model_copy(update={"ml": ml, "decision": trace(VerdictType.ALLOW, deterministic.rule_id)})
