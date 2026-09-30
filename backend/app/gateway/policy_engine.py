from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from app.models.envelope import new_request_id
from app.models.verdict import CheckResult, CheckStatus, Severity, Verdict, VerdictType

# Bumped whenever a rule's meaning, a rule ID, or the check order changes, so
# every recorded verdict can be tied to the policy that produced it.
POLICY_VERSION = "deterministic-core-1.2.0"


@dataclass
class CheckOutcome:
    """The result of one security check, as reported by its own validator.

    The policy engine does not decide *whether* a check passes -- the
    registry, parameter validator, destination validator, etc. already did
    that. This just carries their result so the engine can combine them
    into a final Verdict.
    """

    check: str
    passed: bool
    rule_id: Optional[str] = None
    reason: Optional[str] = None
    severity: Optional[Severity] = None
    stage: str = "gateway"


@dataclass(frozen=True)
class DecisionContext:
    """Request-level facts a decision is recorded against.

    Nothing here can turn a failed check into an ALLOW; only `outcomes`
    decide. The one exception is `planned_checks`, which can only make the
    decision stricter: an ALLOW requires every planned check to have run.
    """

    request_id: str = field(default_factory=new_request_id)
    tool_version: Optional[str] = None
    tool_manifest_hash: Optional[str] = None
    request_hash: Optional[str] = None
    planned_checks: Tuple[str, ...] = ()
    # Reported facts, recorded on the verdict; they never decide anything.
    network: Tuple[Dict[str, Any], ...] = ()
    anomalies: Tuple[Dict[str, Any], ...] = ()


def decide(
    agent_id: Optional[str],
    tool: Optional[str],
    outcomes: List[CheckOutcome],
    context: Optional[DecisionContext] = None,
) -> Verdict:
    """Turn accumulated check outcomes into the final gateway Verdict.

    This is the single place that maps check results to ALLOW/BLOCK.
    The first failed outcome (in the order the checks ran) determines the
    rule_id, reason, and severity of a BLOCK -- this keeps the decision
    deterministic even if more than one check would have failed.

    ALLOW is only returned when at least one check ran, none failed, and
    every planned check ran. Anything else fails closed.
    """
    context = context or DecisionContext()
    evaluated = {o.check for o in outcomes}
    common = dict(
        agent_id=agent_id,
        tool=tool,
        checks=[
            CheckResult(check=o.check, status=CheckStatus.PASSED if o.passed else CheckStatus.FAILED)
            for o in outcomes
        ],
        checks_not_evaluated=[c for c in context.planned_checks if c not in evaluated],
        request_id=context.request_id,
        policy_version=POLICY_VERSION,
        tool_version=context.tool_version,
        tool_manifest_hash=context.tool_manifest_hash,
        request_hash=context.request_hash,
        network=list(context.network),
        anomalies=list(context.anomalies),
    )

    failed = next((o for o in outcomes if not o.passed), None)
    if failed is not None:
        return Verdict(
            verdict=VerdictType.BLOCK,
            severity=failed.severity or Severity.MEDIUM,
            rule_id=failed.rule_id or "POLICY-001",
            reason=failed.reason or "Tool call blocked by policy engine",
            stage=failed.stage,
            **common,
        )

    if not outcomes:
        return Verdict(
            verdict=VerdictType.BLOCK,
            severity=Severity.HIGH,
            rule_id="POLICY-002",
            reason="No security checks were evaluated",
            stage="policy",
            **common,
        )

    if common["checks_not_evaluated"]:
        return Verdict(
            verdict=VerdictType.BLOCK,
            severity=Severity.HIGH,
            rule_id="POLICY-003",
            reason="Required security checks were not evaluated",
            stage="policy",
            **common,
        )

    return Verdict(
        verdict=VerdictType.ALLOW,
        severity=Severity.LOW,
        rule_id="BASE-001",
        reason="Tool call passed basic gateway validation",
        stage="gateway",
        **common,
    )
