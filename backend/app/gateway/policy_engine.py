from dataclasses import dataclass
from typing import List, Optional

from app.models.verdict import CheckResult, Severity, Verdict, VerdictType


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


def decide(agent_id: str, tool: str, outcomes: List[CheckOutcome]) -> Verdict:
    """Turn accumulated check outcomes into the final gateway Verdict.

    This is the single place that maps check results to ALLOW/BLOCK.
    The first failed outcome (in the order the checks ran) determines the
    rule_id, reason, and severity of a BLOCK -- this keeps the decision
    deterministic even if more than one check would have failed.
    """
    checks = [
        CheckResult(check=o.check, status="PASSED" if o.passed else "FAILED")
        for o in outcomes
    ]

    failed = next((o for o in outcomes if not o.passed), None)
    if failed is not None:
        return Verdict(
            verdict=VerdictType.BLOCK,
            severity=failed.severity or Severity.MEDIUM,
            agent_id=agent_id,
            tool=tool,
            rule_id=failed.rule_id or "POLICY-001",
            reason=failed.reason or "Tool call blocked by policy engine",
            stage="gateway",
            checks=checks,
        )

    return Verdict(
        verdict=VerdictType.ALLOW,
        severity=Severity.LOW,
        agent_id=agent_id,
        tool=tool,
        rule_id="BASE-001",
        reason="Tool call passed basic gateway validation",
        stage="gateway",
        checks=checks,
    )
