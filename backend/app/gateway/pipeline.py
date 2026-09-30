from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from app.gateway.canonicalizer import CanonicalizationError, canonicalize
from app.gateway.destination_validator import validate_destination
from app.gateway.parameter_validator import validate_parameters
from app.gateway.policy_engine import CheckOutcome, DecisionContext, decide
from app.gateway.registry import get_tool, is_agent_authorized, is_manifest_intact
from app.gateway.request_integrity import sign_request
from app.models.envelope import Principal, ToolCallEnvelope
from app.models.tool_call import ToolCall
from app.models.verdict import RequestIntegrity, Severity, Verdict, VerdictType

CHECK_REQUEST_STRUCTURE = "REQUEST_STRUCTURE"
CHECK_TOOL_REGISTRY = "TOOL_REGISTRY"
CHECK_TOOL_ENABLED = "TOOL_ENABLED"
CHECK_AGENT_PERMISSION = "AGENT_PERMISSION"
CHECK_PARAMETER_VALIDATION = "PARAMETER_VALIDATION"
CHECK_DESTINATION_VALIDATION = "DESTINATION_VALIDATION"

PLANNED_CHECKS = (
    CHECK_REQUEST_STRUCTURE,
    CHECK_TOOL_REGISTRY,
    CHECK_TOOL_ENABLED,
    CHECK_AGENT_PERMISSION,
    CHECK_PARAMETER_VALIDATION,
    CHECK_DESTINATION_VALIDATION,
)


def integrity_fields(verdict: Verdict) -> Dict[str, Any]:
    """The verdict fields the request-integrity tag covers."""
    fields: Dict[str, Any] = verdict.model_dump(mode="json")
    fields["pinned_ips"] = [n.pinned_ip for n in verdict.network]
    return fields


@dataclass(frozen=True)
class GatewayResult:
    verdict: Verdict
    # The canonical request the checks ran against; None only when the
    # request could not be canonicalized. Only an ALLOW verdict authorizes
    # acting on it.
    envelope: Optional[ToolCallEnvelope]


def process_tool_call(tool_call: ToolCall, principal: Principal, request_id: str) -> GatewayResult:
    """Run a ToolCall through the gateway's security checks, then hand the
    accumulated results to the policy engine for the final decision.

    The request is first canonicalized (REQUEST_STRUCTURE); every later
    check reads the canonical envelope, never the raw ToolCall. Then:
    registry and manifest integrity, enabled state, agent permission,
    parameter schema, and destination (egress) validation. Each validator
    remains the sole owner of its own check; this function only runs them
    in order and collects their outcomes.

    Checks stop at the first failure, deliberately:
      * a tool that isn't registered has no parameters worth validating;
      * an agent that isn't authorized for a tool must not learn anything
        about that tool's schema or destinations from later checks;
      * later checks (e.g. budgets) may have side effects that must not
        happen for an already-vetoed request.
    Checks that did not run are reported in `checks_not_evaluated`.
    """
    outcomes: List[CheckOutcome] = []
    facts: Dict[str, Any] = {"request_id": request_id, "planned_checks": PLANNED_CHECKS}

    def finish(envelope: Optional[ToolCallEnvelope]) -> GatewayResult:
        verdict = decide(principal.agent_id, tool_call.tool, outcomes, DecisionContext(**facts))
        if verdict.verdict == VerdictType.ALLOW:
            # Bind the approval to this exact request (and its DNS pins) so the
            # execution layer can refuse anything the gateway did not allow.
            integrity = RequestIntegrity(**sign_request(integrity_fields(verdict)))
            verdict = verdict.model_copy(update={"request_integrity": integrity})
        return GatewayResult(verdict=verdict, envelope=envelope)

    def fail(check: str, rule_id: str, reason: str, severity: Severity, stage: str = "gateway") -> None:
        outcomes.append(CheckOutcome(check, False, rule_id, reason, severity, stage))

    try:
        envelope = canonicalize(tool_call, principal, request_id)
    except CanonicalizationError as error:
        fail(CHECK_REQUEST_STRUCTURE, error.rule_id, error.reason, Severity.MEDIUM, stage="canonicalize")
        return finish(None)
    facts["request_hash"] = envelope.request_hash
    outcomes.append(CheckOutcome(CHECK_REQUEST_STRUCTURE, passed=True))

    tool = get_tool(envelope.tool)
    if tool is None:
        fail(CHECK_TOOL_REGISTRY, "TOOL-001", "Tool is not registered", Severity.MEDIUM)
        return finish(envelope)
    facts["tool_version"] = tool.version
    facts["tool_manifest_hash"] = tool.manifest_hash()
    if not is_manifest_intact(envelope.tool, tool):
        fail(CHECK_TOOL_REGISTRY, "TOOL-004", "Tool manifest does not match its registered hash", Severity.HIGH)
        return finish(envelope)
    outcomes.append(CheckOutcome(CHECK_TOOL_REGISTRY, passed=True))

    if not tool.enabled:
        fail(CHECK_TOOL_ENABLED, "TOOL-002", "Tool is disabled", Severity.MEDIUM)
        return finish(envelope)
    outcomes.append(CheckOutcome(CHECK_TOOL_ENABLED, passed=True))

    if not is_agent_authorized(tool, envelope.principal.agent_id):
        fail(CHECK_AGENT_PERMISSION, "TOOL-003", "Agent is not authorized to use this tool", Severity.HIGH)
        return finish(envelope)
    outcomes.append(CheckOutcome(CHECK_AGENT_PERMISSION, passed=True))

    param_error = validate_parameters(tool, envelope.parameters)
    if param_error is not None:
        fail(CHECK_PARAMETER_VALIDATION, *param_error, Severity.MEDIUM)
        return finish(envelope)
    outcomes.append(CheckOutcome(CHECK_PARAMETER_VALIDATION, passed=True))

    destination = validate_destination(tool, envelope.parameters)
    facts["network"] = tuple(n.as_dict() for n in destination.network)
    if destination.error is not None:
        fail(CHECK_DESTINATION_VALIDATION, *destination.error, Severity.HIGH)
        return finish(envelope)
    outcomes.append(CheckOutcome(CHECK_DESTINATION_VALIDATION, passed=True))

    return finish(envelope)
