from typing import List

from app.gateway.destination_validator import validate_destination
from app.gateway.parameter_validator import validate_parameters
from app.gateway.policy_engine import CheckOutcome, decide
from app.gateway.registry import get_tool, is_agent_authorized
from app.models.tool_call import ToolCall
from app.models.verdict import Severity, Verdict

CHECK_REQUEST_STRUCTURE = "REQUEST_STRUCTURE"
CHECK_TOOL_REGISTRY = "TOOL_REGISTRY"
CHECK_TOOL_ENABLED = "TOOL_ENABLED"
CHECK_AGENT_PERMISSION = "AGENT_PERMISSION"
CHECK_PARAMETER_VALIDATION = "PARAMETER_VALIDATION"
CHECK_DESTINATION_VALIDATION = "DESTINATION_VALIDATION"


def process_tool_call(tool_call: ToolCall) -> Verdict:
    """Run a ToolCall through the gateway's security checks, then hand the
    accumulated results to the policy engine for the final decision.

    Phase 1 checked structural validity (enforced by Pydantic before this
    runs). Phase 2 added the tool registry and agent permission checks.
    Phase 3 added parameter/schema validation. Phase 4 added destination
    (egress) validation. Phase 5 pulls the final ALLOW/BLOCK decision out
    of this function and into the policy engine -- this function's only
    job is to run each check in order and collect its outcome.

    Checks stop at the first failure: a tool that isn't even registered
    has no parameters worth validating. Each validator (registry,
    parameter, destination) remains the sole owner of its own check; this
    function does not re-implement or duplicate their logic.
    """
    outcomes: List[CheckOutcome] = [CheckOutcome(CHECK_REQUEST_STRUCTURE, passed=True)]

    tool = get_tool(tool_call.tool)
    if tool is None:
        outcomes.append(
            CheckOutcome(CHECK_TOOL_REGISTRY, False, "TOOL-001", "Tool is not registered", Severity.MEDIUM)
        )
        return decide(tool_call.agent_id, tool_call.tool, outcomes)
    outcomes.append(CheckOutcome(CHECK_TOOL_REGISTRY, passed=True))

    if not tool.enabled:
        outcomes.append(CheckOutcome(CHECK_TOOL_ENABLED, False, "TOOL-002", "Tool is disabled", Severity.MEDIUM))
        return decide(tool_call.agent_id, tool_call.tool, outcomes)
    outcomes.append(CheckOutcome(CHECK_TOOL_ENABLED, passed=True))

    if not is_agent_authorized(tool, tool_call.agent_id):
        outcomes.append(
            CheckOutcome(
                CHECK_AGENT_PERMISSION,
                False,
                "TOOL-003",
                "Agent is not authorized to use this tool",
                Severity.HIGH,
            )
        )
        return decide(tool_call.agent_id, tool_call.tool, outcomes)
    outcomes.append(CheckOutcome(CHECK_AGENT_PERMISSION, passed=True))

    param_error = validate_parameters(tool_call.tool, tool_call.parameters)
    if param_error is not None:
        rule_id, reason = param_error
        outcomes.append(CheckOutcome(CHECK_PARAMETER_VALIDATION, False, rule_id, reason, Severity.MEDIUM))
        return decide(tool_call.agent_id, tool_call.tool, outcomes)
    outcomes.append(CheckOutcome(CHECK_PARAMETER_VALIDATION, passed=True))

    destination_error = validate_destination(tool_call.tool, tool_call.parameters)
    if destination_error is not None:
        rule_id, reason = destination_error
        outcomes.append(CheckOutcome(CHECK_DESTINATION_VALIDATION, False, rule_id, reason, Severity.HIGH))
        return decide(tool_call.agent_id, tool_call.tool, outcomes)
    outcomes.append(CheckOutcome(CHECK_DESTINATION_VALIDATION, passed=True))

    return decide(tool_call.agent_id, tool_call.tool, outcomes)
