from typing import Dict, List

from app.gateway.parameter_validator import validate_parameters
from app.gateway.registry import get_tool, is_agent_authorized
from app.models.tool_call import ToolCall
from app.models.verdict import Severity, Verdict, VerdictType

CHECK_REQUEST_STRUCTURE = "REQUEST_STRUCTURE"
CHECK_TOOL_REGISTRY = "TOOL_REGISTRY"
CHECK_TOOL_ENABLED = "TOOL_ENABLED"
CHECK_AGENT_PERMISSION = "AGENT_PERMISSION"
CHECK_PARAMETER_VALIDATION = "PARAMETER_VALIDATION"


def process_tool_call(tool_call: ToolCall) -> Verdict:
    """Run a ToolCall through the gateway pipeline and produce a Verdict.

    Phase 1 checked structural validity (enforced by Pydantic before this
    runs). Phase 2 added the tool registry and agent permission checks.
    Phase 3 adds parameter/schema validation for the tool that was
    authorized. Later phases will insert destination validation and
    deeper policy evaluation here.

    Each stage is recorded in `checks` so a future UI can show a
    pass/fail breakdown per stage, not just the final verdict.
    """
    checks: List[Dict[str, str]] = [_passed(CHECK_REQUEST_STRUCTURE)]

    tool = get_tool(tool_call.tool)
    if tool is None:
        checks.append(_failed(CHECK_TOOL_REGISTRY))
        return _block(tool_call, "TOOL-001", "Tool is not registered", Severity.MEDIUM, checks)
    checks.append(_passed(CHECK_TOOL_REGISTRY))

    if not tool.enabled:
        checks.append(_failed(CHECK_TOOL_ENABLED))
        return _block(tool_call, "TOOL-002", "Tool is disabled", Severity.MEDIUM, checks)
    checks.append(_passed(CHECK_TOOL_ENABLED))

    if not is_agent_authorized(tool, tool_call.agent_id):
        checks.append(_failed(CHECK_AGENT_PERMISSION))
        return _block(
            tool_call,
            "TOOL-003",
            "Agent is not authorized to use this tool",
            Severity.HIGH,
            checks,
        )
    checks.append(_passed(CHECK_AGENT_PERMISSION))

    param_error = validate_parameters(tool_call.tool, tool_call.parameters)
    if param_error is not None:
        rule_id, reason = param_error
        checks.append(_failed(CHECK_PARAMETER_VALIDATION))
        return _block(tool_call, rule_id, reason, Severity.MEDIUM, checks)
    checks.append(_passed(CHECK_PARAMETER_VALIDATION))

    return Verdict(
        verdict=VerdictType.ALLOW,
        severity=Severity.LOW,
        agent_id=tool_call.agent_id,
        tool=tool_call.tool,
        rule_id="BASE-001",
        reason="Tool call passed basic gateway validation",
        stage="gateway",
        checks=checks,
    )


def _passed(check: str) -> Dict[str, str]:
    return {"check": check, "status": "PASSED"}


def _failed(check: str) -> Dict[str, str]:
    return {"check": check, "status": "FAILED"}


def _block(
    tool_call: ToolCall,
    rule_id: str,
    reason: str,
    severity: Severity,
    checks: List[Dict[str, str]],
) -> Verdict:
    return Verdict(
        verdict=VerdictType.BLOCK,
        severity=severity,
        agent_id=tool_call.agent_id,
        tool=tool_call.tool,
        rule_id=rule_id,
        reason=reason,
        stage="gateway",
        checks=checks,
    )
