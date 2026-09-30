from app.gateway.registry import get_tool, is_agent_authorized
from app.models.tool_call import ToolCall
from app.models.verdict import Severity, Verdict, VerdictType


def process_tool_call(tool_call: ToolCall) -> Verdict:
    """Run a ToolCall through the gateway pipeline and produce a Verdict.

    Phase 1 only checked structural validity (enforced by Pydantic before
    this runs). Phase 2 adds the first real policy check: is the tool
    registered, enabled, and is this agent allowed to use it. Later phases
    will insert parameter validation, destination validation, and deeper
    policy evaluation here.
    """
    tool = get_tool(tool_call.tool)

    if tool is None:
        return _block(tool_call, "TOOL-001", "Tool is not registered", Severity.MEDIUM)

    if not tool.enabled:
        return _block(tool_call, "TOOL-002", "Tool is disabled", Severity.MEDIUM)

    if not is_agent_authorized(tool, tool_call.agent_id):
        return _block(
            tool_call,
            "TOOL-003",
            "Agent is not authorized to use this tool",
            Severity.HIGH,
        )

    return Verdict(
        verdict=VerdictType.ALLOW,
        severity=Severity.LOW,
        agent_id=tool_call.agent_id,
        tool=tool_call.tool,
        rule_id="BASE-001",
        reason="Tool call passed basic gateway validation",
        stage="gateway",
    )


def _block(tool_call: ToolCall, rule_id: str, reason: str, severity: Severity) -> Verdict:
    return Verdict(
        verdict=VerdictType.BLOCK,
        severity=severity,
        agent_id=tool_call.agent_id,
        tool=tool_call.tool,
        rule_id=rule_id,
        reason=reason,
        stage="gateway",
    )
