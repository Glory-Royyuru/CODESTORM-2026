from app.models.tool_call import ToolCall
from app.models.verdict import Severity, Verdict, VerdictType


def process_tool_call(tool_call: ToolCall) -> Verdict:
    """Run a ToolCall through the gateway pipeline and produce a Verdict.

    Phase 1 only checks that the request is structurally valid (already
    enforced by Pydantic before this runs), so every request that reaches
    here is ALLOWed. Later phases will insert permission checks, parameter
    validation, destination validation, and policy evaluation here.
    """
    return Verdict(
        verdict=VerdictType.ALLOW,
        severity=Severity.LOW,
        agent_id=tool_call.agent_id,
        tool=tool_call.tool,
        rule_id="BASE-001",
        reason="Tool call passed basic gateway validation",
        stage="gateway",
    )
