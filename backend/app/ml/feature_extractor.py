"""Build the ML package's MLRequest from a canonical gateway envelope.

Every field has one deterministic source (ml/integration_contract.md §3):

  request_id          envelope.request_id
  tool_name           canonical tool name
  tool_description    registry manifest description (trusted)
  arguments           canonical, validated parameters
  known_entities      the gateway's egress allowlists (trusted)
  task_text           context["task"]            (caller-supplied, optional)
  current_observation context["observation"]     (caller-supplied, optional)
  previous_steps      context["previous_steps"]  (caller-supplied, optional)

The context fields are unauthenticated claims from the agent framework. The
ML result can only make a decision *more* restrictive, never less than the
deterministic policy, so a caller who lies in them can at most evade an ML
escalation; it cannot unlock anything the deterministic policy blocks.
"""

from typing import Any, Dict, List, Optional, Tuple

from app.gateway.destination_validator import EGRESS_ALLOWLISTS
from app.gateway.registry import RegisteredTool
from app.models.envelope import ToolCallEnvelope

MAX_TEXT_CHARS = 8000
MAX_PREVIOUS_STEPS = 16
_STEP_TEXT_CHARS = 4000


def _text(value: Any, limit: int = MAX_TEXT_CHARS) -> str:
    return value[:limit] if isinstance(value, str) else ""


def _steps(value: Any) -> List[Dict[str, Any]]:
    if not isinstance(value, list):
        return []
    steps = []
    for item in value[-MAX_PREVIOUS_STEPS:]:
        if not isinstance(item, dict):
            continue
        tool = item.get("tool_name", item.get("tool"))
        if not isinstance(tool, str) or not tool:
            continue
        arguments = item.get("arguments", item.get("args"))
        steps.append({
            "tool_name": tool[:128],
            "arguments": arguments if isinstance(arguments, dict) else {},
            "observation": _text(item.get("observation", item.get("obs")), _STEP_TEXT_CHARS),
        })
    return steps


def known_entities() -> Dict[str, Any]:
    domains = sorted({d for allowlist in EGRESS_ALLOWLISTS.values() for d in allowlist})
    return {"company": "Company", "known_domains": domains}


def build_ml_request(envelope: ToolCallEnvelope, tool: RegisteredTool) -> Tuple[Dict[str, Any], List[str]]:
    """Return (MLRequest as a dict, names of the context fields that were used)."""
    context: Optional[Dict[str, Any]] = envelope.untrusted_context if isinstance(envelope.untrusted_context, dict) else {}
    request = {
        "request_id": envelope.request_id,
        "tool_name": envelope.tool,
        "tool_description": tool.description,
        "arguments": dict(envelope.parameters),
        "task_text": _text(context.get("task")),
        "current_observation": _text(context.get("observation")),
        "previous_steps": _steps(context.get("previous_steps")),
        "session_features": {"known_entities": known_entities()},
    }
    used = [
        name
        for name, present in (
            ("task", bool(request["task_text"])),
            ("observation", bool(request["current_observation"])),
            ("previous_steps", bool(request["previous_steps"])),
        )
        if present
    ]
    return request, used
