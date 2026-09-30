from datetime import datetime, timezone
from typing import Any, Dict, List

from app.models.verdict import Verdict

_audit_log: List[Dict[str, Any]] = []


def record_audit_event(verdict: Verdict) -> Dict[str, Any]:
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "agent_id": verdict.agent_id,
        "tool": verdict.tool,
        "verdict": verdict.verdict.value,
        "reason": verdict.reason,
    }
    _audit_log.append(event)
    print(f"[AUDIT] {event}")
    return event


def get_audit_log() -> List[Dict[str, Any]]:
    return _audit_log
