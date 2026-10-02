import hashlib
import json
import logging
import threading
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List, Optional

from app.models.envelope import Principal
from app.models.verdict import Verdict

# In-memory only (no persistence yet); bounded so it cannot grow forever.
MAX_IN_MEMORY_EVENTS = 10_000

_audit_log: Deque[Dict[str, Any]] = deque(maxlen=MAX_IN_MEMORY_EVENTS)
# Guards _audit_log and _seq: events are appended on the event loop and read
# from the audit API's worker threads.
_lock = threading.Lock()
# Server-side sequence number, 1 for the first event of this process. Like the
# log itself it lives only as long as the process: a restart starts again at 1.
_seq = 0
PROCESS_STARTED_AT = datetime.now(timezone.utc).isoformat()

_logger = logging.getLogger("satg.audit")
if not _logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter("[AUDIT] %(message)s"))
    _logger.addHandler(_handler)
    _logger.setLevel(logging.INFO)
    _logger.propagate = False


def _redacted(verdict: Dict[str, Any]) -> Dict[str, Any]:
    """Tool output can carry private data: the audit log keeps its SHA-256
    and size, never the output itself. ML context text is never in a verdict."""
    execution = verdict.get("execution")
    if isinstance(execution, dict):
        for stream in ("stdout", "stderr"):
            data = (execution.pop(stream, "") or "").encode("utf-8")
            execution[f"{stream}_sha256"] = hashlib.sha256(data).hexdigest()
            execution[f"{stream}_bytes"] = len(data)
        execution.pop("result", None)
    return verdict


def record_audit_event(verdict: Verdict, principal: Optional[Principal] = None) -> Dict[str, Any]:
    """Record one gateway decision -- ALLOW, BLOCK, or an ingress rejection.

    The event carries the full verdict (request_id, rule, reason, severity,
    checks, policy/manifest versions, request hash) plus how the caller's
    identity was established. `principal` is None when the request was
    rejected before an identity could be resolved.
    """
    global _seq
    body = {
        **_redacted(verdict.model_dump(mode="json")),
        "authenticated": principal.authenticated if principal else False,
        "auth_method": principal.auth_method if principal else None,
    }
    with _lock:
        # seq and timestamp are assigned together, so seq order is record order.
        _seq += 1
        event = {"seq": _seq, "timestamp": datetime.now(timezone.utc).isoformat(), **body}
        _audit_log.append(event)
    # One JSON object per line: values with newlines cannot forge log lines.
    _logger.info(json.dumps(event, sort_keys=True, ensure_ascii=True))
    return event


def get_audit_log() -> List[Dict[str, Any]]:
    with _lock:
        return list(_audit_log)


@dataclass(frozen=True)
class AuditSnapshot:
    """A consistent copy of the in-memory audit history of this process."""

    # Oldest first. Events are never modified after they are recorded.
    events: List[Dict[str, Any]]
    capacity: int
    # Events recorded since the process started, including evicted ones.
    total_recorded: int
    process_started_at: str


def audit_snapshot() -> AuditSnapshot:
    with _lock:
        return AuditSnapshot(
            events=list(_audit_log),
            capacity=MAX_IN_MEMORY_EVENTS,
            total_recorded=_seq,
            process_started_at=PROCESS_STARTED_AT,
        )
