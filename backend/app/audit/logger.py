import json
import logging
from collections import deque
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List, Optional

from app.models.envelope import Principal
from app.models.verdict import Verdict

# In-memory only (no persistence yet); bounded so it cannot grow forever.
MAX_IN_MEMORY_EVENTS = 10_000

_audit_log: Deque[Dict[str, Any]] = deque(maxlen=MAX_IN_MEMORY_EVENTS)

_logger = logging.getLogger("satg.audit")
if not _logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter("[AUDIT] %(message)s"))
    _logger.addHandler(_handler)
    _logger.setLevel(logging.INFO)
    _logger.propagate = False


def record_audit_event(verdict: Verdict, principal: Optional[Principal] = None) -> Dict[str, Any]:
    """Record one gateway decision -- ALLOW, BLOCK, or an ingress rejection.

    The event carries the full verdict (request_id, rule, reason, severity,
    checks, policy/manifest versions, request hash) plus how the caller's
    identity was established. `principal` is None when the request was
    rejected before an identity could be resolved.
    """
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **verdict.model_dump(mode="json"),
        "authenticated": principal.authenticated if principal else False,
        "auth_method": principal.auth_method if principal else None,
    }
    _audit_log.append(event)
    # One JSON object per line: values with newlines cannot forge log lines.
    _logger.info(json.dumps(event, sort_keys=True, ensure_ascii=True))
    return event


def get_audit_log() -> List[Dict[str, Any]]:
    return list(_audit_log)
