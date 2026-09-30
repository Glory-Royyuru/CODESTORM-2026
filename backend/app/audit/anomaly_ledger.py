import hashlib
import threading
import uuid
from collections import deque
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List, Optional

from app.gateway.crypto_guard import Anomaly

# In-memory only (no persistence yet); bounded like the audit log.
MAX_ANOMALY_RECORDS = 10_000
# The ledger keeps a fingerprint of the refused value and at most this many
# of its bytes, hex-encoded -- never the raw value itself.
MAX_SNIPPET_BYTES = 64

_records: Deque[Dict[str, Any]] = deque(maxlen=MAX_ANOMALY_RECORDS)
_lock = threading.Lock()


def quarantine_record(
    anomaly: Anomaly, request_id: str, agent_id: Optional[str], tool: Optional[str]
) -> Dict[str, Any]:
    """Build the quarantine envelope for one anomaly. The raw value is
    reduced to a SHA-256 fingerprint and a bounded hex snippet, so nothing
    stored or logged can be re-parsed as the original payload."""
    return {
        "anomaly_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "request_id": request_id,
        # Claimed identifiers from the rejected body; unauthenticated.
        "agent_id": agent_id,
        "tool": tool,
        "anomaly_type": anomaly.anomaly_type.value,
        "risk_severity": anomaly.severity.value,
        "rule_id": anomaly.rule_id,
        "location": anomaly.location,
        "raw_payload_sha256": "sha256:" + hashlib.sha256(anomaly.raw).hexdigest(),
        "raw_payload_bytes": len(anomaly.raw),
        "quarantined_hex_snippet": anomaly.raw[:MAX_SNIPPET_BYTES].hex(),
        "parser_error_detail": anomaly.detail,
        "mitigation_action": anomaly.mitigation.value,
    }


def append_anomaly(record: Dict[str, Any]) -> None:
    """Append-only: records are never edited or removed individually."""
    with _lock:
        _records.append(dict(record))


def get_anomalies() -> List[Dict[str, Any]]:
    with _lock:
        return [dict(r) for r in _records]
