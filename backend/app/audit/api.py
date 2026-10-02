"""Read-only audit API: GET /v1/audit/events.

Serves the in-memory audit history of this backend process (app/audit/logger.py):
every decision since the process started, up to the log's capacity. It is not
persistent, signed, hash-chained or shared between workers, and the response
says so.

The endpoint only reads. It never runs a check, the ML model or the sandbox,
and nothing it does can influence a tool-call decision.

Access needs the operator token SATG_AUDIT_API_TOKEN (Authorization: Bearer).
Without a configured token the API is disabled.

Events are projected onto explicit response models instead of being returned
as stored. Withheld: HMAC signatures, ML features / signals / top factors and
internal ML detail, the anomaly hex snippet, raw sandbox error text, and URL
query strings, fragments and userinfo. Request parameters, context text and
tool output are never stored in the first place.
"""

import hmac
import re
from typing import Any, Dict, List, Literal, Optional
from urllib.parse import urlsplit, urlunsplit

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from pydantic import BaseModel

from app.audit.logger import audit_snapshot
from app.config import get_settings

DEFAULT_LIMIT = 50
MAX_LIMIT = 200
# Filter values have the shape of identifiers (agent_id, tool, rule_id, request_id).
_FILTER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
# ML-001/ML-002 reasons end with the model's top factors; those are model internals.
_ML_FACTORS = re.compile(r"; top factors: .*$")
# The runner reports "<code>: <detail>"; only a short code is returned.
_ERROR_CODE = re.compile(r"^([a-z][a-z0-9_]{0,40}): ")
_MAX_URL_PATH = 200

# Fixed wording per sandbox status, returned instead of the raw error text.
_EXECUTION_SUMMARY = {
    "success": None,
    "tool_error": "The tool reported an error.",
    "rejected": "The sandbox runner rejected the request.",
    "timeout": "Exceeded the sandbox timeout; the container was killed.",
    "killed": "The container was killed (memory limit or signal).",
    "sandbox_unavailable": "Docker was unavailable; the tool was not run.",
    "integrity_failed": "The request-integrity check failed; nothing was started.",
    "error": "Sandbox error; the tool may not have run.",
    "not_executed": "Not executed.",
}

router = APIRouter(prefix="/v1/audit", tags=["audit"])


def require_operator(authorization: Optional[str] = Header(default=None)) -> None:
    """401 for a missing or wrong token; 503 when no token is configured."""
    token = get_settings().audit_api_token
    if token is None:
        raise HTTPException(status_code=503, detail="Audit API is disabled: SATG_AUDIT_API_TOKEN is not configured")
    scheme, _, presented = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(presented.strip().encode("utf-8"), token.encode("utf-8")):
        raise HTTPException(status_code=401, detail="Missing or invalid audit API token", headers={"WWW-Authenticate": "Bearer"})


# ----------------------------------------------------------------- response models


class AuditCheck(BaseModel):
    check: str
    status: Literal["PASSED", "FAILED"]


class AuditDecision(BaseModel):
    deterministic_verdict: Literal["ALLOW", "BLOCK"]
    deterministic_rule_id: str
    final_verdict: Literal["ALLOW", "BLOCK", "ESCALATE"]
    final_rule_id: str
    ml_mode: str
    ml_high_risk_threshold: float
    ml_critical_risk_threshold: float


class AuditMl(BaseModel):
    """Operator summary of the ML assessment; model internals are withheld."""

    status: Literal["ok", "unavailable", "error", "not_consulted", "disabled"]
    mode: str
    model_version: Optional[str] = None
    risk_score: Optional[float] = None
    risk_level: Optional[str] = None
    prediction: Optional[Literal["risky", "benign"]] = None
    latency_ms: Optional[float] = None
    # Names of the caller-supplied context fields the model saw; never their text.
    context_used: List[str] = []


class AuditExecution(BaseModel):
    status: str
    sandbox_id: Optional[str] = None
    exit_code: Optional[int] = None
    duration_ms: Optional[float] = None
    container_removed: Optional[bool] = None
    stdout_sha256: Optional[str] = None
    stdout_bytes: Optional[int] = None
    stderr_sha256: Optional[str] = None
    stderr_bytes: Optional[int] = None
    # A short machine code from the runner (e.g. "not_found"), when it reported one.
    error_code: Optional[str] = None
    # Fixed text for the status; the raw error is never returned.
    error_summary: Optional[str] = None


class AuditNetworkCheck(BaseModel):
    check: str
    status: Literal["PASSED", "BLOCKED", "NOT_EVALUATED"]
    detail: Optional[str] = None


class AuditNetwork(BaseModel):
    parameter: str
    # scheme://host[:port]/path; query, fragment and userinfo removed.
    url: str
    url_query_removed: bool
    requested_host: Optional[str] = None
    registrable_domain: Optional[str] = None
    resolved_ips: List[str] = []
    pinned_ip: Optional[str] = None
    checks: List[AuditNetworkCheck] = []


class AuditAnomaly(BaseModel):
    """A quarantined anomaly without its hex snippet (reversible to the raw bytes)."""

    anomaly_id: str
    anomaly_type: str
    risk_severity: str
    rule_id: str
    location: str
    raw_payload_sha256: str
    raw_payload_bytes: int
    mitigation_action: str


class AuditIntegrity(BaseModel):
    """The HMAC tag's metadata; the signature itself is withheld."""

    algorithm: str
    key_id: str
    signed_fields: List[str]


class AuditEvent(BaseModel):
    seq: int
    # When the backend wrote the audit record (after the decision and any sandbox run), UTC.
    timestamp: str
    request_id: str
    verdict: Literal["ALLOW", "BLOCK", "ESCALATE"]
    severity: str
    rule_id: str
    reason: str
    stage: str
    # Self-asserted by the caller (authenticated is always false today).
    agent_id: Optional[str] = None
    tool: Optional[str] = None
    authenticated: bool
    auth_method: Optional[str] = None
    checks: List[AuditCheck]
    checks_not_evaluated: List[str]
    policy_version: str
    tool_version: Optional[str] = None
    tool_manifest_hash: Optional[str] = None
    request_hash: Optional[str] = None
    decision: Optional[AuditDecision] = None
    ml: Optional[AuditMl] = None
    execution: Optional[AuditExecution] = None
    network: List[AuditNetwork] = []
    request_integrity: Optional[AuditIntegrity] = None
    anomalies: List[AuditAnomaly] = []


class AuditPage(BaseModel):
    events: List[AuditEvent]
    # Pass as before_seq for the next (older) page; None when there is none.
    next_before_seq: Optional[int] = None
    storage: Literal["in_memory"] = "in_memory"
    scope: Literal["this_backend_process"] = "this_backend_process"
    process_started_at: str
    capacity: int
    retained: int
    total_recorded: int
    evicted: int
    oldest_seq: Optional[int] = None
    newest_seq: Optional[int] = None
    note: str


# ----------------------------------------------------------------- projection


def sanitize_url(raw: Any) -> tuple[str, bool]:
    """Return (scheme://host[:port]/path, whether anything after the path was removed)."""
    if not isinstance(raw, str):
        return "<not a URL>", False
    try:
        parts = urlsplit(raw.strip())
        host = parts.hostname or ""
        port = parts.port
    except ValueError:
        return "<unparseable URL>", False
    if not parts.scheme or not host:
        return "<unparseable URL>", False
    netloc = f"[{host}]" if ":" in host else host
    if port is not None:
        netloc += f":{port}"
    path = parts.path[:_MAX_URL_PATH]
    removed = bool(parts.query or parts.fragment or parts.username or parts.password or len(parts.path) > _MAX_URL_PATH)
    return urlunsplit((parts.scheme.lower(), netloc, path, "", "")), removed


def _reason(event: Dict[str, Any]) -> str:
    reason = str(event.get("reason", ""))
    return _ML_FACTORS.sub("", reason) if str(event.get("rule_id", "")).startswith("ML-") else reason


def _ml(ml: Optional[Dict[str, Any]]) -> Optional[AuditMl]:
    if not isinstance(ml, dict):
        return None
    return AuditMl(
        status=ml["status"], mode=ml.get("mode", ""), model_version=ml.get("model_version"), risk_score=ml.get("risk_score"),
        risk_level=ml.get("risk_level"), prediction=ml.get("prediction"), latency_ms=ml.get("latency_ms"),
        context_used=[c for c in ml.get("context_used") or [] if isinstance(c, str)],
    )


def _execution(e: Optional[Dict[str, Any]]) -> Optional[AuditExecution]:
    if not isinstance(e, dict):
        return None
    status = str(e.get("status", "error"))
    code = _ERROR_CODE.match(e.get("error") or "") if status in ("tool_error", "rejected", "error") else None
    return AuditExecution(
        status=status, sandbox_id=e.get("sandbox_id"), exit_code=e.get("exit_code"), duration_ms=e.get("duration_ms"),
        container_removed=e.get("container_removed"), stdout_sha256=e.get("stdout_sha256"), stdout_bytes=e.get("stdout_bytes"),
        stderr_sha256=e.get("stderr_sha256"), stderr_bytes=e.get("stderr_bytes"),
        error_code=code.group(1) if code else None,
        error_summary=_EXECUTION_SUMMARY.get(status, "Sandbox error.") if e.get("error") or status != "success" else None,
    )


def _network(n: Dict[str, Any]) -> AuditNetwork:
    url, removed = sanitize_url(n.get("requested_url"))
    return AuditNetwork(
        parameter=str(n.get("parameter", "")), url=url, url_query_removed=removed, requested_host=n.get("requested_host"),
        registrable_domain=n.get("registrable_domain"), resolved_ips=list(n.get("resolved_ips") or []), pinned_ip=n.get("pinned_ip"),
        checks=[AuditNetworkCheck(check=c["check"], status=c["status"], detail=c.get("detail")) for c in n.get("checks") or []],
    )


def project(event: Dict[str, Any]) -> AuditEvent:
    """Build the operator view of one stored audit event, field by field."""
    decision = event.get("decision")
    integrity = event.get("request_integrity")
    return AuditEvent(
        seq=event["seq"], timestamp=event["timestamp"], request_id=event["request_id"], verdict=event["verdict"],
        severity=event["severity"], rule_id=event["rule_id"], reason=_reason(event), stage=event["stage"],
        agent_id=event.get("agent_id"), tool=event.get("tool"), authenticated=bool(event.get("authenticated")),
        auth_method=event.get("auth_method"),
        checks=[AuditCheck(check=c["check"], status=c["status"]) for c in event.get("checks") or []],
        checks_not_evaluated=list(event.get("checks_not_evaluated") or []),
        policy_version=event["policy_version"], tool_version=event.get("tool_version"),
        tool_manifest_hash=event.get("tool_manifest_hash"), request_hash=event.get("request_hash"),
        decision=AuditDecision(**{k: decision[k] for k in AuditDecision.model_fields}) if isinstance(decision, dict) else None,
        ml=_ml(event.get("ml")),
        execution=_execution(event.get("execution")),
        network=[_network(n) for n in event.get("network") or []],
        request_integrity=AuditIntegrity(algorithm=integrity["algorithm"], key_id=integrity["key_id"], signed_fields=list(integrity["signed_fields"]))
        if isinstance(integrity, dict) else None,
        anomalies=[AuditAnomaly(**{k: a[k] for k in AuditAnomaly.model_fields}) for a in event.get("anomalies") or []],
    )


# ----------------------------------------------------------------- endpoint


@router.get("/events", response_model=AuditPage, dependencies=[Depends(require_operator)])
def list_events(
    limit: int = Query(DEFAULT_LIMIT, ge=1, le=MAX_LIMIT),
    before_seq: Optional[int] = Query(None, ge=1),
    verdict: Optional[Literal["ALLOW", "BLOCK", "ESCALATE"]] = None,
    rule_id: Optional[str] = Query(None, pattern=_FILTER_PATTERN),
    tool: Optional[str] = Query(None, pattern=_FILTER_PATTERN),
    agent_id: Optional[str] = Query(None, pattern=_FILTER_PATTERN),
    request_id: Optional[str] = Query(None, pattern=_FILTER_PATTERN),
) -> AuditPage:
    """Newest first. Filters are exact matches and combine with AND."""
    snapshot = audit_snapshot()
    wanted = {"verdict": verdict, "rule_id": rule_id, "tool": tool, "agent_id": agent_id, "request_id": request_id}
    filters = {k: v for k, v in wanted.items() if v is not None}
    matches = [
        e for e in reversed(snapshot.events)
        if (before_seq is None or e["seq"] < before_seq) and all(e.get(k) == v for k, v in filters.items())
    ]
    page = matches[:limit]
    retained = len(snapshot.events)
    return AuditPage(
        events=[project(e) for e in page],
        next_before_seq=page[-1]["seq"] if len(matches) > limit else None,
        process_started_at=snapshot.process_started_at,
        capacity=snapshot.capacity,
        retained=retained,
        total_recorded=snapshot.total_recorded,
        evicted=snapshot.total_recorded - retained,
        oldest_seq=snapshot.events[0]["seq"] if retained else None,
        newest_seq=snapshot.events[-1]["seq"] if retained else None,
        note="In-memory audit history of this backend process since it started, up to its capacity. "
        "Not persistent, signed or shared between workers; a restart starts empty.",
    )
