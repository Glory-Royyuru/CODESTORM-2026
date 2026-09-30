from enum import Enum
from typing import List, Literal, Optional

from pydantic import BaseModel, Field


class VerdictType(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    # Reserved for later work (M7 decision fusion / WP10 approvals queue):
    # "hold for a human or a stronger check". The deterministic policy core
    # never emits it -- a deterministic check can only pass or veto -- so
    # nothing in the gateway produces this value yet. It exists now so that
    # clients handle a third value from the start instead of treating
    # "not ALLOW" as BLOCK (or the reverse).
    ESCALATE = "ESCALATE"


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    # Quarantined crypt-arithmetic tampering (CRYPTO-*).
    CRITICAL = "CRITICAL"


class CheckStatus(str, Enum):
    PASSED = "PASSED"
    FAILED = "FAILED"


class CheckResult(BaseModel):
    check: str
    status: CheckStatus


class NetworkCheck(BaseModel):
    check: str
    status: Literal["PASSED", "BLOCKED", "NOT_EVALUATED"]
    detail: Optional[str] = None


class NetworkInspection(BaseModel):
    """What the network boundary found for one URL destination."""

    parameter: str
    requested_url: str
    requested_host: Optional[str] = None
    registrable_domain: Optional[str] = None
    resolved_ips: List[str] = Field(default_factory=list)
    # The execution layer must connect to this IP and never re-resolve.
    pinned_ip: Optional[str] = None
    checks: List[NetworkCheck] = Field(default_factory=list)


class RequestIntegrity(BaseModel):
    """HMAC-SHA256 tag over the allowed request (ALLOW verdicts only)."""

    algorithm: Literal["HMAC-SHA256"]
    key_id: str
    signed_fields: List[str]
    signature: str


class QuarantinedAnomaly(BaseModel):
    """A crypt-arithmetic anomaly, reduced to a fingerprint and a bounded
    hex snippet; the raw value is never echoed."""

    anomaly_id: str
    anomaly_type: str
    risk_severity: Literal["CRITICAL", "HIGH", "ELEVATED"]
    rule_id: str
    location: str
    raw_payload_sha256: str
    raw_payload_bytes: int
    quarantined_hex_snippet: str
    parser_error_detail: str
    mitigation_action: Literal["QUARANTINE_AND_HARD_DENY", "STRIP_AND_RETRY_SANDBOX", "ISOLATE_SESSION"]


class Verdict(BaseModel):
    verdict: VerdictType
    severity: Severity
    # agent_id / tool are None only for ingress rejections where the request
    # was too malformed to read a valid identifier from it.
    agent_id: Optional[str] = None
    tool: Optional[str] = None
    rule_id: str
    reason: str
    stage: str
    # Checks that ran, in order. Checks stop at the first failure, so any
    # planned check that did not run is listed in checks_not_evaluated.
    checks: List[CheckResult] = Field(default_factory=list)
    checks_not_evaluated: List[str] = Field(default_factory=list)
    request_id: str
    policy_version: str
    tool_version: Optional[str] = None
    tool_manifest_hash: Optional[str] = None
    # SHA-256 of the canonical (agent_id, tool, parameters) the checks ran
    # against. Anything acting on an ALLOW must act on exactly that request.
    request_hash: Optional[str] = None
    # URL destinations only: resolution, pinning and deny-range results.
    network: List[NetworkInspection] = Field(default_factory=list)
    # Present only on ALLOW; downstream tools fail closed without it.
    request_integrity: Optional[RequestIntegrity] = None
    # Present only on CRYPTO-* rejections.
    anomalies: List[QuarantinedAnomaly] = Field(default_factory=list)
