from enum import Enum
from typing import Any, Dict, List, Literal, Optional

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


class MLFactor(BaseModel):
    feature: str
    value: float
    # Share of the absolute XGBoost contribution that pushed risk up.
    contribution: float


class MLAssessment(BaseModel):
    """Advisory risk assessment from the SATG ML package (ml/). Only numeric
    model features are exposed; request text never is."""

    status: Literal["ok", "unavailable", "error", "not_consulted", "disabled"]
    mode: str
    model_version: Optional[str] = None
    feature_version: Optional[str] = None
    # Calibrated fused_risk in [0, 1].
    risk_score: Optional[float] = None
    # Level from ml/configs/decision_thresholds.json (ALLOW < MONITOR < STEP_UP < ...).
    risk_level: Optional[str] = None
    # fused_risk >= 0.5, the a-priori threshold used in the ML evaluation.
    prediction: Optional[Literal["risky", "benign"]] = None
    conformal_abstain: Optional[bool] = None
    signals: Dict[str, float] = Field(default_factory=dict)
    features: Dict[str, float] = Field(default_factory=dict)
    top_factors: List[MLFactor] = Field(default_factory=list)
    # Which caller-supplied context fields (task, observation, previous_steps) the model saw.
    context_used: List[str] = Field(default_factory=list)
    latency_ms: Optional[float] = None
    detail: Optional[str] = None


class DecisionTrace(BaseModel):
    """How the final verdict was reached: deterministic policy first, then ML."""

    deterministic_verdict: Literal["ALLOW", "BLOCK"]
    deterministic_rule_id: str
    ml_mode: str
    ml_high_risk_threshold: float
    ml_critical_risk_threshold: float
    final_verdict: Literal["ALLOW", "BLOCK", "ESCALATE"]
    final_rule_id: str


class SandboxExecution(BaseModel):
    """Result of running an ALLOWED call in a disposable Docker container."""

    sandbox_id: Optional[str] = None
    status: Literal[
        "success", "tool_error", "rejected", "timeout", "killed", "sandbox_unavailable",
        "integrity_failed", "error", "not_executed",
    ]
    exit_code: Optional[int] = None
    duration_ms: Optional[float] = None
    stdout: str = ""
    stderr: str = ""
    # Parsed runner output, when it was valid JSON.
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    container_removed: Optional[bool] = None


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
    # Present when the ML layer was reachable in the decision (not for ingress rejections).
    ml: Optional[MLAssessment] = None
    decision: Optional[DecisionTrace] = None
    # Present only on ALLOW; BLOCK and ESCALATE never reach the sandbox.
    execution: Optional[SandboxExecution] = None
