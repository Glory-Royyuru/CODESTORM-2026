from enum import Enum
from typing import List, Optional

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


class CheckStatus(str, Enum):
    PASSED = "PASSED"
    FAILED = "FAILED"


class CheckResult(BaseModel):
    check: str
    status: CheckStatus


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
