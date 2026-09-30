from enum import Enum
from typing import List

from pydantic import BaseModel, Field


class VerdictType(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class CheckResult(BaseModel):
    check: str
    status: str


class Verdict(BaseModel):
    verdict: VerdictType
    severity: Severity
    agent_id: str
    tool: str
    rule_id: str
    reason: str
    stage: str
    checks: List[CheckResult] = Field(default_factory=list)
