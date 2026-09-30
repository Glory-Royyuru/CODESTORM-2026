from enum import Enum

from pydantic import BaseModel


class VerdictType(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class Verdict(BaseModel):
    verdict: VerdictType
    severity: Severity
    agent_id: str
    tool: str
    rule_id: str
    reason: str
    stage: str
