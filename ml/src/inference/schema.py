"""Public API types (plan §2). Plain dataclasses, JSON-serialisable, no sklearn objects."""
from __future__ import annotations

import json
import math
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class MLRequest:
    request_id: str
    task_text: str
    tool_name: str
    tool_description: str = ""
    arguments: dict = field(default_factory=dict)
    current_observation: str = ""
    # each previous step: {"tool_name"|"tool", "arguments"|"args", "observation"|"obs"}
    previous_steps: list = field(default_factory=list)
    # optional keys: "known_entities" {user, email, company, contacts:[{name,email}], known_domains:[...]},
    #                "domain" (str)
    session_features: dict = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict) -> "MLRequest":
        return cls(
            request_id=str(d.get("request_id", "")),
            task_text=d.get("task_text", "") or "",
            tool_name=d.get("tool_name", "") or "",
            tool_description=d.get("tool_description", "") or "",
            arguments=d.get("arguments") or {},
            current_observation=d.get("current_observation", "") or "",
            previous_steps=list(d.get("previous_steps") or []),
            session_features=dict(d.get("session_features") or {}),
        )


def _bounded(x: float) -> float:
    x = float(x)
    if math.isnan(x):
        return 0.0
    return min(1.0, max(0.0, x))


@dataclass
class MLRiskResult:
    p_inject: float
    p_misaligned: float
    anomaly_score: float
    sequence_surprisal: float
    context_shift: float
    fused_risk: float
    risk_vector: dict
    conformal_abstain: bool
    model_version: str
    feature_version: str
    request_id: str = ""
    top_risk_features: list = field(default_factory=list)
    latency_ms: dict = field(default_factory=dict)

    def __post_init__(self):
        for name in ("p_inject", "p_misaligned", "anomaly_score", "sequence_surprisal",
                     "context_shift", "fused_risk"):
            setattr(self, name, _bounded(getattr(self, name)))
        self.conformal_abstain = bool(self.conformal_abstain)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict())
