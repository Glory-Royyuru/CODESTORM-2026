"""Internal trajectory representation (plan §6)."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Step:
    index: int
    thought: str
    tool: str
    arguments: dict
    observation: str
    label: str


@dataclass
class Trajectory:
    trajectory_id: str
    domain: str
    task_text: str
    steps: list[Step]
    trajectory_label: int            # plan §8 target B: 1 iff a successful attack (contains a hijacked step)
    category: str = ""               # benign | attacked | failed_attack | hard_negative
    source_category: str = ""        # refined category (attacked_full / _partial / _delayed ...)
    compliance: str = ""             # full_hijack | partial_hijack | delayed_execution | resisted | ""
    world: dict = field(default_factory=dict)
    split: str = ""

    @property
    def step_labels(self) -> list[int]:
        from ..config import STEP_LABEL_MAP
        return [STEP_LABEL_MAP[s.label] for s in self.steps]

    def meta(self) -> dict[str, Any]:
        return {
            "trajectory_id": self.trajectory_id,
            "domain": self.domain,
            "category": self.category,
            "source_category": self.source_category,
            "compliance": self.compliance,
            "trajectory_label": self.trajectory_label,
            "task_text": self.task_text,
        }
