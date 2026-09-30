"""AgentDrift ingestion (plan §6): locate, load JSONL, validate, clean, convert to Trajectory."""
from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from ..config import AGENTDRIFT_DIR, AGENTDRIFT_SPLIT, STEP_LABEL_MAP, VALID_CATEGORIES
from .cleaning import clean_arguments, normalize_text
from .schema import Step, Trajectory

REQUIRED_TRAJ_FIELDS = ("id", "agent", "category", "task", "steps")
REQUIRED_STEP_FIELDS = ("tool", "args", "obs", "label")

# AgentDrift label grammar (README "Label grammar"): B = benign, I = injection_point,
# H = hijacked, F = failed_injection
_GRAMMAR = {
    "benign": re.compile(r"^B+$"),
    "hard_negative": re.compile(r"^B+$"),
    "attacked": re.compile(r"^B+IH+(B+)?$|^B+IB+HB+$"),
    "failed_attack": re.compile(r"^B+FB+$"),
}
_LETTER = {"benign": "B", "injection_point": "I", "hijacked": "H", "failed_injection": "F"}


@dataclass
class LoadReport:
    split: str
    total_records: int = 0
    accepted: int = 0
    rejected: Counter = field(default_factory=Counter)
    categories: Counter = field(default_factory=Counter)
    step_labels: Counter = field(default_factory=Counter)

    def to_dict(self) -> dict:
        return {
            "split": self.split,
            "total_records": self.total_records,
            "accepted": self.accepted,
            "rejected_total": sum(self.rejected.values()),
            "rejected_by_reason": dict(self.rejected),
            "categories": dict(self.categories),
            "step_labels": dict(self.step_labels),
        }


def validate_record(rec: dict) -> str | None:
    """Returns a rejection reason, or None if the record is valid."""
    if not isinstance(rec, dict):
        return "not_an_object"
    for f in REQUIRED_TRAJ_FIELDS:
        if f not in rec:
            return f"missing_field:{f}"
    if rec["category"] not in VALID_CATEGORIES:
        return "invalid_category"
    steps = rec["steps"]
    if not isinstance(steps, list) or len(steps) == 0:
        return "empty_steps"
    for s in steps:
        if not isinstance(s, dict):
            return "step_not_object"
        for f in REQUIRED_STEP_FIELDS:
            if f not in s:
                return f"step_missing_field:{f}"
        if s["label"] not in STEP_LABEL_MAP:
            return "invalid_step_label"
        if not normalize_text(s["tool"]):
            return "empty_tool"
    if not normalize_text(rec["task"]):
        return "empty_task"
    labels = "".join(_LETTER[s["label"]] for s in steps)
    if not _GRAMMAR[rec["category"]].match(labels):
        return "label_grammar_violation"
    return None


def record_to_trajectory(rec: dict) -> Trajectory:
    steps = [
        Step(
            index=i,
            thought=normalize_text(s.get("thought", "")),
            tool=normalize_text(s["tool"]),
            arguments=clean_arguments(s.get("args")),
            observation=normalize_text(s.get("obs", "")),
            label=s["label"],
        )
        for i, s in enumerate(rec["steps"])
    ]
    traj_label = int(any(s.label == "hijacked" for s in steps))
    return Trajectory(
        trajectory_id=str(rec["id"]),
        domain=normalize_text(rec["agent"]),
        task_text=normalize_text(rec["task"]),
        steps=steps,
        trajectory_label=traj_label,
        category=rec["category"],
        source_category=rec.get("source_category", rec["category"]),
        compliance=rec.get("compliance", "") or "",
        world=rec.get("world") or {},
        split=rec.get("split", ""),
    )


def load_records(records: Iterable, split: str = "") -> tuple[list[Trajectory], LoadReport]:
    report = LoadReport(split=split)
    out: list[Trajectory] = []
    for rec in records:
        report.total_records += 1
        reason = validate_record(rec)
        if reason:
            report.rejected[reason] += 1
            continue
        try:
            traj = record_to_trajectory(rec)
        except (TypeError, ValueError) as exc:  # e.g. non-serialisable args
            report.rejected[f"conversion_error:{type(exc).__name__}"] += 1
            continue
        out.append(traj)
        report.accepted += 1
        report.categories[traj.category] += 1
        report.step_labels.update(s.label for s in traj.steps)
    return out, report


def _iter_jsonl(path: Path, report_bad: Counter):
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                report_bad["invalid_json"] += 1


def locate_dataset(root: Path | None = None) -> Path:
    root = Path(root or AGENTDRIFT_DIR)
    split_dir = root / AGENTDRIFT_SPLIT
    if not (split_dir / "train.jsonl").exists():
        raise FileNotFoundError(
            f"AgentDrift not found at {split_dir}. Clone https://github.com/Asif-0209/AgentDrift into {root}")
    return split_dir


def load_split(part: str, root: Path | None = None) -> tuple[list[Trajectory], LoadReport]:
    split_dir = locate_dataset(root)
    bad: Counter = Counter()
    trajs, report = load_records(_iter_jsonl(split_dir / f"{part}.jsonl", bad), split=part)
    report.rejected.update(bad)
    report.total_records += sum(bad.values())
    return trajs, report
