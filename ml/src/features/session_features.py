"""Behavioural session features (plan §15) and stable context features (plan §18).

All features are computed from the session history (previous steps) plus the current step only, so
training and inference share exactly the same causal definition.
"""
from __future__ import annotations

import json
import math
from functools import lru_cache
from pathlib import Path

from ..config import CONFIG_DIR
from .text_features import extract_destinations, is_external

BEHAVIOR_FEATURES = [
    "number_of_steps",
    "unique_tools",
    "tool_switch_rate",
    "repeated_tool_rate",
    "argument_length",
    "observation_length",
    "new_destination_count",
    "external_domain_count",
    "sensitive_action_count",
    "action_frequency",
    "tool_transition_frequency",
]


@lru_cache(maxsize=1)
def _tier_config() -> dict:
    return json.loads((CONFIG_DIR / "tool_risk_tiers.json").read_text(encoding="utf-8"))


def tool_risk_tier(tool: str) -> int:
    cfg = _tier_config()
    t = tool.lower()
    if t in cfg["overrides"]:
        return int(cfg["overrides"][t])
    for prefix, tier in cfg["verb_prefix_tiers"]:
        if t.startswith(prefix):
            return int(tier)
    return int(cfg["default_tier"])


def session_features(tools: list[str], args_json: list[str], observations: list[str],
                     known_domains: set[str], known_emails: set[str],
                     trigram=None) -> tuple[dict[str, float], dict[str, float]]:
    """``tools``/``args_json``/``observations`` include the current step as the last element.

    Returns (behaviour features for IsolationForest, context features for fusion).
    """
    n = len(tools)
    cur_tool = tools[-1]
    switches = sum(1 for i in range(1, n) if tools[i] != tools[i - 1])
    repeats = n - len(set(tools))

    # destinations introduced by actions (arguments) — where data is being sent / acted upon
    seen: set[str] = set()
    changes = 0
    new_now = 0
    for i, a in enumerate(args_json):
        dests = set(extract_destinations(a))
        new = dests - seen
        if new:
            changes += 1
            if i == n - 1:
                new_now = len(new)
        seen |= dests
    ext_domains = {d.split("@")[-1] for d in seen if is_external(d, known_domains, known_emails)}
    sensitive = sum(1 for t in tools if tool_risk_tier(t) >= 3)

    if trigram is not None and trigram.total:
        action_freq = trigram.uni.get(cur_tool, 0) / trigram.total
        prev = tools[-2] if n >= 2 else "<s>"
        ctx = trigram.ctx1.get(prev, 0)
        trans_freq = trigram.bi.get((prev, cur_tool), 0) / ctx if ctx else 0.0
    else:
        action_freq = trans_freq = 0.0

    arg_len = math.log1p(len(args_json[-1]))
    obs_len = math.log1p(len(observations[-1]))
    behaviour = {
        "number_of_steps": float(n),
        "unique_tools": float(len(set(tools))),
        "tool_switch_rate": switches / (n - 1) if n > 1 else 0.0,
        "repeated_tool_rate": repeats / n,
        "argument_length": arg_len,
        "observation_length": obs_len,
        "new_destination_count": float(new_now),
        "external_domain_count": float(len(ext_domains)),
        "sensitive_action_count": float(sensitive),
        "action_frequency": float(action_freq),
        "tool_transition_frequency": float(trans_freq),
    }
    context = {
        "tool_risk_tier": float(tool_risk_tier(cur_tool)),
        "session_step_count": float(n),
        "unique_tool_count": float(len(set(tools))),
        "destination_change_count": float(changes),
        "argument_size": arg_len,
        "observation_size": obs_len,
    }
    return behaviour, context
