import hashlib
import json
import re
import unicodedata
from typing import Any

from app.models.envelope import Principal, ToolCallEnvelope
from app.models.tool_call import ToolCall

# NFKC can expand a string (a single character can become up to 18), so the
# normalized result is capped rather than trusting the raw body size limit.
MAX_CANONICAL_STRING_LENGTH = 65_536

ALLOWED_CONTROL_CHARACTERS = frozenset("\t\n\r")

# Invisible characters that make text display differently from how it is
# processed: bidi overrides/isolates ("Trojan Source") and zero-width
# characters. The zero-width joiner/non-joiner are allowed (used in emoji
# and some scripts).
DISALLOWED_INVISIBLE_CHARACTERS = frozenset(
    "؜​‎‏‪‫‬‭‮⁠⁦⁧⁨⁩﻿"
)

_SAFE_NAME = re.compile(r"[A-Za-z0-9_]{1,64}")


class CanonicalizationError(Exception):
    def __init__(self, rule_id: str, reason: str) -> None:
        super().__init__(reason)
        self.rule_id = rule_id
        self.reason = reason


def canonical_json(value: Any) -> bytes:
    """Deterministic JSON encoding used for hashing: sorted keys, no
    insignificant whitespace, UTF-8, no NaN/Infinity.

    This is not full RFC 8785 (JCS) -- float formatting follows Python --
    which is sufficient for the values this gateway hashes today.
    """
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def canonicalize(tool_call: ToolCall, principal: Principal, request_id: str) -> ToolCallEnvelope:
    """Build the canonical envelope every security check operates on.

    Every string parameter value is NFKC-normalized and checked for invalid
    Unicode and control/invisible characters. Parameter names are checked
    but not normalized: they must match the tool schema exactly, and
    normalizing them could merge two distinct keys into one.

    Raises CanonicalizationError if the request cannot be represented
    unambiguously.
    """
    parameters = {
        name: _canonicalize_value(value, _label(name))
        for name, value in _checked_items(tool_call.parameters, "parameters")
    }
    request_hash = sha256_hex(
        canonical_json({"agent_id": principal.agent_id, "tool": tool_call.tool, "parameters": parameters})
    )
    return ToolCallEnvelope(
        request_id=request_id,
        principal=principal,
        tool=tool_call.tool,
        parameters=parameters,
        untrusted_context=tool_call.context,
        request_hash=request_hash,
    )


def _label(name: str) -> str:
    # Only echo a parameter name back in a reason when it is plainly safe to.
    return f"parameter '{name}'" if _SAFE_NAME.fullmatch(name) else "a parameter"


def _checked_items(mapping: dict, label: str):
    for key, value in mapping.items():
        _check_characters(key, f"a key in {label}")
        yield key, value


def _canonicalize_value(value: Any, label: str) -> Any:
    if isinstance(value, str):
        return _canonicalize_string(value, label)
    if isinstance(value, dict):
        return {key: _canonicalize_value(item, label) for key, item in _checked_items(value, label)}
    if isinstance(value, list):
        return [_canonicalize_value(item, label) for item in value]
    # int, float, bool, None. Strict JSON parsing already rejected NaN/Infinity.
    return value


def _canonicalize_string(value: str, label: str) -> str:
    _check_characters(value, label)
    normalized = unicodedata.normalize("NFKC", value)
    if len(normalized) > MAX_CANONICAL_STRING_LENGTH:
        raise CanonicalizationError("CANON-003", f"Value of {label} is too long after normalization")
    _check_characters(normalized, label)
    return normalized


def _check_characters(value: str, label: str) -> None:
    for char in value:
        category = unicodedata.category(char)
        if category == "Cs":
            raise CanonicalizationError("CANON-002", f"Value of {label} is not valid Unicode")
        if char in DISALLOWED_INVISIBLE_CHARACTERS or (
            category == "Cc" and char not in ALLOWED_CONTROL_CHARACTERS
        ):
            raise CanonicalizationError(
                "CANON-001", f"Value of {label} contains a disallowed control or invisible character"
            )
