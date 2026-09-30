"""Deterministic cleaning (plan §7) and world anonymization (AgentDrift leakage control).

Cleaning NEVER removes attack text: malicious instructions are the signal.
"""
from __future__ import annotations

import json
import re
import unicodedata
from typing import Any

_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f​-‏  ‪-‮⁠-⁤﻿]")
_WS_RE = re.compile(r"\s+")
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
URL_RE = re.compile(r"(?:https?://|www\.)[^\s\"'<>)]+", re.IGNORECASE)


def normalize_text(value: Any) -> str:
    """Unicode NFKC -> strip invalid control chars -> normalize whitespace. None/empty -> ""."""
    if value is None:
        return ""
    if not isinstance(value, str):
        value = str(value)
    value = unicodedata.normalize("NFKC", value)
    value = _CONTROL_RE.sub(" ", value)
    return _WS_RE.sub(" ", value).strip()


def _clean_json_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {normalize_text(k): _clean_json_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_clean_json_value(v) for v in value]
    if isinstance(value, str):
        return normalize_text(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return normalize_text(value)


def clean_arguments(args: Any) -> dict:
    """Validate JSON arguments and return a cleaned dict. Strings are parsed as JSON when possible."""
    if args is None:
        return {}
    if isinstance(args, str):
        try:
            args = json.loads(args)
        except (ValueError, TypeError):
            return {"_raw": normalize_text(args)}
    if not isinstance(args, dict):
        return {"_value": _clean_json_value(args)}
    cleaned = _clean_json_value(args)
    json.dumps(cleaned)  # raises if not serialisable
    return cleaned


def canonical_json(args: dict) -> str:
    """Canonical serialisation: json.dumps(sort_keys=True)."""
    return json.dumps(args or {}, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)


def email_domain(email: str) -> str:
    return email.rsplit("@", 1)[-1].lower().replace(" ", "")


class WorldAnonymizer:
    """Replaces world identities with relation-preserving placeholders.

    AgentDrift README: "anonymize the world before training (replace person and company names with
    placeholders and every address with an in-domain or out-of-domain placeholder, which keeps the
    relations and removes identity)". At inference the gateway may pass the same information via
    ``session_features["known_entities"]``; without it only e-mail addresses are abstracted.
    """

    def __init__(self, world: dict | None):
        world = world or {}
        self.known_emails: set[str] = set()
        self.known_domains: set[str] = set()
        names: list[tuple[str, str]] = []
        user_email = normalize_text(world.get("email", "")).lower()
        if user_email:
            self.known_emails.add(user_email)
            self.known_domains.add(email_domain(user_email))
        for d in world.get("known_domains", []) or []:
            self.known_domains.add(normalize_text(d).lower())
        user = normalize_text(world.get("user", ""))
        if user:
            names.append((user, "<USER>"))
        for c in world.get("contacts", []) or []:
            if not isinstance(c, dict):
                continue
            em = normalize_text(c.get("email", "")).lower()
            if em:
                self.known_emails.add(em)
                self.known_domains.add(email_domain(em))
            nm = normalize_text(c.get("name", ""))
            if nm:
                names.append((nm, "<CONTACT>"))
        company = normalize_text(world.get("company", ""))
        self._patterns: list[tuple[re.Pattern, str]] = []
        if company:
            self._patterns.append((re.compile(re.escape(company), re.IGNORECASE), "<COMPANY>"))
        # full names first, then individual name parts (>=3 chars) e.g. possessives "Yara's"
        parts: dict[str, str] = {}
        for full, tag in names:
            self._patterns.append((re.compile(r"\b" + re.escape(full) + r"\b", re.IGNORECASE), tag))
            for p in full.split():
                if len(p) >= 3 and p.lower() not in parts:
                    parts[p.lower()] = tag
        for p, tag in sorted(parts.items(), key=lambda kv: -len(kv[0])):
            self._patterns.append((re.compile(r"\b" + re.escape(p) + r"\b", re.IGNORECASE), tag))

    def is_internal_email(self, email: str) -> bool:
        e = email.lower()
        return e in self.known_emails or email_domain(e) in self.known_domains

    def _email_sub(self, m: re.Match) -> str:
        return "<INTERNAL_EMAIL>" if self.is_internal_email(m.group(0)) else "<EXTERNAL_EMAIL>"

    def __call__(self, text: str) -> str:
        if not text:
            return ""
        text = EMAIL_RE.sub(self._email_sub, text)
        for pat, tag in self._patterns:
            text = pat.sub(tag, text)
        return text
