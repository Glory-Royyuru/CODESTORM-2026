"""Application request integrity: an HMAC-SHA256 tag over the exact request
the gateway allowed.

This is separate from caller identity (transport/workload authentication,
not implemented yet -- see identity.py). Identity says *who* is calling; the
integrity tag says *this exact request* was approved by the gateway. The
execution layer recomputes the tag from the verdict's fields and must refuse
to run a tool if the tag is missing or does not match (fail closed).
"""

import hashlib
import hmac
import os
import secrets
from typing import Any, Dict, Mapping, Optional

from app.gateway.canonicalizer import canonical_json

ALGORITHM = "HMAC-SHA256"
SECRET_ENV = "SATG_GATEWAY_HMAC_SECRET"
MIN_SECRET_BYTES = 32

# The verdict fields the tag binds. pinned_ips binds the DNS pin, so the
# execution layer cannot be pointed at a different address.
SIGNED_FIELDS = ("request_id", "agent_id", "tool", "request_hash", "tool_manifest_hash", "policy_version", "pinned_ips")


def _load_secret() -> bytes:
    configured = os.environ.get(SECRET_ENV)
    if configured is None:
        # Per-process key: tags are only verifiable while this process runs.
        return secrets.token_bytes(MIN_SECRET_BYTES)
    secret = configured.encode("utf-8")
    if len(secret) < MIN_SECRET_BYTES:
        raise RuntimeError(f"{SECRET_ENV} must be at least {MIN_SECRET_BYTES} bytes")
    return secret


_SECRET = _load_secret()
KEY_ID = "satg-hmac-" + hashlib.sha256(b"satg-key-id:" + _SECRET).hexdigest()[:12]


def canonical_request(fields: Mapping[str, Any]) -> bytes:
    return canonical_json({name: fields.get(name) for name in SIGNED_FIELDS})


def sign_request(fields: Mapping[str, Any]) -> Dict[str, Any]:
    tag = hmac.new(_SECRET, canonical_request(fields), hashlib.sha256).hexdigest()
    return {"algorithm": ALGORITHM, "key_id": KEY_ID, "signed_fields": list(SIGNED_FIELDS), "signature": tag}


def verify_request_integrity(fields: Mapping[str, Any], integrity: Optional[Mapping[str, Any]]) -> bool:
    """What a downstream tool runs before acting. Missing, foreign-key or
    mismatched tags all fail closed."""
    if not integrity or integrity.get("algorithm") != ALGORITHM or integrity.get("key_id") != KEY_ID:
        return False
    signature = integrity.get("signature")
    if not isinstance(signature, str):
        return False
    expected = hmac.new(_SECRET, canonical_request(fields), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)
