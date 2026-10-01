"""Crypt-arithmetic quarantine guard.

Runs inside ingress, before a request becomes a typed ToolCall:

1. Numeric literals are intercepted *during* JSON parsing (json.loads'
   parse_int / parse_float hooks) so they are never converted: a literal
   that is too large is replaced by a QuarantinedNumber placeholder instead
   of being turned into a number that a downstream JS/IEEE-754 parser would
   silently truncate.
2. Values of cryptographic fields (signatures, nonces, DPoP proofs, MACs,
   digests, public keys, CRCs) must be canonically encoded and structurally
   valid. Keys that only *look* like cryptographic field names (homoglyphs)
   are treated as smuggling attempts.

Checks are structural. The gateway holds no signer keys, so it does not
verify signatures cryptographically; it refuses values that no valid
signature, point or proof could have.

Detail strings never echo the raw value. Anomalies carry the raw bytes only
so the ledger can fingerprint them and keep a bounded hex snippet.
"""

import base64
import binascii
import json
import re
import unicodedata
import zlib
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

MAX_CRYPTO_INT_BITS = 256
MAX_SAFE_INTEGER = 2**53 - 1  # largest integer IEEE-754 doubles represent exactly
# 2**256 has 78 decimal digits; anything longer is out of range without converting it.
_MAX_CRYPTO_INT_DIGITS = 78

# edwards25519 parameters (RFC 8032).
ED25519_P = 2**255 - 19
ED25519_L = 2**252 + 27742317777372353535851937790883648493
ED25519_D = (-121665 * pow(121666, -1, ED25519_P)) % ED25519_P

RSA_SIGNATURE_BYTES = (256, 384, 512)
MAC_BYTES = (32, 48, 64)
DPOP_ALGORITHMS = frozenset({"EdDSA", "ES256"})


class AnomalyType(str, Enum):
    CORRUPT_CRYPTO_TOKEN = "CORRUPT_CRYPTO_TOKEN"
    ARITHMETIC_INTEGER_OVERFLOW = "ARITHMETIC_INTEGER_OVERFLOW"
    NON_CANONICAL_ENCODING = "NON_CANONICAL_ENCODING"
    SIGNATURE_VERIFICATION_FAILURE = "SIGNATURE_VERIFICATION_FAILURE"
    DPOP_PROOF_TAMPERING = "DPOP_PROOF_TAMPERING"
    MALFORMED_BIGINT = "MALFORMED_BIGINT"


class RiskSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    ELEVATED = "ELEVATED"


class Mitigation(str, Enum):
    QUARANTINE_AND_HARD_DENY = "QUARANTINE_AND_HARD_DENY"
    STRIP_AND_RETRY_SANDBOX = "STRIP_AND_RETRY_SANDBOX"
    ISOLATE_SESSION = "ISOLATE_SESSION"


RULE_IDS: Dict[AnomalyType, str] = {
    AnomalyType.ARITHMETIC_INTEGER_OVERFLOW: "CRYPTO-001",
    AnomalyType.MALFORMED_BIGINT: "CRYPTO-002",
    AnomalyType.NON_CANONICAL_ENCODING: "CRYPTO-003",
    AnomalyType.CORRUPT_CRYPTO_TOKEN: "CRYPTO-004",
    AnomalyType.SIGNATURE_VERIFICATION_FAILURE: "CRYPTO-005",
    AnomalyType.DPOP_PROOF_TAMPERING: "CRYPTO-006",
}

# The gateway always blocks; the mitigation is the recommended follow-up.
MITIGATIONS: Dict[AnomalyType, Mitigation] = {
    AnomalyType.ARITHMETIC_INTEGER_OVERFLOW: Mitigation.QUARANTINE_AND_HARD_DENY,
    # A legitimate caller can resend the value as a decimal string.
    AnomalyType.MALFORMED_BIGINT: Mitigation.STRIP_AND_RETRY_SANDBOX,
    AnomalyType.NON_CANONICAL_ENCODING: Mitigation.QUARANTINE_AND_HARD_DENY,
    AnomalyType.CORRUPT_CRYPTO_TOKEN: Mitigation.QUARANTINE_AND_HARD_DENY,
    AnomalyType.SIGNATURE_VERIFICATION_FAILURE: Mitigation.QUARANTINE_AND_HARD_DENY,
    # A forged proof-of-possession means the caller's credential is suspect.
    AnomalyType.DPOP_PROOF_TAMPERING: Mitigation.ISOLATE_SESSION,
}

_SEVERITY_ORDER = {RiskSeverity.ELEVATED: 0, RiskSeverity.HIGH: 1, RiskSeverity.CRITICAL: 2}


@dataclass(frozen=True)
class Anomaly:
    anomaly_type: AnomalyType
    severity: RiskSeverity
    location: str
    detail: str
    raw: bytes

    @property
    def rule_id(self) -> str:
        return RULE_IDS[self.anomaly_type]

    @property
    def mitigation(self) -> Mitigation:
        return MITIGATIONS[self.anomaly_type]


def most_severe(anomalies: List[Anomaly]) -> Anomaly:
    """The anomaly that decides the verdict: highest severity, then first found."""
    return max(anomalies, key=lambda a: _SEVERITY_ORDER[a.severity])  # max() keeps the first on ties


# ---------------------------------------------------------------- numbers --


@dataclass(frozen=True)
class QuarantinedNumber:
    """Stands in for a numeric literal that was refused before conversion."""

    index: int


class NumericGuard:
    """parse_int / parse_float hooks for json.loads. Refused literals are
    recorded and replaced with a QuarantinedNumber; nothing is converted."""

    def __init__(self) -> None:
        self.refused: List[Tuple[AnomalyType, RiskSeverity, str, str]] = []

    def _refuse(self, kind: AnomalyType, severity: RiskSeverity, literal: str, detail: str) -> QuarantinedNumber:
        self.refused.append((kind, severity, literal, detail))
        return QuarantinedNumber(len(self.refused) - 1)

    def parse_int(self, literal: str) -> Any:
        digits = len(literal.lstrip("-"))
        if digits > _MAX_CRYPTO_INT_DIGITS:
            return self._refuse(
                AnomalyType.ARITHMETIC_INTEGER_OVERFLOW, RiskSeverity.CRITICAL, literal,
                f"integer literal with {digits} digits exceeds {MAX_CRYPTO_INT_BITS} bits",
            )
        value = int(literal)
        if value.bit_length() > MAX_CRYPTO_INT_BITS:
            return self._refuse(
                AnomalyType.ARITHMETIC_INTEGER_OVERFLOW, RiskSeverity.CRITICAL, literal,
                f"integer of {value.bit_length()} bits exceeds {MAX_CRYPTO_INT_BITS} bits",
            )
        if abs(value) > MAX_SAFE_INTEGER:
            return self._refuse(
                AnomalyType.MALFORMED_BIGINT, RiskSeverity.ELEVATED, literal,
                f"integer of {value.bit_length()} bits is outside the IEEE-754 safe range and would be truncated "
                "by downstream parsers; send big integers as decimal strings",
            )
        return value

    def parse_float(self, literal: str) -> Any:
        value = float(literal)
        if value in (float("inf"), float("-inf")) or abs(value) >= 2.0**MAX_CRYPTO_INT_BITS:
            return self._refuse(
                AnomalyType.ARITHMETIC_INTEGER_OVERFLOW, RiskSeverity.CRITICAL, literal,
                "numeric literal overflows the representable range",
            )
        return value

    def anomalies(self, data: Any) -> List[Anomaly]:
        """Attach the JSON path of each refused literal."""
        paths = {q.index: path for path, q in _find_placeholders(data, "$")}
        return [
            Anomaly(kind, severity, paths.get(i, "$"), detail, literal.encode("ascii"))
            for i, (kind, severity, literal, detail) in enumerate(self.refused)
        ]


def _find_placeholders(value: Any, path: str):
    if isinstance(value, QuarantinedNumber):
        yield path, value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _find_placeholders(item, _child_path(path, key))
    elif isinstance(value, list):
        for i, item in enumerate(value):
            yield from _find_placeholders(item, f"{path}[{i}]")


_SAFE_KEY = re.compile(r"[A-Za-z0-9_]{1,64}")


def _child_path(path: str, key: Any) -> str:
    # Only echo a key back when it is plainly safe to.
    return f"{path}.{key}" if isinstance(key, str) and _SAFE_KEY.fullmatch(key) else f"{path}.<key>"


# ---------------------------------------------------------- crypto fields --

_CRYPTO_FIELD = re.compile(r"signature|(?:^|_)sig(?:$|_)|nonce|dpop|hmac|(?:^|_)mac(?:$|_)|crc|public_?key|pubkey|digest|jws")

# Latin look-alikes from Cyrillic and Greek that NFKC does not fold.
_CONFUSABLES = str.maketrans(
    {
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j",
        "ѕ": "s", "ԁ": "d", "ԛ": "q", "ԝ": "w", "һ": "h", "ɡ": "g", "ո": "n",
        "α": "a", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p", "τ": "t", "υ": "u", "χ": "x",
    }
)


def _skeleton(key: str) -> str:
    return unicodedata.normalize("NFKC", key).casefold().translate(_CONFUSABLES)


def scan_crypto_fields(data: Any) -> List[Anomaly]:
    """Check every cryptographic field in the parsed body (any depth)."""
    anomalies: List[Anomaly] = []
    _scan(data, "$", anomalies)
    return anomalies


def _scan(value: Any, path: str, out: List[Anomaly]) -> None:
    if isinstance(value, list):
        for i, item in enumerate(value):
            _scan(item, f"{path}[{i}]", out)
        return
    if not isinstance(value, dict):
        return
    for key, item in value.items():
        child = _child_path(path, key)
        if isinstance(key, str) and _CRYPTO_FIELD.search(_skeleton(key)):
            if not key.isascii():
                out.append(Anomaly(
                    AnomalyType.NON_CANONICAL_ENCODING, RiskSeverity.CRITICAL, child,
                    "cryptographic field name uses look-alike (homoglyph) characters", key.encode("utf-8"),
                ))
                continue
            problem = _check_crypto_field(key.lower(), item, value)
            if problem is not None:
                kind, severity, detail = problem
                out.append(Anomaly(kind, severity, child, detail, _raw_bytes(item)))
                continue
        _scan(item, child, out)


def _raw_bytes(value: Any) -> bytes:
    if isinstance(value, str):
        return value.encode("utf-8", "surrogatepass")
    if isinstance(value, QuarantinedNumber):
        return b""
    return json.dumps(value, sort_keys=True, default=str).encode("utf-8")


Problem = Optional[Tuple[AnomalyType, RiskSeverity, str]]


def _check_crypto_field(key: str, value: Any, siblings: Dict[str, Any]) -> Problem:
    if "crc" in key:
        return _check_crc(value, siblings)
    if isinstance(value, (dict, list, QuarantinedNumber)) or value is None:
        return None  # structured values (e.g. a JWK) are scanned recursively; numbers were handled at parse time
    if not isinstance(value, str):
        return AnomalyType.CORRUPT_CRYPTO_TOKEN, RiskSeverity.HIGH, f"expected an encoded string, got {type(value).__name__}"
    if not value.isascii():
        return AnomalyType.NON_CANONICAL_ENCODING, RiskSeverity.CRITICAL, "non-ASCII (look-alike) characters in a cryptographic value"
    if "dpop" in key:
        return _check_dpop(value)

    decoded = decode_canonical(value)
    if isinstance(decoded, str):
        return AnomalyType.NON_CANONICAL_ENCODING, RiskSeverity.HIGH, decoded
    if "sig" in key or "jws" in key:
        return _check_signature(decoded)
    if "hmac" in key or re.search(r"(?:^|_)mac(?:$|_)", key):
        if len(decoded) not in MAC_BYTES:
            return AnomalyType.CORRUPT_CRYPTO_TOKEN, RiskSeverity.HIGH, f"MAC of {len(decoded)} bytes is not an HMAC-SHA-256/384/512 tag"
    if "nonce" in key and not any(decoded):
        return AnomalyType.CORRUPT_CRYPTO_TOKEN, RiskSeverity.HIGH, "all-zero nonce"
    if ("public" in key or "pubkey" in key) and len(decoded) == 32 and not is_ed25519_point(decoded):
        return AnomalyType.CORRUPT_CRYPTO_TOKEN, RiskSeverity.HIGH, "public key is not a valid edwards25519 point"
    return None


_HEX = re.compile(r"(?:0x)?[0-9A-Fa-f]+")
_B64_STD = re.compile(r"[A-Za-z0-9+/]+={0,2}")
_B64_URL = re.compile(r"[A-Za-z0-9_-]+={0,2}")


def decode_canonical(value: str) -> Any:
    """Decode hex or (url-safe) Base64. Returns bytes, or a reason string if
    the encoding is invalid or not the one canonical spelling of its bytes
    (odd-length or mixed-case hex, misplaced padding, non-zero trailing
    bits, mixed alphabets)."""
    if not value:
        return "empty value"
    if _HEX.fullmatch(value):
        body = value[2:] if value.startswith("0x") else value
        if len(body) % 2:
            return "odd-length hexadecimal"
        if body != body.lower() and body != body.upper():
            return "mixed-case hexadecimal"
        return bytes.fromhex(body)

    std, url = _B64_STD.fullmatch(value), _B64_URL.fullmatch(value)
    if not std and not url:
        return "characters outside the hex and Base64 alphabets (mixed alphabets or misplaced padding)"
    stripped = value.rstrip("=")
    padding = len(value) - len(stripped)
    if len(stripped) % 4 == 1:
        return "Base64 length is impossible"
    if padding and len(value) % 4:
        return "Base64 padding does not complete a quantum"
    if padding and (len(stripped) % 4 == 0 or 4 - len(stripped) % 4 != padding):
        return "superfluous Base64 padding"
    alphabet = "-_" if url and not std else "+/"
    try:
        decoded = base64.b64decode(stripped + "=" * (-len(stripped) % 4), altchars=alphabet.encode(), validate=True)
    except (binascii.Error, ValueError):
        return "invalid Base64"
    reencoded = base64.b64encode(decoded, altchars=alphabet.encode()).decode().rstrip("=")
    if reencoded != stripped:
        return "non-canonical Base64 (non-zero trailing bits)"
    return decoded


def is_ed25519_point(encoded: bytes) -> bool:
    """RFC 8032 section 5.1.3 point decoding, without the arithmetic after it."""
    if len(encoded) != 32:
        return False
    y = int.from_bytes(encoded, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= ED25519_P:
        return False
    p = ED25519_P
    u = (y * y - 1) % p
    v = (ED25519_D * y * y + 1) % p
    x = (u * pow(v, 3, p) * pow(u * pow(v, 7, p), (p - 5) // 8, p)) % p
    vx2 = (v * x * x) % p
    if vx2 == (-u) % p:
        x = (x * pow(2, (p - 1) // 4, p)) % p
    elif vx2 != u:
        return False
    return not (x == 0 and sign == 1)


def _check_signature(sig: bytes) -> Problem:
    if not any(sig):
        return AnomalyType.SIGNATURE_VERIFICATION_FAILURE, RiskSeverity.CRITICAL, "all-zero signature"
    if len(sig) == 64:
        if int.from_bytes(sig[32:], "little") >= ED25519_L:
            return AnomalyType.SIGNATURE_VERIFICATION_FAILURE, RiskSeverity.CRITICAL, "Ed25519 scalar S is not reduced mod l (malleable signature)"
        if not is_ed25519_point(sig[:32]):
            return AnomalyType.CORRUPT_CRYPTO_TOKEN, RiskSeverity.HIGH, "Ed25519 R is not a valid edwards25519 point"
        return None
    if len(sig) in RSA_SIGNATURE_BYTES:
        if all(b == 0xFF for b in sig):
            return AnomalyType.SIGNATURE_VERIFICATION_FAILURE, RiskSeverity.CRITICAL, "degenerate RSA signature"
        return None
    return AnomalyType.CORRUPT_CRYPTO_TOKEN, RiskSeverity.HIGH, f"signature of {len(sig)} bytes is neither Ed25519 (64) nor RSA (256/384/512)"


def _check_crc(value: Any, siblings: Dict[str, Any]) -> Problem:
    payload = next((siblings[k] for k in ("payload", "data", "body") if isinstance(siblings.get(k), str)), None)
    if isinstance(value, QuarantinedNumber):
        return None
    if isinstance(value, str):
        decoded = decode_canonical(value)
        if isinstance(decoded, str) or len(decoded) != 4:
            return AnomalyType.NON_CANONICAL_ENCODING, RiskSeverity.HIGH, "CRC-32 must be 8 hex digits"
        claimed = int.from_bytes(decoded, "big")
    elif isinstance(value, int) and not isinstance(value, bool) and 0 <= value < 2**32:
        claimed = value
    else:
        return AnomalyType.CORRUPT_CRYPTO_TOKEN, RiskSeverity.HIGH, "CRC-32 is not a 32-bit unsigned value"
    if payload is not None and zlib.crc32(payload.encode("utf-8")) != claimed:
        return AnomalyType.CORRUPT_CRYPTO_TOKEN, RiskSeverity.HIGH, "CRC-32 does not match the payload"
    return None


def _b64url_json(segment: str) -> Any:
    decoded = decode_canonical(segment)
    if isinstance(decoded, str) or "=" in segment:
        return None
    try:
        parsed = json.loads(decoded.decode("utf-8"), object_pairs_hook=_no_duplicates)
    except (UnicodeDecodeError, ValueError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _no_duplicates(pairs):
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate key")
    return dict(pairs)


def _check_dpop(value: str) -> Problem:
    """RFC 9449 proof structure: compact JWS, typ dpop+jwt, asymmetric alg,
    public JWK only, required claims, well-formed signature."""
    tampered = AnomalyType.DPOP_PROOF_TAMPERING, RiskSeverity.CRITICAL
    parts = value.split(".")
    if len(parts) != 3 or not all(re.fullmatch(r"[A-Za-z0-9_-]+", p) for p in parts):
        return (*tampered, "DPoP proof is not a compact JWS (three base64url segments)")
    header, claims = _b64url_json(parts[0]), _b64url_json(parts[1])
    if header is None or claims is None:
        return (*tampered, "DPoP header or claims are not canonical base64url JSON objects")
    if header.get("typ") != "dpop+jwt":
        return (*tampered, "DPoP header typ is not dpop+jwt")
    if header.get("alg") not in DPOP_ALGORITHMS:
        return (*tampered, "DPoP alg is not an allowed asymmetric algorithm (alg=none/HS* refused)")
    jwk = header.get("jwk")
    if not isinstance(jwk, dict) or "d" in jwk:
        return (*tampered, "DPoP jwk is missing or contains private key material")
    if not all(isinstance(claims.get(c), str) for c in ("jti", "htm", "htu")) or not isinstance(claims.get("iat"), int):
        return (*tampered, "DPoP claims jti/htm/htu/iat are missing or mistyped")
    signature = decode_canonical(parts[2])
    if isinstance(signature, str) or len(signature) != 64:
        return (*tampered, "DPoP signature is not 64 bytes")
    if header["alg"] == "EdDSA":
        problem = _check_signature(signature)
        if problem is not None:
            return (*tampered, f"DPoP signature: {problem[2]}")
        if jwk.get("crv") != "Ed25519" or not isinstance(jwk.get("x"), str):
            return (*tampered, "DPoP jwk is not an Ed25519 public key")
        x = decode_canonical(jwk["x"])
        if isinstance(x, str) or not is_ed25519_point(x):
            return (*tampered, "DPoP jwk x is not a valid edwards25519 point")
    return None
