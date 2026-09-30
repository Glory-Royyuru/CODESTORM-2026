import base64
import json

import pytest

from app.audit.anomaly_ledger import MAX_SNIPPET_BYTES, get_anomalies
from app.gateway.crypto_guard import ED25519_L, decode_canonical, is_ed25519_point

# RFC 8032 section 7.1, test 1.
PUBLIC_KEY = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
SIGNATURE = bytes.fromhex(
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
    "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
)
TWO_POW_256 = 2**256


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def dpop(header=None, claims=None, signature=SIGNATURE) -> str:
    header = header or {"typ": "dpop+jwt", "alg": "EdDSA", "jwk": {"kty": "OKP", "crv": "Ed25519", "x": b64url(PUBLIC_KEY)}}
    claims = claims or {"jti": "e1j3V_bKic8-LAEB", "htm": "POST", "htu": "https://satg.local/v1/toolcalls", "iat": 1790000000}
    return ".".join([b64url(json.dumps(header).encode()), b64url(json.dumps(claims).encode()), b64url(signature)])


def settle(**overrides) -> dict:
    parameters = {
        "invoice_id": "INV-2044",
        "amount_minor": 125000,
        "currency": "EUR",
        "partner_signature": SIGNATURE.hex(),
        "dpop_proof": dpop(),
        **overrides,
    }
    return {"agent_id": "billing-bot", "tool": "settle_invoice", "parameters": parameters}


def post_raw(client, text: str):
    return client.post("/v1/toolcalls", content=text.encode("utf-8"), headers={"content-type": "application/json"})


def test_well_formed_signed_call_is_allowed(client):
    response = client.post("/v1/toolcalls", json=settle())
    body = response.json()
    assert response.status_code == 200
    assert body["verdict"] == "ALLOW"
    assert body["anomalies"] == []


def test_integer_overflow_is_quarantined_before_conversion(client):
    text = json.dumps(settle(amount_minor=0)).replace('"amount_minor": 0', f'"amount_minor": {TWO_POW_256}')
    response = post_raw(client, text)
    body = response.json()
    assert response.status_code == 400
    assert body["verdict"] == "BLOCK"
    assert body["rule_id"] == "CRYPTO-001"
    assert body["severity"] == "CRITICAL"
    assert body["stage"] == "quarantine"
    assert body["agent_id"] == "billing-bot"
    anomaly = body["anomalies"][0]
    assert anomaly["anomaly_type"] == "ARITHMETIC_INTEGER_OVERFLOW"
    assert anomaly["location"] == "$.parameters.amount_minor"
    assert anomaly["mitigation_action"] == "QUARANTINE_AND_HARD_DENY"
    assert bytes.fromhex(anomaly["quarantined_hex_snippet"]) == str(TWO_POW_256).encode()[:MAX_SNIPPET_BYTES]


def test_huge_literal_is_never_converted(client):
    # Python refuses to convert integer strings over 4300 digits; the guard
    # must reject the literal without trying.
    text = json.dumps(settle(amount_minor=0)).replace('"amount_minor": 0', '"amount_minor": ' + "9" * 5000)
    body = post_raw(client, text).json()
    assert body["rule_id"] == "CRYPTO-001"
    anomaly = body["anomalies"][0]
    assert anomaly["raw_payload_bytes"] == 5000
    assert len(bytes.fromhex(anomaly["quarantined_hex_snippet"])) == MAX_SNIPPET_BYTES


def test_unsafe_integer_is_malformed_bigint(client):
    body = client.post("/v1/toolcalls", json=settle(amount_minor=2**60)).json()
    assert body["rule_id"] == "CRYPTO-002"
    assert body["severity"] == "MEDIUM"
    assert body["anomalies"][0]["mitigation_action"] == "STRIP_AND_RETRY_SANDBOX"


def test_float_overflow(client):
    text = '{"agent_id": "research-bot", "tool": "get_weather", "parameters": {"city": "x", "n": 1e400}}'
    assert post_raw(client, text).json()["rule_id"] == "CRYPTO-001"


@pytest.mark.parametrize(
    "signature, rule",
    [
        (SIGNATURE.hex()[:-1], "CRYPTO-003"),  # odd-length hex
        (SIGNATURE.hex()[:64].upper() + SIGNATURE.hex()[64:], "CRYPTO-003"),  # mixed case
        (base64.b64encode(SIGNATURE).decode()[:-2] + "=", "CRYPTO-003"),  # broken padding
        ("AB==", "CRYPTO-003"),  # non-zero trailing bits
        (SIGNATURE.hex()[:120], "CRYPTO-004"),  # 60 bytes
        ("00" * 64, "CRYPTO-005"),  # all-zero
        (SIGNATURE[:32].hex() + (int.from_bytes(SIGNATURE[32:], "little") + ED25519_L).to_bytes(32, "little").hex(), "CRYPTO-005"),
        (("ff" * 31 + "7f") + SIGNATURE.hex()[64:], "CRYPTO-004"),  # R not on the curve
        ("е" + SIGNATURE.hex()[1:], "CRYPTO-003"),  # Cyrillic e
    ],
)
def test_signature_anomalies(client, signature, rule):
    body = client.post("/v1/toolcalls", json=settle(partner_signature=signature)).json()
    assert body["verdict"] == "BLOCK"
    assert body["rule_id"] == rule


@pytest.mark.parametrize(
    "proof",
    [
        "not-a-jws",
        dpop(header={"typ": "dpop+jwt", "alg": "none", "jwk": {"kty": "OKP", "crv": "Ed25519", "x": b64url(PUBLIC_KEY)}}),
        dpop(header={"typ": "dpop+jwt", "alg": "HS256", "jwk": {"kty": "oct"}}),
        dpop(header={"typ": "JWT", "alg": "EdDSA", "jwk": {"kty": "OKP", "crv": "Ed25519", "x": b64url(PUBLIC_KEY)}}),
        dpop(header={"typ": "dpop+jwt", "alg": "EdDSA", "jwk": {"kty": "OKP", "crv": "Ed25519", "x": b64url(PUBLIC_KEY), "d": "secret"}}),
        dpop(claims={"htm": "POST"}),
        dpop(signature=b"\x00" * 64),
        dpop(signature=SIGNATURE[:40]),
    ],
)
def test_dpop_tampering(client, proof):
    body = client.post("/v1/toolcalls", json=settle(dpop_proof=proof)).json()
    assert body["rule_id"] == "CRYPTO-006"
    assert body["severity"] == "CRITICAL"
    assert body["anomalies"][0]["mitigation_action"] == "ISOLATE_SESSION"


def test_homoglyph_crypto_key_is_smuggling(client):
    request = settle()
    request["parameters"]["ѕignature"] = SIGNATURE.hex()  # Cyrillic dze
    body = client.post("/v1/toolcalls", json=request).json()
    assert body["rule_id"] == "CRYPTO-003"
    assert body["severity"] == "CRITICAL"
    assert body["anomalies"][0]["location"] == "$.parameters.<key>"


def test_crc_mismatch(client, temp_tool):
    temp_tool(parameters={"payload": {"type": "string"}, "crc32": {"type": "string"}})
    request = {"agent_id": "test-agent", "tool": "temp_tool", "parameters": {"payload": "hello", "crc32": "00000000"}}
    assert client.post("/v1/toolcalls", json=request).json()["rule_id"] == "CRYPTO-004"
    request["parameters"]["crc32"] = "3610a686"  # crc32(b"hello")
    assert client.post("/v1/toolcalls", json=request).json()["verdict"] == "ALLOW"


def test_most_severe_anomaly_decides_and_all_are_ledgered(client):
    text = json.dumps(settle(partner_signature="00" * 64, dpop_proof="x.y")).replace(
        '"amount_minor": 125000', '"amount_minor": 9007199254740993'
    )
    body = post_raw(client, text).json()
    types = [a["anomaly_type"] for a in body["anomalies"]]
    assert types == ["MALFORMED_BIGINT", "SIGNATURE_VERIFICATION_FAILURE", "DPOP_PROOF_TAMPERING"]
    # First CRITICAL wins over the earlier ELEVATED one.
    assert body["rule_id"] == "CRYPTO-005"
    ledgered = {r["anomaly_id"]: r for r in get_anomalies()}
    for anomaly in body["anomalies"]:
        record = ledgered[anomaly["anomaly_id"]]
        assert record["request_id"] == body["request_id"]
        assert record["raw_payload_sha256"].startswith("sha256:")


def test_context_is_not_scanned(client):
    request = {"agent_id": "research-bot", "tool": "get_weather", "parameters": {"city": "Berlin"}, "context": {"signature": "zz"}}
    assert client.post("/v1/toolcalls", json=request).json()["verdict"] == "ALLOW"


def test_decode_canonical():
    assert decode_canonical("0xdeadbeef") == bytes.fromhex("deadbeef")
    assert decode_canonical("aGVsbG8") == b"hello"
    assert decode_canonical("aGVsbG8=") == b"hello"
    assert isinstance(decode_canonical("aGVsbG8=="), str)
    assert isinstance(decode_canonical("a+b-"), str)  # mixed alphabets


def test_ed25519_point_check():
    assert is_ed25519_point(PUBLIC_KEY)
    assert not is_ed25519_point(b"\xff" * 31 + b"\x7f")
