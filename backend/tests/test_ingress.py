import json

from app.gateway.ingress import MAX_BODY_BYTES

VALID_REQUEST = {
    "agent_id": "support-bot-3",
    "tool": "send_email",
    "parameters": {"to": "user@company.com", "subject": "Support", "body": "Hello"},
}
JSON_HEADERS = {"content-type": "application/json"}


def post_raw(client, body, headers=JSON_HEADERS):
    return client.post("/v1/toolcalls", content=body, headers=headers)


def test_v1_endpoint_allows_valid_request(client):
    response = client.post("/v1/toolcalls", json=VALID_REQUEST)
    assert response.status_code == 200

    body = response.json()
    assert body["verdict"] == "ALLOW"
    assert body["rule_id"] == "BASE-001"
    assert body["request_id"].startswith("req_")


def test_legacy_endpoint_is_an_alias_of_v1(client):
    v1 = client.post("/v1/toolcalls", json=VALID_REQUEST).json()
    legacy = client.post("/api/tool-call", json=VALID_REQUEST).json()

    for field in ("verdict", "rule_id", "reason", "checks", "request_hash", "tool_manifest_hash"):
        assert v1[field] == legacy[field]


def test_request_id_is_server_generated_and_unique(client):
    ids = {client.post("/v1/toolcalls", json=VALID_REQUEST).json()["request_id"] for _ in range(5)}
    assert len(ids) == 5


def test_caller_cannot_supply_request_id(client):
    response = client.post("/v1/toolcalls", json={**VALID_REQUEST, "request_id": "req_attacker"})
    assert response.status_code == 422
    assert response.json()["request_id"] != "req_attacker"


def test_unknown_top_level_field_is_rejected(client):
    response = client.post("/v1/toolcalls", json={**VALID_REQUEST, "is_admin": True})
    assert response.status_code == 422

    body = response.json()
    assert body["verdict"] == "BLOCK"
    assert body["rule_id"] == "INGRESS-005"
    assert body["stage"] == "ingress"
    assert body["detail"][0]["loc"] == ["is_admin"]


def test_duplicate_top_level_key_is_rejected(client):
    # With "last key wins" this would authorize as support-bot-3.
    raw = (
        '{"agent_id": "random-agent", "agent_id": "support-bot-3", "tool": "send_email",'
        ' "parameters": {"to": "user@company.com", "subject": "s", "body": "b"}}'
    )
    response = post_raw(client, raw)
    assert response.status_code == 400
    assert response.json()["rule_id"] == "INGRESS-002"
    assert response.json()["verdict"] == "BLOCK"


def test_duplicate_nested_key_is_rejected(client):
    raw = (
        '{"agent_id": "support-bot-3", "tool": "send_email", "parameters":'
        ' {"to": "user@company.com", "to": "x@evil.com", "subject": "s", "body": "b"}}'
    )
    response = post_raw(client, raw)
    assert response.status_code == 400
    assert response.json()["rule_id"] == "INGRESS-002"


def test_oversized_request_is_rejected(client):
    request = {**VALID_REQUEST, "parameters": {**VALID_REQUEST["parameters"], "body": "A" * MAX_BODY_BYTES}}
    response = client.post("/v1/toolcalls", json=request)
    assert response.status_code == 413
    assert response.json()["rule_id"] == "INGRESS-003"


def test_oversized_chunked_request_without_content_length_is_rejected(client):
    def chunks():
        yield b'{"agent_id": "support-bot-3", "tool": "send_email", "parameters": {"body": "'
        for _ in range(MAX_BODY_BYTES // 1024 + 1):
            yield b"A" * 1024
        yield b'"}}'

    response = post_raw(client, chunks())
    assert response.status_code == 413
    assert response.json()["rule_id"] == "INGRESS-003"


def test_excessive_nesting_is_rejected(client):
    nested = "leaf"
    for _ in range(10):
        nested = {"n": nested}
    response = client.post("/v1/toolcalls", json={**VALID_REQUEST, "context": nested})
    assert response.status_code == 400
    assert response.json()["rule_id"] == "INGRESS-004"


def test_pathological_nesting_within_size_limit_is_rejected(client):
    raw = "[" * 20_000 + "]" * 20_000
    response = post_raw(client, raw)
    assert response.status_code == 400
    assert response.json()["rule_id"] == "INGRESS-004"


def test_invalid_json_is_rejected(client):
    response = post_raw(client, '{"agent_id": "support-bot-3",')
    assert response.status_code == 400
    assert response.json()["rule_id"] == "INGRESS-001"


def test_nan_and_infinity_are_rejected(client):
    for constant in ("NaN", "Infinity", "-Infinity"):
        raw = '{"agent_id": "a", "tool": "t", "parameters": {"x": %s}}' % constant
        response = post_raw(client, raw)
        assert response.status_code == 400
        assert response.json()["rule_id"] == "INGRESS-001"


def test_invalid_utf8_is_rejected(client):
    response = post_raw(client, b'{"agent_id": "\xff"}')
    assert response.status_code == 400
    assert response.json()["rule_id"] == "INGRESS-001"


def test_non_json_content_type_is_rejected(client):
    response = post_raw(client, json.dumps(VALID_REQUEST), headers={"content-type": "text/plain"})
    assert response.status_code == 415
    assert response.json()["rule_id"] == "INGRESS-006"


def test_non_object_body_is_rejected(client):
    response = post_raw(client, "[]")
    assert response.status_code == 422
    assert response.json()["rule_id"] == "INGRESS-005"


def test_types_are_not_coerced(client):
    response = client.post("/v1/toolcalls", json={**VALID_REQUEST, "agent_id": 123})
    assert response.status_code == 422


def test_identifier_with_whitespace_or_lookalikes_is_rejected(client):
    for agent_id in ("support-bot-3\n", " support-bot-3", "support‑bot-3"):
        response = client.post("/v1/toolcalls", json={**VALID_REQUEST, "agent_id": agent_id})
        assert response.status_code == 422


def test_caller_context_is_not_trusted_as_identity(client):
    request = {
        **VALID_REQUEST,
        "agent_id": "random-agent",
        "context": {"agent_id": "support-bot-3", "role": "admin", "authenticated": True},
    }
    body = client.post("/v1/toolcalls", json=request).json()
    assert body["verdict"] == "BLOCK"
    assert body["rule_id"] == "TOOL-003"
    assert body["agent_id"] == "random-agent"


def test_context_does_not_change_the_request_hash(client):
    plain = client.post("/v1/toolcalls", json=VALID_REQUEST).json()
    with_context = client.post("/v1/toolcalls", json={**VALID_REQUEST, "context": {"session_id": "s-1"}}).json()
    assert plain["request_hash"] == with_context["request_hash"]
