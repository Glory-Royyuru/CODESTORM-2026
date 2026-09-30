from app.audit.logger import get_audit_log

VALID_REQUEST = {
    "agent_id": "support-bot-3",
    "tool": "send_email",
    "parameters": {"to": "user@company.com", "subject": "Support", "body": "Hello"},
}


def audit_event_for(request_id):
    matches = [e for e in get_audit_log() if e["request_id"] == request_id]
    assert len(matches) == 1
    return matches[0]


def test_allowed_request_is_fully_audited(client):
    body = client.post("/v1/toolcalls", json=VALID_REQUEST).json()
    event = audit_event_for(body["request_id"])

    assert event["verdict"] == "ALLOW"
    assert event["agent_id"] == "support-bot-3"
    assert event["tool"] == "send_email"
    assert event["rule_id"] == "BASE-001"
    assert event["severity"] == "LOW"
    assert event["checks"] == body["checks"]
    assert event["policy_version"] == body["policy_version"]
    assert event["tool_manifest_hash"] == body["tool_manifest_hash"]
    assert event["request_hash"] == body["request_hash"]
    assert event["authenticated"] is False
    assert event["auth_method"] == "self_asserted"
    assert "timestamp" in event


def test_blocked_request_is_audited(client):
    request = {**VALID_REQUEST, "parameters": {**VALID_REQUEST["parameters"], "to": "a@evil.com"}}
    body = client.post("/v1/toolcalls", json=request).json()
    event = audit_event_for(body["request_id"])

    assert event["verdict"] == "BLOCK"
    assert event["rule_id"] == "DEST-001"
    assert event["reason"] == "Destination domain 'evil.com' is not allowed"
    assert event["severity"] == "HIGH"
    assert event["checks"][-1] == {"check": "DESTINATION_VALIDATION", "status": "FAILED"}


def test_short_circuited_block_records_unevaluated_checks(client):
    request = {"agent_id": "admin-bot", "tool": "delete_database", "parameters": {"database_name": "prod"}}
    body = client.post("/v1/toolcalls", json=request).json()
    event = audit_event_for(body["request_id"])

    assert event["rule_id"] == "TOOL-002"
    assert event["checks_not_evaluated"] == ["AGENT_PERMISSION", "PARAMETER_VALIDATION", "DESTINATION_VALIDATION"]


def test_malformed_request_is_audited(client):
    response = client.post("/v1/toolcalls", json={"tool": "send_email", "parameters": {}})
    assert response.status_code == 422
    event = audit_event_for(response.json()["request_id"])

    assert event["verdict"] == "BLOCK"
    assert event["rule_id"] == "INGRESS-005"
    assert event["stage"] == "ingress"
    assert event["agent_id"] is None
    assert event["tool"] == "send_email"
    assert event["auth_method"] is None


def test_rejected_request_records_claimed_identity_when_well_formed(client):
    response = client.post("/v1/toolcalls", json={**VALID_REQUEST, "unexpected": 1})
    event = audit_event_for(response.json()["request_id"])
    assert event["agent_id"] == "support-bot-3"


def test_duplicate_key_request_is_audited(client):
    raw = '{"agent_id": "a", "agent_id": "b", "tool": "t", "parameters": {}}'
    response = client.post("/v1/toolcalls", content=raw, headers={"content-type": "application/json"})
    event = audit_event_for(response.json()["request_id"])
    assert event["rule_id"] == "INGRESS-002"


def test_internal_error_fails_closed_and_is_audited(client, monkeypatch):
    def broken_pipeline(*args, **kwargs):
        raise RuntimeError("validator crashed")

    monkeypatch.setattr("app.main.process_tool_call", broken_pipeline)
    response = client.post("/v1/toolcalls", json=VALID_REQUEST)
    assert response.status_code == 500

    body = response.json()
    assert body["verdict"] == "BLOCK"
    assert body["rule_id"] == "GATEWAY-001"
    assert audit_event_for(body["request_id"])["verdict"] == "BLOCK"
