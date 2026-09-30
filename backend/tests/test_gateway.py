from fastapi.testclient import TestClient

from app.audit.logger import get_audit_log
from app.main import app

client = TestClient(app)

VALID_REQUEST = {
    "agent_id": "support-bot-3",
    "tool": "send_email",
    "parameters": {
        "to": "user@company.com",
        "subject": "Support",
        "body": "Hello",
    },
}


def test_valid_request_returns_allow():
    response = client.post("/api/tool-call", json=VALID_REQUEST)
    assert response.status_code == 200

    body = response.json()
    assert body["verdict"] == "ALLOW"
    assert body["agent_id"] == "support-bot-3"
    assert body["tool"] == "send_email"


def test_missing_tool_is_rejected():
    request = {k: v for k, v in VALID_REQUEST.items() if k != "tool"}
    response = client.post("/api/tool-call", json=request)
    assert response.status_code == 422


def test_missing_agent_id_is_rejected():
    request = {k: v for k, v in VALID_REQUEST.items() if k != "agent_id"}
    response = client.post("/api/tool-call", json=request)
    assert response.status_code == 422


def test_empty_tool_is_rejected():
    request = {**VALID_REQUEST, "tool": ""}
    response = client.post("/api/tool-call", json=request)
    assert response.status_code == 422


def test_audit_event_created_for_successful_request():
    before = len(get_audit_log())
    client.post("/api/tool-call", json=VALID_REQUEST)
    after = get_audit_log()

    assert len(after) == before + 1
    latest = after[-1]
    assert latest["agent_id"] == "support-bot-3"
    assert latest["tool"] == "send_email"
    assert latest["verdict"] == "ALLOW"
    assert "timestamp" in latest


def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


# --- Phase 2: tool registry + permission enforcement ---


def test_registered_and_authorized_tool_returns_allow():
    response = client.post("/api/tool-call", json=VALID_REQUEST)
    assert response.status_code == 200

    body = response.json()
    assert body["verdict"] == "ALLOW"
    assert body["rule_id"] == "BASE-001"


def test_unknown_tool_is_blocked():
    request = {**VALID_REQUEST, "tool": "wipe_disk"}
    response = client.post("/api/tool-call", json=request)
    assert response.status_code == 200

    body = response.json()
    assert body["verdict"] == "BLOCK"
    assert body["rule_id"] == "TOOL-001"
    assert body["reason"] == "Tool is not registered"


def test_disabled_tool_is_blocked():
    request = {**VALID_REQUEST, "agent_id": "admin-bot", "tool": "delete_database"}
    response = client.post("/api/tool-call", json=request)
    assert response.status_code == 200

    body = response.json()
    assert body["verdict"] == "BLOCK"
    assert body["rule_id"] == "TOOL-002"
    assert body["reason"] == "Tool is disabled"


def test_unauthorized_agent_is_blocked():
    request = {**VALID_REQUEST, "agent_id": "random-agent"}
    response = client.post("/api/tool-call", json=request)
    assert response.status_code == 200

    body = response.json()
    assert body["verdict"] == "BLOCK"
    assert body["rule_id"] == "TOOL-003"
    assert body["reason"] == "Agent is not authorized to use this tool"


# --- Phase 3: parameter/schema validation ---


def test_valid_parameters_returns_allow():
    response = client.post("/api/tool-call", json=VALID_REQUEST)
    assert response.status_code == 200

    body = response.json()
    assert body["verdict"] == "ALLOW"
    assert body["rule_id"] == "BASE-001"

    check_names = [c["check"] for c in body["checks"]]
    assert check_names == [
        "REQUEST_STRUCTURE",
        "TOOL_REGISTRY",
        "TOOL_ENABLED",
        "AGENT_PERMISSION",
        "PARAMETER_VALIDATION",
        "DESTINATION_VALIDATION",
    ]
    assert all(c["status"] == "PASSED" for c in body["checks"])


def test_missing_required_parameter_is_blocked():
    request = {
        **VALID_REQUEST,
        "parameters": {"to": "user@company.com", "subject": "Support"},
    }
    response = client.post("/api/tool-call", json=request)
    assert response.status_code == 200

    body = response.json()
    assert body["verdict"] == "BLOCK"
    assert body["rule_id"] == "PARAM-001"
    assert body["reason"] == "Required parameter 'body' is missing"
    assert body["checks"][-1] == {"check": "PARAMETER_VALIDATION", "status": "FAILED"}


def test_wrong_parameter_type_is_blocked():
    request = {
        **VALID_REQUEST,
        "parameters": {"to": "user@company.com", "subject": "Support", "body": 12345},
    }
    response = client.post("/api/tool-call", json=request)
    assert response.status_code == 200

    body = response.json()
    assert body["verdict"] == "BLOCK"
    assert body["rule_id"] == "PARAM-002"
    assert body["reason"] == "Parameter 'body' must be a string"


def test_unexpected_parameter_is_blocked():
    request = {
        **VALID_REQUEST,
        "parameters": {
            "to": "user@company.com",
            "subject": "Support",
            "body": "Hello",
            "admin_password": "secret",
        },
    }
    response = client.post("/api/tool-call", json=request)
    assert response.status_code == 200

    body = response.json()
    assert body["verdict"] == "BLOCK"
    assert body["rule_id"] == "PARAM-003"
    assert body["reason"] == "Unexpected parameter 'admin_password'"


def test_empty_required_parameter_is_blocked():
    request = {
        **VALID_REQUEST,
        "parameters": {"to": "user@company.com", "subject": "Support", "body": "   "},
    }
    response = client.post("/api/tool-call", json=request)
    assert response.status_code == 200

    body = response.json()
    assert body["verdict"] == "BLOCK"
    assert body["rule_id"] == "PARAM-004"
    assert body["reason"] == "Required parameter 'body' cannot be empty"


# --- Phase 4: destination/egress validation ---


def test_allowed_email_destination_returns_allow():
    request = {
        **VALID_REQUEST,
        "parameters": {"to": "user@trusted-partner.com", "subject": "Support", "body": "Hello"},
    }
    response = client.post("/api/tool-call", json=request)
    assert response.status_code == 200

    body = response.json()
    assert body["verdict"] == "ALLOW"
    assert body["rule_id"] == "BASE-001"
    assert body["checks"][-1] == {"check": "DESTINATION_VALIDATION", "status": "PASSED"}


def test_unauthorized_email_destination_is_blocked():
    request = {
        **VALID_REQUEST,
        "parameters": {"to": "user@evil-external.com", "subject": "Support", "body": "Hello"},
    }
    response = client.post("/api/tool-call", json=request)
    assert response.status_code == 200

    body = response.json()
    assert body["verdict"] == "BLOCK"
    assert body["rule_id"] == "DEST-001"
    assert body["reason"] == "Destination domain 'evil-external.com' is not allowed"
    assert body["checks"][-1] == {"check": "DESTINATION_VALIDATION", "status": "FAILED"}

    # earlier stages must have passed before destination validation ran
    earlier_checks = body["checks"][:-1]
    assert all(c["status"] == "PASSED" for c in earlier_checks)


def test_non_email_tool_bypasses_destination_validation():
    request = {
        "agent_id": "support-bot-3",
        "tool": "search_customer",
        "parameters": {"customer_id": "12345"},
    }
    response = client.post("/api/tool-call", json=request)
    assert response.status_code == 200

    body = response.json()
    assert body["verdict"] == "ALLOW"
    assert body["checks"][-1] == {"check": "DESTINATION_VALIDATION", "status": "PASSED"}
