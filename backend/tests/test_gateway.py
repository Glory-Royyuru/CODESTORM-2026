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
