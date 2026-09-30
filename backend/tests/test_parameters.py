import pytest

from app.gateway.canonicalizer import MAX_CANONICAL_STRING_LENGTH, CanonicalizationError, canonicalize
from app.gateway.identity import resolve_principal
from app.gateway.parameter_validator import validate_parameters
from app.gateway.registry import RegisteredTool
from app.models.tool_call import ToolCall

EMAIL = {"to": "user@company.com", "subject": "Support", "body": "Hello"}


def call_email(client, **parameters):
    request = {"agent_id": "support-bot-3", "tool": "send_email", "parameters": {**EMAIL, **parameters}}
    return client.post("/v1/toolcalls", json=request).json()


def call_email_with(client, parameters):
    request = {"agent_id": "support-bot-3", "tool": "send_email", "parameters": parameters}
    return client.post("/v1/toolcalls", json=request).json()


# --- schema checks (PARAM-001..005) ---


def test_valid_parameters_are_allowed(client):
    assert call_email(client)["verdict"] == "ALLOW"


@pytest.mark.parametrize(
    "parameters, rule_id, reason",
    [
        ({"to": "user@company.com", "subject": "s"}, "PARAM-001", "Required parameter 'body' is missing"),
        ({**EMAIL, "body": 12345}, "PARAM-002", "Parameter 'body' must be a string"),
        ({**EMAIL, "body": None}, "PARAM-002", "Parameter 'body' must be a string"),
        ({**EMAIL, "admin_password": "x"}, "PARAM-003", "Unexpected parameter 'admin_password'"),
        ({**EMAIL, "body": "   "}, "PARAM-004", "Required parameter 'body' cannot be empty"),
        ({**EMAIL, "subject": "Hi\r\nBcc: x@evil.com"}, "PARAM-005", "Parameter 'subject' must not contain line breaks"),
        ({**EMAIL, "to": "user@company.com\nx@evil.com"}, "PARAM-005", "Parameter 'to' must not contain line breaks"),
    ],
)
def test_parameter_rules(client, parameters, rule_id, reason):
    body = call_email_with(client, parameters)
    assert body["verdict"] == "BLOCK"
    assert body["rule_id"] == rule_id
    assert body["reason"] == reason
    assert body["checks"][-1] == {"check": "PARAMETER_VALIDATION", "status": "FAILED"}


def test_multiline_body_is_allowed(client):
    assert call_email(client, body="Line one\n\tLine two\r\n")["verdict"] == "ALLOW"


def test_booleans_are_not_numbers():
    tool = RegisteredTool.model_validate(
        {
            "name": "t", "version": "1", "server_id": "s", "description": "d", "enabled": True,
            "allowed_agents": ["*"], "security": {"side_effect": "none", "egress": None},
            "parameters": {"count": {"type": "integer"}, "ratio": {"type": "number"}, "flag": {"type": "boolean"}},
        }
    )
    assert validate_parameters(tool, {"count": 1, "ratio": 0.5, "flag": False}) is None
    assert validate_parameters(tool, {"count": True, "ratio": 0.5, "flag": False})[0] == "PARAM-002"
    assert validate_parameters(tool, {"count": 1, "ratio": True, "flag": False})[0] == "PARAM-002"
    assert validate_parameters(tool, {"count": 1, "ratio": 0.5, "flag": 0})[0] == "PARAM-002"


def test_optional_parameter_may_be_absent():
    tool = RegisteredTool.model_validate(
        {
            "name": "t", "version": "1", "server_id": "s", "description": "d", "enabled": True,
            "allowed_agents": ["*"], "security": {"side_effect": "none", "egress": None},
            "parameters": {"q": {"type": "string"}, "limit": {"type": "integer", "required": False}},
        }
    )
    assert validate_parameters(tool, {"q": "x"}) is None


# --- canonicalization ---


def test_unicode_whitespace_only_value_is_empty_after_normalization(client):
    body = call_email(client, body="　 ")
    assert body["rule_id"] == "PARAM-004"


def test_strings_are_nfkc_normalized_before_checks():
    call = ToolCall(agent_id="a", tool="t", parameters={"q": "ｆｕｌｌ ﬁ", "n": {"k": "①"}})
    envelope = canonicalize(call, resolve_principal("a"), "req_1")
    assert envelope.parameters == {"q": "full fi", "n": {"k": "1"}}


def test_equivalent_requests_have_the_same_request_hash(client):
    fullwidth = call_email(client, subject="Ｓupport")
    plain = call_email(client, subject="Support")
    assert fullwidth["request_hash"] == plain["request_hash"]
    assert fullwidth["request_id"] != plain["request_id"]


def test_different_requests_have_different_request_hashes(client):
    assert call_email(client, body="a")["request_hash"] != call_email(client, body="b")["request_hash"]


@pytest.mark.parametrize(
    "value",
    [
        "user@company.com‮",  # right-to-left override (Trojan Source)
        "Hel​lo",  # zero-width space
        "Hello\u0000",  # NUL
        "Hello\u001b[31m",  # ANSI escape
        "Hello\u0085",  # C1 control (NEL)
    ],
)
def test_control_and_invisible_characters_are_rejected(client, value):
    body = call_email(client, body=value)
    assert body["verdict"] == "BLOCK"
    assert body["rule_id"] == "CANON-001"
    assert body["stage"] == "canonicalize"
    assert body["checks"] == [{"check": "REQUEST_STRUCTURE", "status": "FAILED"}]
    assert body["request_hash"] is None


def test_control_character_in_parameter_name_is_rejected(client):
    body = call_email_with(client, {**EMAIL, "to\u0000": "x"})
    assert body["rule_id"] == "CANON-001"


def test_nested_values_are_canonicalized(client, temp_tool):
    temp_tool(name="nested_tool", parameters={"q": {"type": "string"}})
    request = {"agent_id": "test-agent", "tool": "nested_tool", "parameters": {"q": "x", "extra": {"k": ["‮"]}}}
    body = client.post("/v1/toolcalls", json=request).json()
    assert body["rule_id"] == "CANON-001"


def test_lone_surrogate_is_rejected(client):
    raw = (
        '{"agent_id": "support-bot-3", "tool": "send_email",'
        ' "parameters": {"to": "user@company.com", "subject": "s", "body": "\\ud800"}}'
    )
    response = client.post("/v1/toolcalls", content=raw, headers={"content-type": "application/json"})
    assert response.json()["rule_id"] == "CANON-002"


def test_normalization_expansion_is_bounded():
    # U+FDFA expands to 18 characters under NFKC.
    expanding = "ﷺ" * (MAX_CANONICAL_STRING_LENGTH // 18 + 1)
    call = ToolCall(agent_id="a", tool="t", parameters={"body": expanding})
    with pytest.raises(CanonicalizationError) as error:
        canonicalize(call, resolve_principal("a"), "req_1")
    assert error.value.rule_id == "CANON-003"
