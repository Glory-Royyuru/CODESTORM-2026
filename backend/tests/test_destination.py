import pytest

from app.gateway.destination_validator import parse_email_domain


def send_email(client, to):
    request = {
        "agent_id": "support-bot-3",
        "tool": "send_email",
        "parameters": {"to": to, "subject": "Support", "body": "Hello"},
    }
    return client.post("/v1/toolcalls", json=request).json()


@pytest.mark.parametrize(
    "to",
    ["user@company.com", "USER@Company.COM", "first.last+tag@trusted-partner.com"],
)
def test_allowed_destinations(client, to):
    body = send_email(client, to)
    assert body["verdict"] == "ALLOW"
    assert body["checks"][-1] == {"check": "DESTINATION_VALIDATION", "status": "PASSED"}


@pytest.mark.parametrize("to", ["user@evil.com", "user@sub.company.com", "user@company.co", "user@xn--cmpany-9ta.com"])
def test_disallowed_domain_is_blocked(client, to):
    body = send_email(client, to)
    assert body["verdict"] == "BLOCK"
    assert body["rule_id"] == "DEST-001"
    assert body["severity"] == "HIGH"
    assert body["checks"][-1] == {"check": "DESTINATION_VALIDATION", "status": "FAILED"}


@pytest.mark.parametrize(
    "to",
    [
        # previously bypassed DEST-001
        "a@evil.com, b@company.com",
        "a@evil.com,b@company.com",
        "a@evil.com;b@company.com",
        "a@evil.com@company.com",
        # other ambiguous or malformed forms
        "a@evil.com，b@company.com",  # full-width comma, becomes ',' under NFKC
        "Evil <a@evil.com>",
        "<user@company.com>",
        '"a@evil.com"@company.com',
        "a(comment)@company.com",
        "user @company.com",
        "user@company.com ",
        "user",
        "user@",
        "@company.com",
        "user@company",
        "user@company..com",
        "user@-company.com",
        "user@company.com.",
        "user.@company.com",
        "a..b@company.com",
        "user@[127.0.0.1]",
        "usér@company.com",
        "user@cоmpany.com",  # Cyrillic 'o'
        "a" * 65 + "@company.com",
    ],
)
def test_ambiguous_or_malformed_recipient_is_blocked(client, to):
    body = send_email(client, to)
    assert body["verdict"] == "BLOCK"
    assert body["rule_id"] == "DEST-002"
    assert body["severity"] == "HIGH"


def test_fullwidth_address_is_checked_in_canonical_form(client):
    # NFKC turns this into user@company.com, and the canonical value is what
    # is checked, hashed, and must be used downstream.
    body = send_email(client, "ｕｓｅｒ＠ｃｏｍｐａｎｙ．ｃｏｍ")
    assert body["verdict"] == "ALLOW"
    assert body["request_hash"] == send_email(client, "user@company.com")["request_hash"]


@pytest.mark.parametrize(
    "address, domain",
    [
        ("user@company.com", "company.com"),
        ("User@COMPANY.com", "company.com"),
        ("a@evil.com@company.com", None),
        ("a@evil.com, b@company.com", None),
        ("", None),
        (None, None),
        (42, None),
        ("a@" + "b" * 64 + ".com", None),
    ],
)
def test_parse_email_domain(address, domain):
    assert parse_email_domain(address) == domain


def test_egress_validation_is_driven_by_manifest_not_tool_name(client, temp_tool):
    temp_tool(
        name="notify_partner",
        parameters={"recipient": {"type": "string"}, "message": {"type": "string"}},
        security={"side_effect": "write", "egress": {"channel": "email", "destination_parameters": ["recipient"]}},
    )
    request = {"agent_id": "test-agent", "tool": "notify_partner", "parameters": {"message": "hi"}}

    blocked = client.post(
        "/v1/toolcalls", json={**request, "parameters": {**request["parameters"], "recipient": "x@evil.com"}}
    ).json()
    allowed = client.post(
        "/v1/toolcalls", json={**request, "parameters": {**request["parameters"], "recipient": "x@company.com"}}
    ).json()
    assert blocked["rule_id"] == "DEST-001"
    assert allowed["verdict"] == "ALLOW"


def test_unsupported_egress_channel_fails_closed(client, temp_tool):
    temp_tool(
        name="http_post",
        parameters={"url": {"type": "string"}},
        security={"side_effect": "write", "egress": {"channel": "http", "destination_parameters": ["url"]}},
    )
    body = client.post(
        "/v1/toolcalls",
        json={"agent_id": "test-agent", "tool": "http_post", "parameters": {"url": "https://company.com"}},
    ).json()
    assert body["verdict"] == "BLOCK"
    assert body["rule_id"] == "DEST-003"


def test_tool_without_egress_passes_destination_check(client):
    body = client.post(
        "/v1/toolcalls", json={"agent_id": "support-bot-3", "tool": "search_customer", "parameters": {"customer_id": "1"}}
    ).json()
    assert body["verdict"] == "ALLOW"
    assert body["checks"][-1] == {"check": "DESTINATION_VALIDATION", "status": "PASSED"}
