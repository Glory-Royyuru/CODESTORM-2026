import ipaddress

import pytest

from app.gateway import network
from app.gateway.network import classify_ip, inspect_url, registrable_domain
from app.gateway.pipeline import integrity_fields
from app.gateway.request_integrity import verify_request_integrity
from app.models.verdict import Verdict

ALLOWLIST = frozenset({"company.com", "github.com"})


@pytest.fixture
def dns(monkeypatch):
    """Static DNS for tests: hostname -> list of addresses."""
    table = {}
    monkeypatch.setattr(network, "resolver", lambda host: table.get(host, []))
    return table


def fetch(client, url):
    request = {"agent_id": "research-bot", "tool": "fetch_url", "parameters": {"url": url}}
    return client.post("/v1/toolcalls", json=request).json()


def check_status(body, name):
    return next(c["status"] for c in body["network"][0]["checks"] if c["check"] == name)


@pytest.mark.parametrize(
    "address, check",
    [
        ("127.0.0.1", "LOOPBACK"),
        ("127.255.0.9", "LOOPBACK"),
        ("::1", "LOOPBACK"),
        ("0.0.0.0", "ZERO_ADDRESS"),
        ("::", "ZERO_ADDRESS"),
        ("10.1.2.3", "RFC1918_PRIVATE"),
        ("172.16.0.1", "RFC1918_PRIVATE"),
        ("172.31.255.255", "RFC1918_PRIVATE"),
        ("192.168.1.1", "RFC1918_PRIVATE"),
        ("169.254.169.254", "LINK_LOCAL_METADATA"),
        ("169.254.10.10", "LINK_LOCAL_METADATA"),
        ("fe80::1", "LINK_LOCAL_METADATA"),
        ("fd00::1", "UNIQUE_LOCAL_V6"),
        ("fc00::1", "UNIQUE_LOCAL_V6"),
        ("224.0.0.1", "MULTICAST_BROADCAST"),
        ("239.255.255.250", "MULTICAST_BROADCAST"),
        ("255.255.255.255", "MULTICAST_BROADCAST"),
        ("ff02::1", "MULTICAST_BROADCAST"),
        ("::ffff:169.254.169.254", "LINK_LOCAL_METADATA"),
        ("::ffff:10.0.0.1", "RFC1918_PRIVATE"),
    ],
)
def test_denied_ranges(address, check):
    assert classify_ip(ipaddress.ip_address(address)) == check


@pytest.mark.parametrize("address", ["8.8.8.8", "172.32.0.1", "140.82.112.3", "2606:4700::1111"])
def test_public_addresses_pass(address):
    assert classify_ip(ipaddress.ip_address(address)) is None


@pytest.mark.parametrize(
    "host, domain",
    [("github.com", "github.com"), ("api.github.com", "github.com"), ("a.b.company.co.uk", "company.co.uk"), ("host.unknowntld", None), ("com", None)],
)
def test_registrable_domain(host, domain):
    assert registrable_domain(host) == domain


def test_allowed_url_is_resolved_pinned_and_signed(client, dns):
    dns["api.github.com"] = ["140.82.112.5", "140.82.112.6"]
    body = fetch(client, "https://api.github.com/zen")
    assert body["verdict"] == "ALLOW"
    inspection = body["network"][0]
    assert inspection["requested_host"] == "api.github.com"
    assert inspection["registrable_domain"] == "github.com"
    assert inspection["resolved_ips"] == ["140.82.112.5", "140.82.112.6"]
    assert inspection["pinned_ip"] == "140.82.112.5"
    assert all(c["status"] == "PASSED" for c in inspection["checks"])
    # The HMAC tag verifies against the verdict and binds the pinned IP.
    verdict = Verdict.model_validate(body)
    fields = integrity_fields(verdict)
    assert verify_request_integrity(fields, body["request_integrity"])
    assert not verify_request_integrity({**fields, "pinned_ips": ["169.254.169.254"]}, body["request_integrity"])


def test_cloud_metadata_ip_is_blocked_without_dns(client, dns):
    body = fetch(client, "https://169.254.169.254/latest/meta-data/iam/security-credentials/")
    assert body["verdict"] == "BLOCK"
    assert body["rule_id"] == "DEST-004"
    assert body["request_integrity"] is None
    assert check_status(body, "LINK_LOCAL_METADATA") == "BLOCKED"
    assert check_status(body, "RFC1918_PRIVATE") == "PASSED"
    assert check_status(body, "DOMAIN_ALLOWLIST") == "NOT_EVALUATED"
    assert check_status(body, "DNS_RESOLUTION_PINNED") == "NOT_EVALUATED"


@pytest.mark.parametrize(
    "url",
    ["https://127.0.0.1/", "https://[::1]/", "https://[fd12::1]/", "https://10.0.0.8/admin", "https://[::ffff:169.254.169.254]/"],
)
def test_private_ip_literals_are_ssrf(client, dns, url):
    assert fetch(client, url)["rule_id"] == "DEST-004"


@pytest.mark.parametrize("url", ["https://localhost/", "https://metadata.google.internal/", "https://printer.local/", "https://x.localhost/"])
def test_local_hostnames_are_ssrf(client, dns, url):
    assert fetch(client, url)["rule_id"] == "DEST-004"


def test_dns_rebinding_to_private_address_is_blocked(client, dns):
    # The allow-listed name resolves to a public and a metadata address.
    dns["docs.company.com"] = ["93.184.216.34", "169.254.169.254"]
    body = fetch(client, "https://docs.company.com/")
    assert body["rule_id"] == "DEST-004"
    assert check_status(body, "DNS_RESOLUTION_PINNED") == "BLOCKED"
    assert body["network"][0]["pinned_ip"] is None


def test_unresolvable_host_fails_closed(client, dns):
    body = fetch(client, "https://nx.company.com/")
    assert body["rule_id"] == "DEST-005"


@pytest.mark.parametrize("url", ["https://evil.example.net/", "https://github.com.evil.io/", "https://8.8.8.8/", "https://host.unknowntld/"])
def test_non_allowlisted_destinations(client, dns, url):
    assert fetch(client, url)["rule_id"] == "DEST-001"


def test_http_scheme_is_refused(client, dns):
    assert fetch(client, "http://api.github.com/")["rule_id"] == "DEST-006"


@pytest.mark.parametrize(
    "url",
    [
        "https://2852039166/",  # 169.254.169.254 as an integer
        "https://0xA9FEA9FE/",
        "https://0251.0376.0251.0376/",
        "https://127.1/",
        "https://user@api.github.com/",
        "https://api.github.com:8443/",
        "https://api.github.com\\@evil.io/",
        "api.github.com/zen",
        "https://",
        "https://gіthub.com/",  # Cyrillic i
    ],
)
def test_ambiguous_urls_are_malformed(client, dns, url):
    assert fetch(client, url)["rule_id"] == "DEST-002"


def test_inspection_reports_every_check():
    result = inspect_url("url", "https://10.0.0.1/", ALLOWLIST)
    assert [c.check for c in result.checks] == list(network.ALL_URL_CHECKS)


def test_system_resolver_timeout_is_enforced(monkeypatch):
    """A hung OS lookup is abandoned after DNS_TIMEOUT_SECONDS, not awaited."""
    import threading
    import time

    release = threading.Event()
    monkeypatch.setattr(network, "DNS_TIMEOUT_SECONDS", 0.2)
    monkeypatch.setattr(network.socket, "getaddrinfo", lambda *a, **k: release.wait(10) and [])
    started = time.perf_counter()
    try:
        with pytest.raises(TimeoutError):
            network.system_resolver("hung.example")
        assert time.perf_counter() - started < 2
    finally:
        release.set()
