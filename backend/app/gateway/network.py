"""Network boundary for URL egress: strict URL parsing, IPv4/IPv6 deny
ranges, registrable-domain allowlisting and DNS resolution pinning.

The gateway never executes a tool, so it never opens the connection itself.
It resolves the destination once, checks every resolved address, and hands
the execution layer a *pinned* IP. The execution layer must connect to that
IP (sending the original hostname as SNI/Host) and must not resolve the name
again -- otherwise a DNS-rebinding server could answer the gateway with a
public address and the socket with 169.254.169.254.
"""

import concurrent.futures
import ipaddress
import re
import socket
from dataclasses import dataclass, field
from typing import Callable, Dict, FrozenSet, List, Optional, Tuple, Union
from urllib.parse import urlsplit

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]

# Denied ranges, grouped by the check that reports them. Order matters only
# for which check a blocked address is attributed to.
DENY_RANGES: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("LOOPBACK", ("127.0.0.0/8", "::1/128")),
    ("ZERO_ADDRESS", ("0.0.0.0/8", "::/128")),
    ("RFC1918_PRIVATE", ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")),
    ("LINK_LOCAL_METADATA", ("169.254.0.0/16", "fe80::/10")),
    ("UNIQUE_LOCAL_V6", ("fc00::/7",)),
    ("MULTICAST_BROADCAST", ("224.0.0.0/4", "255.255.255.255/32", "ff00::/8")),
)
_DENY_NETWORKS = tuple(
    (check, tuple(ipaddress.ip_network(cidr) for cidr in cidrs)) for check, cidrs in DENY_RANGES
)
IP_RANGE_CHECKS = tuple(check for check, _ in DENY_RANGES)

# Hostnames that name the local machine or a private zone, whatever they
# resolve to.
_LOCAL_HOST_SUFFIXES = (".localhost", ".local", ".internal", ".home.arpa")
_LOCAL_HOSTNAMES = frozenset({"localhost", "metadata", "metadata.google.internal"})

# A deliberately small public-suffix table. A host whose suffix is not listed
# has no known registrable domain and is refused (fail closed).
PUBLIC_SUFFIXES: FrozenSet[str] = frozenset(
    {"com", "net", "org", "io", "dev", "app", "ai", "co", "de", "fr", "in", "co.uk", "org.uk", "com.au", "co.in", "co.jp"}
)

MAX_URL_LENGTH = 2048
_HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
# Dotted-quad only: 4 decimal octets without leading zeros. Integer, octal
# and hex forms (2852039166, 0251.0376.0251.0376, 0xA9FEA9FE) are refused as
# ambiguous, because libraries disagree on how to read them.
_DOTTED_QUAD = re.compile(r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}")
_NUMERIC_LABEL = re.compile(r"\d+|0x[0-9a-f]*")

DNS_TIMEOUT_SECONDS = 2.0

Resolver = Callable[[str], List[str]]


def system_resolver(hostname: str) -> List[str]:
    """Resolve with the OS resolver, bounded by DNS_TIMEOUT_SECONDS."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(socket.getaddrinfo, hostname, 443, type=socket.SOCK_STREAM)
        infos = future.result(timeout=DNS_TIMEOUT_SECONDS)
    return list(dict.fromkeys(info[4][0] for info in infos))


# Replaceable for tests; production code always goes through resolve().
resolver: Resolver = system_resolver


def classify_ip(address: IPAddress) -> Optional[str]:
    """Return the deny-range check an address falls into, or None if public."""
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        # ::ffff:169.254.169.254 reaches the IPv4 address on dual-stack hosts.
        address = address.ipv4_mapped
    for check, networks in _DENY_NETWORKS:
        if any(address.version == net.version and address in net for net in networks):
            return check
    return None


def registrable_domain(hostname: str) -> Optional[str]:
    """eTLD+1 of a hostname using PUBLIC_SUFFIXES, or None if unknown."""
    labels = hostname.split(".")
    for size in (2, 1):
        if len(labels) > size and ".".join(labels[-size:]) in PUBLIC_SUFFIXES:
            return ".".join(labels[-size - 1 :])
    return None


@dataclass
class NetworkCheck:
    check: str
    status: str  # PASSED | BLOCKED | NOT_EVALUATED
    detail: Optional[str] = None


@dataclass
class UrlInspection:
    """Everything the gateway learned about one URL destination."""

    parameter: str
    requested_url: str
    requested_host: Optional[str] = None
    registrable_domain: Optional[str] = None
    resolved_ips: List[str] = field(default_factory=list)
    pinned_ip: Optional[str] = None
    checks: List[NetworkCheck] = field(default_factory=list)
    # (rule_id, reason) when the destination is refused.
    error: Optional[Tuple[str, str]] = None

    def as_dict(self) -> Dict[str, object]:
        return {
            "parameter": self.parameter,
            "requested_url": self.requested_url,
            "requested_host": self.requested_host,
            "registrable_domain": self.registrable_domain,
            "resolved_ips": list(self.resolved_ips),
            "pinned_ip": self.pinned_ip,
            "checks": [{"check": c.check, "status": c.status, "detail": c.detail} for c in self.checks],
        }


ALL_URL_CHECKS = ("URL_PARSE", "SCHEME_HTTPS", "LOCAL_HOSTNAME", *IP_RANGE_CHECKS, "DOMAIN_ALLOWLIST", "DNS_RESOLUTION_PINNED")


def inspect_url(parameter: str, value: object, allowlist: FrozenSet[str]) -> UrlInspection:
    """Validate one URL destination. Every check in ALL_URL_CHECKS is
    reported, as PASSED, BLOCKED, or NOT_EVALUATED when an earlier check
    already refused the destination."""
    inspection = UrlInspection(parameter=parameter, requested_url=value if isinstance(value, str) else repr(value)[:200])
    done: Dict[str, NetworkCheck] = {}

    def record(check: str, passed: bool, detail: Optional[str] = None) -> bool:
        done[check] = NetworkCheck(check, "PASSED" if passed else "BLOCKED", detail)
        return passed

    def finish(rule_id: Optional[str] = None, reason: Optional[str] = None) -> UrlInspection:
        inspection.checks = [done.get(c, NetworkCheck(c, "NOT_EVALUATED")) for c in ALL_URL_CHECKS]
        if rule_id is not None:
            inspection.error = (rule_id, reason or "Destination refused")
        return inspection

    parsed = _parse_url(value)
    if isinstance(parsed, str):
        record("URL_PARSE", False, parsed)
        return finish("DEST-002", f"Destination '{parameter}' is not a single valid URL ({parsed})")
    scheme, host, ip_literal = parsed
    inspection.requested_host = host
    record("URL_PARSE", True)

    if not record("SCHEME_HTTPS", scheme == "https", f"scheme {scheme}"):
        return finish("DEST-006", f"Destination '{parameter}' must use https (got {scheme})")

    if ip_literal is None:
        local = host in _LOCAL_HOSTNAMES or host.endswith(_LOCAL_HOST_SUFFIXES)
        if not record("LOCAL_HOSTNAME", not local, f"{host} names a local or private zone" if local else None):
            return finish("DEST-004", f"SSRF: '{host}' names a local or private network zone")
    else:
        record("LOCAL_HOSTNAME", True, "IP literal")

    if ip_literal is not None:
        blocked = _record_ip_ranges([ip_literal], record)
        if blocked:
            return finish("DEST-004", f"SSRF: {ip_literal} is in a denied network range ({blocked})")
        # A public IP literal has no registrable domain, so it can never be allow-listed.
        record("DOMAIN_ALLOWLIST", False, "IP literals are never allow-listed")
        return finish("DEST-001", f"Destination '{ip_literal}' is an IP literal; only allow-listed domains are permitted")

    domain = registrable_domain(host)
    inspection.registrable_domain = domain
    if not record("DOMAIN_ALLOWLIST", domain is not None and domain in allowlist, f"registrable domain {domain or 'unknown'}"):
        return finish("DEST-001", f"Destination domain '{domain or host}' is not allowed")

    try:
        addresses = [ipaddress.ip_address(a.split("%", 1)[0]) for a in resolver(host)]
    except Exception:
        addresses = []
    if not addresses:
        record("DNS_RESOLUTION_PINNED", False, "resolution failed")
        return finish("DEST-005", f"Destination host '{host}' could not be resolved (fail closed)")
    inspection.resolved_ips = [str(a) for a in addresses]

    # Every address must be safe: a name that resolves to both a public and
    # a private address is refused, since the socket could pick either.
    blocked = _record_ip_ranges(addresses, record)
    if blocked:
        record("DNS_RESOLUTION_PINNED", False, "resolved into a denied range")
        return finish("DEST-004", f"SSRF: '{host}' resolves into a denied network range ({blocked})")

    inspection.pinned_ip = str(addresses[0])
    record("DNS_RESOLUTION_PINNED", True, f"connect to {inspection.pinned_ip}; do not re-resolve")
    return finish()


def _record_ip_ranges(addresses: List[IPAddress], record: Callable[..., bool]) -> Optional[str]:
    hits: Dict[str, str] = {}
    for address in addresses:
        check = classify_ip(address)
        if check is not None:
            hits.setdefault(check, str(address))
    for check in IP_RANGE_CHECKS:
        record(check, check not in hits, f"{hits[check]} is in a denied range" if check in hits else None)
    return next((f"{c}: {hits[c]}" for c in IP_RANGE_CHECKS if c in hits), None)


def _parse_url(value: object) -> Union[str, Tuple[str, str, Optional[IPAddress]]]:
    """Return (scheme, host, ip_literal) or a short error string."""
    if not isinstance(value, str) or not value or len(value) > MAX_URL_LENGTH or not value.isascii():
        return "not a short ASCII string"
    if any(c.isspace() or c == "\\" for c in value):
        return "whitespace or backslash"
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError:
        return "unparseable"
    scheme = parts.scheme.lower()
    if not parts.netloc:
        return "no host"
    if "@" in parts.netloc:
        return "userinfo is not allowed"
    if port is not None and port != 443:
        return f"port {port} is not allowed"

    netloc_host = parts.netloc.rsplit(":", 1)[0] if not parts.netloc.startswith("[") else parts.netloc
    if netloc_host.startswith("["):
        literal = netloc_host[1:].split("]", 1)[0]
        try:
            address = ipaddress.IPv6Address(literal.split("%", 1)[0])
        except ValueError:
            return "invalid IPv6 literal"
        return scheme, str(address), address

    host = (parts.hostname or "").lower()
    if _DOTTED_QUAD.fullmatch(host):
        return scheme, host, ipaddress.IPv4Address(host)
    labels = host.split(".")
    if all(_NUMERIC_LABEL.fullmatch(label) for label in labels):
        # e.g. 2852039166, 0x7f.1, 0251.0376.0251.0376 -- ambiguous IP encodings.
        return "non-canonical numeric IP encoding"
    if len(host) > 253 or not all(_HOST_LABEL.fullmatch(label) for label in labels):
        return "invalid hostname"
    return scheme, host, None
