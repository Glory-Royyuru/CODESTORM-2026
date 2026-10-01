import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, FrozenSet, List, Optional, Tuple

from app.gateway.network import UrlInspection, inspect_url
from app.gateway.registry import RegisteredTool

# Allowed destinations per egress channel. Matching is exact on the
# lowercased domain: subdomains are not implicitly allowed.
EGRESS_ALLOWLISTS: Dict[str, FrozenSet[str]] = {
    "email": frozenset({"company.com", "trusted-partner.com"}),
    # URL egress is matched on the registrable domain (eTLD+1), so any
    # subdomain of an allow-listed domain is allowed.
    "https": frozenset({"company.com", "trusted-partner.com", "github.com"}),
}

MAX_EMAIL_LENGTH = 254
MAX_LOCAL_PART_LENGTH = 64
MAX_DOMAIN_LENGTH = 253

_LOCAL_PART = re.compile(r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*")
_DOMAIN_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


def parse_email_domain(address: Any) -> Optional[str]:
    """Return the lowercased domain of a single plain email address, or None
    if the value is not exactly one unambiguous address.

    Deliberately far stricter than RFC 5322: no display names, comments,
    quoted local parts, IP literals, address lists, whitespace, or non-ASCII.
    Anything the parser is unsure about is rejected rather than interpreted,
    because a mail library may interpret it differently -- e.g.
    'a@evil.com@company.com' or 'a@evil.com, b@company.com'.
    """
    if not isinstance(address, str) or len(address) > MAX_EMAIL_LENGTH or not address.isascii():
        return None
    if address.count("@") != 1:
        return None

    local, domain = address.split("@")
    if len(local) > MAX_LOCAL_PART_LENGTH or not _LOCAL_PART.fullmatch(local):
        return None

    domain = domain.lower()
    labels = domain.split(".")
    if len(domain) > MAX_DOMAIN_LENGTH or len(labels) < 2:
        return None
    if not all(_DOMAIN_LABEL.fullmatch(label) for label in labels):
        return None
    return domain


# Destination parsers per egress channel: value -> domain, or None if malformed.
_DESTINATION_PARSERS: Dict[str, Callable[[Any], Optional[str]]] = {
    "email": parse_email_domain,
}


@dataclass
class DestinationResult:
    # (rule_id, reason) if a destination is refused, else None.
    error: Optional[Tuple[str, str]] = None
    # One inspection per URL destination (the "https" channel only).
    network: List[UrlInspection] = field(default_factory=list)


def validate_destination(tool: RegisteredTool, parameters: Dict[str, Any]) -> DestinationResult:
    """Check every destination the tool's manifest declares.

    The result has no error if the tool declares no egress or every
    destination is allowed. A declared channel with no parser or allowlist
    is blocked (fail closed). URL destinations additionally go through the
    network boundary (deny ranges, allowlist, DNS pinning) and report what
    it found in `network`.
    """
    egress = tool.security.egress
    if egress is None:
        return DestinationResult()

    allowlist = EGRESS_ALLOWLISTS.get(egress.channel)
    if egress.channel == "https" and allowlist is not None:
        result = DestinationResult()
        for name in egress.destination_parameters:
            inspection = inspect_url(name, parameters.get(name), allowlist)
            result.network.append(inspection)
            if inspection.error is not None:
                result.error = inspection.error
                break
        return result

    parse = _DESTINATION_PARSERS.get(egress.channel)
    if parse is None or allowlist is None:
        return DestinationResult(("DEST-003", f"Egress channel '{egress.channel}' has no destination validator"))

    for name in egress.destination_parameters:
        domain = parse(parameters.get(name))
        if domain is None:
            return DestinationResult(("DEST-002", f"Destination '{name}' is not a single valid address"))
        if domain not in allowlist:
            return DestinationResult(("DEST-001", f"Destination domain '{domain}' is not allowed"))

    return DestinationResult()
