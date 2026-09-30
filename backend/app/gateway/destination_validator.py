import re
from typing import Any, Callable, Dict, FrozenSet, Optional, Tuple

from app.gateway.registry import RegisteredTool

# Allowed destinations per egress channel. Matching is exact on the
# lowercased domain: subdomains are not implicitly allowed.
EGRESS_ALLOWLISTS: Dict[str, FrozenSet[str]] = {
    "email": frozenset({"company.com", "trusted-partner.com"}),
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


def validate_destination(tool: RegisteredTool, parameters: Dict[str, Any]) -> Optional[Tuple[str, str]]:
    """Check every destination the tool's manifest declares.

    Returns None if the tool declares no egress or every destination is
    allowed, or a (rule_id, reason) tuple if it is blocked. A declared
    channel with no parser or allowlist is blocked (fail closed).
    """
    egress = tool.security.egress
    if egress is None:
        return None

    parse = _DESTINATION_PARSERS.get(egress.channel)
    allowlist = EGRESS_ALLOWLISTS.get(egress.channel)
    if parse is None or allowlist is None:
        return "DEST-003", f"Egress channel '{egress.channel}' has no destination validator"

    for name in egress.destination_parameters:
        domain = parse(parameters.get(name))
        if domain is None:
            return "DEST-002", f"Destination '{name}' is not a single valid address"
        if domain not in allowlist:
            return "DEST-001", f"Destination domain '{domain}' is not allowed"

    return None
