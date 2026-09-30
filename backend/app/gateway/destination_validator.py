from typing import Any, Dict, Optional, Tuple

# Domains a send_email recipient is allowed to belong to.
# Only send_email has a destination concept in this phase; other tools
# are not checked here.
ALLOWED_EMAIL_DOMAINS = {"company.com", "trusted-partner.com"}


def validate_destination(tool_name: str, parameters: Dict[str, Any]) -> Optional[Tuple[str, str]]:
    """Check whether the tool call's destination is allowed.

    Returns None if the destination is allowed or the tool has no
    destination concept, or a (rule_id, reason) tuple if it is blocked.
    """
    if tool_name != "send_email":
        return None

    recipient = parameters.get("to", "")
    domain = recipient.rsplit("@", 1)[-1].lower() if "@" in recipient else ""

    if domain not in ALLOWED_EMAIL_DOMAINS:
        return "DEST-001", f"Destination domain '{domain}' is not allowed"

    return None
