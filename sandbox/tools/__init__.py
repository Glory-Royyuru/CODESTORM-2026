"""The tools the sandbox can run. The set must match the gateway registry's
enabled tools (backend/app/gateway/registry.py); a backend test checks this.

Each tool re-checks the argument schema (defence in depth: the gateway has
already validated and canonicalised them) and runs against read-only,
synthetic fixture data baked into the image. No tool has network access
unless the container was given one, which the gateway never does.
"""

import json
import socket
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlsplit

DATA_DIR = "/opt/satg/data"


class ToolError(Exception):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


def _load(name: str) -> Any:
    with open(f"{DATA_DIR}/{name}", encoding="utf-8") as handle:
        return json.load(handle)


@dataclass(frozen=True)
class Tool:
    # parameter name -> python type (bool is rejected where int is expected)
    schema: Dict[str, type]
    run_fn: Callable[[Dict[str, Any], List[str]], Dict[str, Any]]

    def check_arguments(self, arguments: Any) -> Optional[str]:
        if not isinstance(arguments, dict):
            return "arguments must be an object"
        missing = sorted(set(self.schema) - set(arguments))
        extra = sorted(set(arguments) - set(self.schema))
        if missing or extra:
            return f"missing={missing} unexpected={extra}"
        for name, expected in self.schema.items():
            value = arguments[name]
            if isinstance(value, bool) or not isinstance(value, expected):
                return f"{name} must be {expected.__name__}"
            if isinstance(value, str) and not value.strip():
                return f"{name} is empty"
        return None

    def run(self, arguments: Dict[str, Any], pinned_ips: List[str]) -> Dict[str, Any]:
        return self.run_fn(arguments, pinned_ips)


def get_weather(args, _pins):
    weather = _load("weather.json")
    record = weather.get(args["city"].strip().lower())
    if not isinstance(record, dict):
        raise ToolError("not_found", "no fixture weather for this city")
    return {"city": args["city"], **record, "source": "synthetic fixture"}


def search_customer(args, _pins):
    customers = _load("customers.json")
    record = customers.get(args["customer_id"])
    if not isinstance(record, dict):
        raise ToolError("not_found", "no such customer")
    return {"customer_id": args["customer_id"], **record, "source": "synthetic fixture"}


def send_email(args, _pins):
    # The container has no network, so nothing can be delivered. The tool
    # renders the message it *would* send and says so.
    return {
        "delivered": False,
        "reason": "sandbox has no network egress; message rendered, not sent",
        "message": {"to": args["to"], "subject": args["subject"], "body_chars": len(args["body"])},
    }


def fetch_url(args, pins):
    host = urlsplit(args["url"]).hostname
    if not pins:
        raise ToolError("no_pinned_ip", "gateway supplied no pinned IP; refusing to resolve DNS")
    # Connect only to the gateway-pinned IP, never re-resolve the hostname.
    try:
        with socket.create_connection((pins[0], 443), timeout=2):
            pass
    except OSError as error:
        raise ToolError("network_unavailable", f"connect to pinned {pins[0]} for {host} failed: {error.strerror or error}")
    raise ToolError("not_implemented", "HTTPS fetch over an allowed egress path is not implemented")


def settle_invoice(args, _pins):
    if args["currency"] not in {"EUR", "USD", "GBP"}:
        raise ToolError("invalid_currency", "unsupported currency")
    if args["amount_minor"] <= 0:
        raise ToolError("invalid_amount", "amount must be positive")
    return {
        "invoice_id": args["invoice_id"],
        "recorded": True,
        "amount": f"{args['amount_minor'] // 100}.{args['amount_minor'] % 100:02d} {args['currency']}",
        "ledger": "sandbox-local; discarded with the container (no payment rail)",
    }


TOOLS: Dict[str, Tool] = {
    "get_weather": Tool({"city": str}, get_weather),
    "search_customer": Tool({"customer_id": str}, search_customer),
    "send_email": Tool({"to": str, "subject": str, "body": str}, send_email),
    "fetch_url": Tool({"url": str}, fetch_url),
    "settle_invoice": Tool(
        {"invoice_id": str, "amount_minor": int, "currency": str, "partner_signature": str, "dpop_proof": str},
        settle_invoice,
    ),
}
