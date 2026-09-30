import json
from typing import Any, Dict, List, Optional

from fastapi import Request
from pydantic import ValidationError

from app.models.tool_call import IDENTIFIER_RE, ToolCall

MAX_BODY_BYTES = 64 * 1024
# Depth of nested objects/arrays; the top-level object is depth 1 and
# `parameters` is depth 2.
MAX_JSON_DEPTH = 8


class IngressRejection(Exception):
    """A request refused before it became a ToolCall."""

    def __init__(
        self,
        status_code: int,
        rule_id: str,
        reason: str,
        data: Any = None,
        errors: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        super().__init__(reason)
        self.status_code = status_code
        self.rule_id = rule_id
        self.reason = reason
        self.errors = errors
        # Best-effort identifiers for the audit record, only when well-formed.
        self.claimed_agent_id = _claimed_identifier(data, "agent_id")
        self.claimed_tool = _claimed_identifier(data, "tool")


class _DuplicateKeyError(ValueError):
    pass


class _NonFiniteNumberError(ValueError):
    pass


async def read_tool_call(request: Request) -> ToolCall:
    """Read and strictly parse a tool call request body.

    Rejects: non-JSON content types (INGRESS-006), bodies over
    MAX_BODY_BYTES (INGRESS-003), invalid UTF-8/JSON or NaN/Infinity
    (INGRESS-001), duplicate object keys at any depth (INGRESS-002),
    nesting deeper than MAX_JSON_DEPTH (INGRESS-004), and anything that
    does not match the ToolCall schema, including unknown fields
    (INGRESS-005).
    """
    _check_content_type(request)
    body = await _read_body(request)
    data = _parse_json(body)
    if _exceeds_depth(data, MAX_JSON_DEPTH):
        raise IngressRejection(400, "INGRESS-004", f"Request body is nested deeper than {MAX_JSON_DEPTH} levels", data)
    try:
        return ToolCall.model_validate(data)
    except ValidationError as error:
        errors = [
            {"loc": list(e["loc"]), "msg": e["msg"], "type": e["type"]}
            for e in error.errors(include_url=False, include_input=False)
        ]
        raise IngressRejection(422, "INGRESS-005", "Request does not match the tool call schema", data, errors)


def _check_content_type(request: Request) -> None:
    media_type, _, params = request.headers.get("content-type", "").partition(";")
    charset = params.strip().lower()
    if media_type.strip().lower() != "application/json" or charset not in ("", "charset=utf-8"):
        raise IngressRejection(415, "INGRESS-006", "Content-Type must be application/json (UTF-8)")


async def _read_body(request: Request) -> bytes:
    too_large = IngressRejection(413, "INGRESS-003", f"Request body exceeds {MAX_BODY_BYTES} bytes")

    declared = request.headers.get("content-length")
    if declared is not None:
        if not (declared.isascii() and declared.isdigit()):
            raise IngressRejection(400, "INGRESS-001", "Invalid Content-Length header")
        if int(declared) > MAX_BODY_BYTES:
            raise too_large

    # Enforce the limit while reading too, in case Content-Length is absent
    # (chunked transfer) or wrong.
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > MAX_BODY_BYTES:
            raise too_large
    return bytes(body)


def _parse_json(body: bytes) -> Any:
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        raise IngressRejection(400, "INGRESS-001", "Request body is not valid UTF-8")
    try:
        return json.loads(text, object_pairs_hook=_reject_duplicate_keys, parse_constant=_reject_constant)
    except _DuplicateKeyError:
        raise IngressRejection(400, "INGRESS-002", "Request body contains duplicate JSON keys")
    except _NonFiniteNumberError:
        raise IngressRejection(400, "INGRESS-001", "Request body contains NaN or Infinity")
    except RecursionError:
        raise IngressRejection(400, "INGRESS-004", f"Request body is nested deeper than {MAX_JSON_DEPTH} levels")
    except ValueError:
        raise IngressRejection(400, "INGRESS-001", "Request body is not valid JSON")


def _reject_duplicate_keys(pairs: List[tuple]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError(key)
        result[key] = value
    return result


def _reject_constant(name: str) -> Any:
    raise _NonFiniteNumberError(name)


def _exceeds_depth(value: Any, limit: int) -> bool:
    stack = [(value, 1)]
    while stack:
        item, depth = stack.pop()
        if isinstance(item, (dict, list)):
            if depth > limit:
                return True
            children = item.values() if isinstance(item, dict) else item
            stack.extend((child, depth + 1) for child in children)
    return False


def _claimed_identifier(data: Any, field: str) -> Optional[str]:
    value = data.get(field) if isinstance(data, dict) else None
    return value if isinstance(value, str) and IDENTIFIER_RE.fullmatch(value) else None
