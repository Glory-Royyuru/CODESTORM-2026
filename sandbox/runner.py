"""SATG sandbox runner: the container's only entrypoint.

Reads one JSON request from stdin, runs one *registered* tool with the
gateway's canonical, already-validated arguments, and writes one JSON
result to stdout. It never evaluates code, never starts a shell and never
resolves DNS. Unknown tools and malformed arguments fail.

stdin:  {"tool": str, "arguments": {...}, "egress": {"pinned_ips": [str, ...]}}
stdout: {"ok": true, "result": {...}} | {"ok": false, "error": str, "detail": str}
exit:   0 success, 2 rejected request, 3 tool failure
"""

import json
import sys

sys.path.insert(0, "/opt/satg")  # python -I does not add the script directory

from tools import TOOLS, ToolError  # noqa: E402

MAX_INPUT_BYTES = 64 * 1024
EXIT_OK, EXIT_REJECTED, EXIT_TOOL_FAILED = 0, 2, 3


def _reply(code: int, payload: dict) -> None:
    sys.stdout.write(json.dumps(payload, sort_keys=True, ensure_ascii=True))
    sys.stdout.flush()
    sys.exit(code)


def _no_duplicates(pairs):
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate key")
    return dict(pairs)


def _reject_constant(name):
    raise ValueError(f"non-finite number {name}")


def main() -> None:
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        _reply(EXIT_REJECTED, {"ok": False, "error": "input_too_large", "detail": f"over {MAX_INPUT_BYTES} bytes"})
    try:
        request = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicates, parse_constant=_reject_constant)
    except (UnicodeDecodeError, ValueError) as error:
        _reply(EXIT_REJECTED, {"ok": False, "error": "malformed_request", "detail": str(error)[:200]})

    if not isinstance(request, dict) or set(request) - {"tool", "arguments", "egress"}:
        _reply(EXIT_REJECTED, {"ok": False, "error": "malformed_request", "detail": "unexpected request shape"})
    tool = TOOLS.get(request.get("tool")) if isinstance(request.get("tool"), str) else None
    if tool is None:
        _reply(EXIT_REJECTED, {"ok": False, "error": "unknown_tool", "detail": "tool is not registered in the sandbox"})

    arguments = request.get("arguments")
    problem = tool.check_arguments(arguments)
    if problem:
        _reply(EXIT_REJECTED, {"ok": False, "error": "invalid_arguments", "detail": problem})

    egress = request.get("egress") or {}
    pinned = egress.get("pinned_ips") if isinstance(egress, dict) else None
    pinned_ips = [ip for ip in pinned if isinstance(ip, str)] if isinstance(pinned, list) else []

    try:
        result = tool.run(arguments, pinned_ips)
    except ToolError as error:
        _reply(EXIT_TOOL_FAILED, {"ok": False, "error": error.code, "detail": error.detail})
    _reply(EXIT_OK, {"ok": True, "result": result})


if __name__ == "__main__":
    main()
