"""SandboxManager: the only path from a verdict to tool execution.

Preconditions, all checked here, fail closed:
  * the final verdict is ALLOW (BLOCK and ESCALATE never reach Docker);
  * its HMAC request-integrity tag verifies against the verdict;
  * the tool is registered and enabled;
  * the envelope is the one the verdict's request_hash was computed from.
The container receives only the canonical, validated parameters and the
DNS pins. If Docker is unavailable the call fails; it is never run on the host.
"""

import json
from typing import Optional

from app.config import Settings
from app.gateway.canonicalizer import canonical_json, sha256_hex
from app.gateway.pipeline import integrity_fields
from app.gateway.registry import get_tool
from app.gateway.request_integrity import verify_request_integrity
from app.models.envelope import ToolCallEnvelope
from app.models.verdict import SandboxExecution, Verdict, VerdictType
from app.sandbox.docker_runner import KILLED, DockerSandboxRunner

# Runner exit codes (sandbox/runner.py).
RUNNER_OK, RUNNER_REJECTED, RUNNER_TOOL_FAILED = 0, 2, 3


class SandboxRefused(Exception):
    """A precondition failed; nothing was started."""

    def __init__(self, message: str, status: str = "not_executed") -> None:
        super().__init__(message)
        self.status = status


class SandboxManager:
    def __init__(self, settings: Settings, runner: Optional[DockerSandboxRunner] = None) -> None:
        self.settings = settings
        self.runner = runner or DockerSandboxRunner(settings)

    def execute(self, verdict: Verdict, envelope: Optional[ToolCallEnvelope]) -> SandboxExecution:
        try:
            payload = self._payload(verdict, envelope)
        except SandboxRefused as refusal:
            return SandboxExecution(status=refusal.status, error=str(refusal))
        if self.settings.sandbox_mode == "off":
            return SandboxExecution(status="not_executed", error="SANDBOX_MODE=off: verdict only, nothing executed")
        return self._interpret(self.runner.run(payload))

    def _payload(self, verdict: Verdict, envelope: Optional[ToolCallEnvelope]) -> bytes:
        if verdict.verdict != VerdictType.ALLOW:
            raise SandboxRefused(f"verdict is {verdict.verdict.value}; only ALLOW is executed")
        if envelope is None or envelope.request_id != verdict.request_id or envelope.tool != verdict.tool:
            raise SandboxRefused("envelope does not match the verdict")
        recomputed = sha256_hex(canonical_json({"agent_id": envelope.principal.agent_id, "tool": envelope.tool, "parameters": envelope.parameters}))
        if recomputed != verdict.request_hash:
            raise SandboxRefused("canonical parameters do not match the verdict's request_hash", "integrity_failed")
        tag = verdict.request_integrity.model_dump() if verdict.request_integrity else None
        if not verify_request_integrity(integrity_fields(verdict), tag):
            raise SandboxRefused("request integrity tag missing or invalid", "integrity_failed")
        tool = get_tool(envelope.tool)
        if tool is None or not tool.enabled:
            raise SandboxRefused("tool is not registered and enabled")
        return canonical_json({
            "tool": envelope.tool,
            "arguments": envelope.parameters,
            "egress": {"pinned_ips": [n.pinned_ip for n in verdict.network if n.pinned_ip]},
        })

    def _interpret(self, raw) -> SandboxExecution:
        limit = self.settings.sandbox_max_output_bytes
        stdout = raw.stdout[:limit].decode("utf-8", "replace")
        stderr = raw.stderr[:limit].decode("utf-8", "replace")
        common = dict(
            sandbox_id=raw.sandbox_id, exit_code=raw.exit_code, duration_ms=raw.duration_ms,
            stdout=stdout, stderr=stderr, container_removed=raw.container_removed,
        )
        if raw.docker_unavailable:
            return SandboxExecution(status="sandbox_unavailable", error="Docker is unavailable or refused to start the sandbox; the tool was not run", **common)
        if raw.timed_out:
            return SandboxExecution(status="timeout", error=f"exceeded SANDBOX_TIMEOUT={self.settings.sandbox_timeout}s; container killed", **common)
        if raw.exit_code == KILLED:
            return SandboxExecution(status="killed", error="container killed (memory limit or signal)", **common)

        parsed = None
        if len(raw.stdout) <= limit:
            try:
                parsed = json.loads(raw.stdout.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                parsed = None
        parsed = parsed if isinstance(parsed, dict) else None
        if raw.exit_code == RUNNER_OK and parsed and parsed.get("ok") is True:
            result = parsed.get("result")
            return SandboxExecution(status="success", result=result if isinstance(result, dict) else None, **common)
        error = f"{parsed.get('error')}: {parsed.get('detail')}" if parsed else "sandbox produced no valid result"
        if raw.exit_code == RUNNER_REJECTED:
            return SandboxExecution(status="rejected", error=error, **common)
        if raw.exit_code == RUNNER_TOOL_FAILED:
            return SandboxExecution(status="tool_error", error=error, **common)
        return SandboxExecution(status="error", error=error, **common)
