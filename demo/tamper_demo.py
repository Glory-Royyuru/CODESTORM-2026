"""
SATG tamper demo: the sandbox refuses an approved call that was changed after the gateway approved it.

It runs in-process with the backend's own code (no HTTP endpoint exists for
this, by design):
  1. the real gateway pipeline approves search_customer(CUST-1042) and signs it
     (HMAC-SHA256 over the verdict, which binds request_hash);
  2. that untampered approval is executed once, as a control, in the real Docker sandbox;
  3. three tampered copies are handed to the same SandboxManager:
       a. parameters changed after approval,
       b. parameters changed and request_hash recomputed to match,
       c. the integrity tag stripped;
     each must come back integrity_failed with no container started.

Run from the repository root with the backend's interpreter (Docker running,
sandbox image built):
  backend\\.venv\\Scripts\\python.exe demo\\tamper_demo.py
"""

import sys
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.config import get_settings  # noqa: E402
from app.gateway.canonicalizer import canonical_json, sha256_hex  # noqa: E402
from app.gateway.identity import resolve_principal  # noqa: E402
from app.gateway.pipeline import process_tool_call  # noqa: E402
from app.models.envelope import new_request_id  # noqa: E402
from app.models.tool_call import ToolCall  # noqa: E402
from app.sandbox.docker_runner import DockerSandboxRunner  # noqa: E402
from app.sandbox.manager import SandboxManager  # noqa: E402


class CountingRunner(DockerSandboxRunner):
    """The real Docker runner, counting how many containers it is asked to start."""

    def __init__(self, settings):
        super().__init__(settings)
        self.started = 0

    def run(self, payload, entrypoint=None):
        self.started += 1
        return super().run(payload, entrypoint)


def main() -> int:
    settings = get_settings()
    if settings.sandbox_mode != "docker":
        print(f"SANDBOX_MODE={settings.sandbox_mode}: this demo needs SANDBOX_MODE=docker.")
        return 2

    call = ToolCall(agent_id="support-bot-3", tool="search_customer", parameters={"customer_id": "CUST-1042"})
    result = process_tool_call(call, resolve_principal(call.agent_id), new_request_id())
    verdict, envelope = result.verdict, result.envelope
    print(f"Gateway verdict : {verdict.verdict.value} {verdict.rule_id} for search_customer(CUST-1042)")
    if verdict.verdict.value != "ALLOW" or verdict.request_integrity is None:
        print(f"Expected a signed ALLOW to tamper with; got {verdict.verdict.value} ({verdict.reason}).")
        return 1
    print(f"Integrity tag   : {verdict.request_integrity.algorithm} over request_hash {verdict.request_hash[:23]}...")

    runner = CountingRunner(settings)
    manager = SandboxManager(settings, runner)

    control = manager.execute(verdict, envelope)
    print(f"\n[control] untampered approval -> {control.status}, containers started: {runner.started}")
    if control.status == "success":
        print(f"          result: {control.result}")

    swapped = envelope.model_copy(update={"parameters": {"customer_id": "CUST-2077"}})
    forged_hash = sha256_hex(canonical_json(
        {"agent_id": envelope.principal.agent_id, "tool": envelope.tool, "parameters": swapped.parameters}
    ))
    attacks = [
        ("a. customer_id changed to CUST-2077 after approval", verdict, swapped),
        ("b. same change, request_hash recomputed to match", verdict.model_copy(update={"request_hash": forged_hash}), swapped),
        ("c. integrity tag removed", verdict.model_copy(update={"request_integrity": None}), envelope),
    ]
    refused = 0
    for name, tampered_verdict, tampered_envelope in attacks:
        before = runner.started
        outcome = manager.execute(tampered_verdict, tampered_envelope)
        started = runner.started - before
        ok = outcome.status == "integrity_failed" and started == 0
        refused += ok
        print(f"\n[tamper]  {name}")
        print(f"          -> {outcome.status}: {outcome.error}; containers started: {started}  {'(refused)' if ok else '(NOT REFUSED)'}")

    print(f"\n{refused}/{len(attacks)} tampered requests refused by SandboxManager before any container started.")
    return 0 if refused == len(attacks) else 1


if __name__ == "__main__":
    sys.exit(main())
