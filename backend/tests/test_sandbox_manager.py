"""Unit tests: SandboxManager preconditions and result mapping, with a spy
runner instead of Docker. Nothing here starts a container."""

import importlib.util
from pathlib import Path

import pytest

from app.config import get_settings
from app.gateway.registry import TOOL_REGISTRY
from app.main import app  # noqa: F401  (registers the app for the client fixture)
from app.sandbox.docker_runner import DockerSandboxRunner, RawRun
from app.sandbox.manager import SandboxManager

WEATHER = {"agent_id": "research-bot", "tool": "get_weather", "parameters": {"city": "Berlin"}}
SANDBOX_TOOLS = Path(__file__).resolve().parents[2] / "sandbox" / "tools" / "__init__.py"


class SpyRunner:
    def __init__(self, raw=None):
        self.calls = []
        self.raw = raw

    def run(self, payload, entrypoint=None):
        self.calls.append(payload)
        return self.raw or RawRun("satg-sbx-test", 0, b'{"ok": true, "result": {"x": 1}}', b"", 5.0, False, False, True)


def gateway_result(client, body, monkeypatch):
    """Run the real pipeline and capture its (verdict, envelope)."""
    from app.gateway import pipeline

    captured = {}
    original = pipeline.process_tool_call

    def spy(*args):
        result = original(*args)
        captured["result"] = result
        return result

    monkeypatch.setattr("app.main.process_tool_call", spy)
    client.post("/v1/toolcalls", json=body)
    return captured["result"]


@pytest.fixture
def docker_settings(configure):
    return configure(SANDBOX_MODE="docker")


def test_allow_runs_canonical_parameters(client, monkeypatch, docker_settings):
    result = gateway_result(client, WEATHER, monkeypatch)
    spy = SpyRunner()
    execution = SandboxManager(docker_settings, spy).execute(result.verdict, result.envelope)
    assert execution.status == "success" and execution.result == {"x": 1}
    assert spy.calls == [b'{"arguments":{"city":"Berlin"},"egress":{"pinned_ips":[]},"tool":"get_weather"}']


@pytest.mark.parametrize(
    "body",
    [
        {**WEATHER, "tool": "delete_database", "agent_id": "admin-bot", "parameters": {"database_name": "x"}},  # disabled
        {**WEATHER, "tool": "send_email"},  # unauthorized
        {**WEATHER, "tool": "no_such_tool"},  # unknown
    ],
)
def test_blocked_verdict_never_reaches_runner(client, monkeypatch, docker_settings, body):
    result = gateway_result(client, body, monkeypatch)
    spy = SpyRunner()
    execution = SandboxManager(docker_settings, spy).execute(result.verdict, result.envelope)
    assert result.verdict.verdict.value == "BLOCK"
    assert execution.status == "not_executed"
    assert spy.calls == []


def test_escalate_never_reaches_runner(client, monkeypatch, configure):
    settings = configure(SANDBOX_MODE="docker", ML_HIGH_RISK_THRESHOLD="0.0", ML_CRITICAL_RISK_THRESHOLD="1.0")
    result = gateway_result(client, WEATHER, monkeypatch)
    spy = SpyRunner()
    assert result.verdict.verdict.value == "ESCALATE"
    assert SandboxManager(settings, spy).execute(result.verdict, result.envelope).status == "not_executed"
    assert spy.calls == []


def test_forged_allow_without_valid_hmac_is_refused(client, monkeypatch, docker_settings):
    result = gateway_result(client, WEATHER, monkeypatch)
    spy = SpyRunner()
    manager = SandboxManager(docker_settings, spy)
    forged = result.verdict.model_copy(update={"request_integrity": None})
    assert manager.execute(forged, result.envelope).status == "integrity_failed"
    tampered = result.verdict.model_copy(update={"tool_manifest_hash": "sha256:" + "0" * 64})
    assert manager.execute(tampered, result.envelope).status == "integrity_failed"
    assert spy.calls == []


def test_swapped_parameters_are_refused(client, monkeypatch, docker_settings):
    result = gateway_result(client, WEATHER, monkeypatch)
    spy = SpyRunner()
    swapped = result.envelope.model_copy(update={"parameters": {"city": "Lisbon"}})
    assert SandboxManager(docker_settings, spy).execute(result.verdict, swapped).status == "integrity_failed"
    assert spy.calls == []


def test_sandbox_off_executes_nothing(client, monkeypatch, configure):
    settings = configure(SANDBOX_MODE="off")
    result = gateway_result(client, WEATHER, monkeypatch)
    spy = SpyRunner()
    execution = SandboxManager(settings, spy).execute(result.verdict, result.envelope)
    assert execution.status == "not_executed" and spy.calls == []


@pytest.mark.parametrize(
    "raw, status",
    [
        (RawRun("s", None, b"", b"", 1.0, False, True, None), "sandbox_unavailable"),
        (RawRun("s", None, b"", b"", 1.0, True, False, True), "timeout"),
        (RawRun("s", 137, b"", b"", 1.0, False, False, True), "killed"),
        (RawRun("s", 2, b'{"ok": false, "error": "invalid_arguments", "detail": "d"}', b"", 1.0, False, False, True), "rejected"),
        (RawRun("s", 3, b'{"ok": false, "error": "network_unavailable", "detail": "d"}', b"", 1.0, False, False, True), "tool_error"),
        (RawRun("s", 0, b"not json", b"", 1.0, False, False, True), "error"),
    ],
)
def test_result_mapping(client, monkeypatch, docker_settings, raw, status):
    result = gateway_result(client, WEATHER, monkeypatch)
    assert SandboxManager(docker_settings, SpyRunner(raw)).execute(result.verdict, result.envelope).status == status


def test_docker_unavailable_is_a_controlled_failure(configure):
    """No docker CLI: the runner reports it and runs nothing on the host."""
    settings = configure(SANDBOX_MODE="docker", DOCKER_BIN="definitely-not-docker-satg")
    raw = DockerSandboxRunner(settings).run(b'{"tool":"get_weather","arguments":{"city":"Berlin"}}')
    assert raw.docker_unavailable and raw.exit_code is None and raw.stdout == b""


def test_run_args_are_hardened():
    args = DockerSandboxRunner(get_settings()).run_args("n")
    joined = " ".join(args)
    for flag in ("--rm", "--network none", "--read-only", "--cap-drop ALL", "--security-opt no-new-privileges",
                 "--memory 256m", "--cpus 0.5", "--pids-limit 64", "--user 65532:65532", "--pull never"):
        assert flag in joined
    for forbidden in ("--privileged", "-v", "--volume", "--mount", "docker.sock", "--network host", "--pid", "--cap-add"):
        assert forbidden not in args


def test_sandbox_tools_match_enabled_registry():
    spec = importlib.util.spec_from_file_location("sandbox_tools", SANDBOX_TOOLS)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    enabled = {name for name, tool in TOOL_REGISTRY.items() if tool.enabled}
    assert set(module.TOOLS) == enabled
    for name, tool in module.TOOLS.items():
        assert set(tool.schema) == set(TOOL_REGISTRY[name].parameters)
