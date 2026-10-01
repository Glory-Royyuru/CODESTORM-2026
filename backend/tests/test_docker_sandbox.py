"""Integration and Docker security tests: FastAPI -> deterministic checks ->
ML -> decision -> Docker. Needs a running Docker daemon (skipped otherwise).

Security probes run arbitrary Python *only in these tests*, via
DockerSandboxRunner.run(entrypoint=...), which uses exactly the flag set the
gateway uses. The gateway itself never passes an entrypoint.
"""

import json
import subprocess

import pytest

from app.config import get_settings
from app.gateway import network
from app.sandbox import docker_runner
from app.sandbox.docker_runner import DockerSandboxRunner

pytestmark = pytest.mark.docker

WEATHER = {"agent_id": "research-bot", "tool": "get_weather", "parameters": {"city": "Berlin"}}


@pytest.fixture(autouse=True)
def _image(sandbox_image):
    return sandbox_image


@pytest.fixture
def docker_runs(monkeypatch):
    """Count real `docker run` invocations made by the gateway."""
    calls = []
    original = DockerSandboxRunner.run

    def counting(self, payload, entrypoint=None):
        calls.append(payload)
        return original(self, payload, entrypoint)

    monkeypatch.setattr(DockerSandboxRunner, "run", counting)
    return calls


def probe(code: str, **overrides):
    """Run Python inside a container configured exactly like a tool sandbox."""
    settings = get_settings()
    if overrides:
        settings = settings.__class__(**{**settings.__dict__, **overrides})
    return DockerSandboxRunner(settings).run(b"", entrypoint=["python", "-c", code])


def post(client, body):
    return client.post("/v1/toolcalls", json=body).json()


def satg_containers():
    out = subprocess.run(["docker", "ps", "--all", "--quiet", "--filter", "label=satg.sandbox=1"], capture_output=True, timeout=20)
    return out.stdout.split()


# ------------------------------------------------------------------ full chain


def test_1_normal_request_runs_in_docker(client, docker_runs):
    body = post(client, WEATHER)
    assert body["decision"]["deterministic_verdict"] == "ALLOW"
    assert body["ml"]["status"] == "ok"
    assert body["verdict"] == "ALLOW"
    execution = body["execution"]
    assert execution["status"] == "success" and execution["exit_code"] == 0
    assert execution["result"]["forecast"] == "Partly cloudy"
    assert execution["container_removed"] is True
    assert len(docker_runs) == 1


@pytest.mark.parametrize(
    "request_body, rule",
    [
        ({**WEATHER, "tool": "send_email", "parameters": {"to": "a@company.com", "subject": "s", "body": "b"}}, "TOOL-003"),  # test 2
        ({**WEATHER, "tool": "wire_money"}, "TOOL-001"),  # test 3
        ({**WEATHER, "parameters": {"city": 42}}, "PARAM-002"),  # test 4
        ({"agent_id": "research-bot", "tool": "fetch_url", "parameters": {"url": "https://169.254.169.254/latest/meta-data/"}}, "DEST-004"),  # test 5
    ],
    ids=["unauthorized_agent", "unknown_tool", "invalid_parameters", "malicious_destination"],
)
def test_2_to_5_blocked_requests_never_start_docker(client, docker_runs, request_body, rule):
    body = post(client, request_body)
    assert body["verdict"] == "BLOCK" and body["rule_id"] == rule
    assert body["execution"] is None
    assert body["ml"]["status"] == "not_consulted"
    assert docker_runs == []


def test_6_high_ml_risk_escalates_without_docker(client, docker_runs, configure):
    configure(SANDBOX_MODE="docker", ML_HIGH_RISK_THRESHOLD="0.0", ML_CRITICAL_RISK_THRESHOLD="1.0")
    body = post(client, WEATHER)
    assert body["verdict"] == "ESCALATE" and body["rule_id"] == "ML-001"
    assert body["execution"] is None and docker_runs == []


def test_7_private_untrusted_outbound_chain_is_blocked_before_docker(client, docker_runs):
    """Lethal-trifecta shape (private read + untrusted content + outbound).
    The backend has no deterministic trifecta rule (it has no trusted
    session state); this chain is stopped by the ML layer (ML-002)."""
    from test_ml_decision import trifecta_email

    body = post(client, trifecta_email())
    assert body["decision"]["deterministic_verdict"] == "ALLOW"
    assert body["verdict"] == "BLOCK" and body["rule_id"] == "ML-002"
    assert body["execution"] is None and docker_runs == []


# ------------------------------------------------------------------ container security


def test_8_network_is_disabled(client, monkeypatch):
    # A legitimately allowed fetch reaches the sandbox and cannot connect out.
    monkeypatch.setattr(network, "resolver", lambda host: ["140.82.112.5"])
    body = post(client, {"agent_id": "research-bot", "tool": "fetch_url", "parameters": {"url": "https://api.github.com/zen"}})
    assert body["verdict"] == "ALLOW", body["reason"]
    assert body["execution"]["status"] == "tool_error"
    assert "network_unavailable" in body["execution"]["error"]
    raw = probe(
        "import socket\n"
        "try:\n socket.create_connection(('1.1.1.1', 53), timeout=3); print('CONNECTED')\n"
        "except OSError as e: print('BLOCKED', e.errno)\n"
        "print(sorted(i[1] for i in socket.if_nameindex()))"
    )
    out = raw.stdout.decode()
    assert "BLOCKED" in out and "CONNECTED" not in out
    assert "['lo']" in out  # loopback only: no eth0


def test_9_filesystem_is_read_only():
    raw = probe(
        "import errno\n"
        "for p in ('/opt/satg/runner.py', '/tmp/x', '/etc/passwd', '/x'):\n"
        " try:\n  open(p, 'a').write('x'); print('WROTE', p)\n"
        " except OSError as e: print('DENIED', p, errno.errorcode[e.errno])"
    )
    out = raw.stdout.decode()
    assert "WROTE" not in out
    assert out.count("DENIED") == 4
    assert "EROFS" in out


def test_10_runs_as_non_root_without_capabilities():
    raw = probe(
        "import os\n"
        "print(os.getuid(), os.geteuid(), os.getgid())\n"
        "status = dict(l.split(':', 1) for l in open('/proc/self/status') if ':' in l)\n"
        "print(status['CapEff'].strip(), status['CapBnd'].strip(), status['NoNewPrivs'].strip())\n"
        "print(os.path.exists('/var/run/docker.sock'))"
    )
    uid_line, caps_line, sock_line = raw.stdout.decode().split("\n")[:3]
    assert uid_line == "65532 65532 65532"
    assert caps_line == "0000000000000000 0000000000000000 1"
    assert sock_line == "False"


def test_11_resource_limits_are_enforced():
    limits = probe("print(open('/sys/fs/cgroup/memory.max').read().strip(), open('/sys/fs/cgroup/cpu.max').read().strip(), open('/sys/fs/cgroup/pids.max').read().strip())")
    assert limits.stdout.decode().split() == [str(256 * 1024 * 1024), "50000", "100000", "64"]

    memory = probe("x = bytearray(600 * 1024 * 1024); print('ALLOCATED')")
    assert memory.exit_code == docker_runner.KILLED and b"ALLOCATED" not in memory.stdout

    forks = probe(
        "import os, time\n"
        "n = 0\n"
        "try:\n"
        " for _ in range(200):\n"
        "  if os.fork() == 0:\n   time.sleep(5); os._exit(0)\n"
        "  n += 1\n"
        "except OSError as e: print('LIMITED after', n)\n"
    )
    assert b"LIMITED after" in forks.stdout
    assert int(forks.stdout.split()[-1]) < 64


def test_12_timeout_kills_and_cleans_up():
    raw = probe("import time; time.sleep(60)", sandbox_timeout=2.0)
    assert raw.timed_out and raw.exit_code is None
    assert raw.duration_ms < 20_000
    assert raw.container_removed is True


def test_13_docker_unavailable_never_falls_back_to_host(client, configure):
    configure(SANDBOX_MODE="docker", DOCKER_BIN="definitely-not-docker-satg")
    body = post(client, WEATHER)
    assert body["verdict"] == "ALLOW"
    assert body["execution"]["status"] == "sandbox_unavailable"
    assert body["execution"]["result"] is None and body["execution"]["stdout"] == ""


def test_13b_unknown_image_fails_without_pulling(client, configure):
    configure(SANDBOX_MODE="docker", SANDBOX_IMAGE="satg-sandbox:does-not-exist")
    body = post(client, WEATHER)
    assert body["execution"]["status"] == "sandbox_unavailable"


def test_runner_rejects_unregistered_tool_and_bad_arguments():
    runner = DockerSandboxRunner(get_settings())
    unknown = runner.run(json.dumps({"tool": "delete_database", "arguments": {"database_name": "x"}}).encode())
    assert unknown.exit_code == 2 and b"unknown_tool" in unknown.stdout
    bad = runner.run(json.dumps({"tool": "get_weather", "arguments": {"city": "Berlin", "extra": 1}}).encode())
    assert bad.exit_code == 2 and b"invalid_arguments" in bad.stdout
    code = runner.run(json.dumps({"tool": "get_weather", "arguments": {"city": "__import__('os').system('id')"}}).encode())
    assert code.exit_code == 3 and b"not_found" in code.stdout  # treated as data, never evaluated


def test_14_no_orphan_containers_remain():
    assert satg_containers() == []
