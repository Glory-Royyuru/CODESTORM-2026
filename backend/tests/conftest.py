import pytest
from fastapi.testclient import TestClient

from app.gateway.registry import BUILTIN_SERVER_ID, RegisteredTool, register_tool, unregister_tool
from app.main import app


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def temp_tool():
    """Register throwaway tools for a test and remove them afterwards.

    Call it with manifest field overrides; returns the registered tool.
    """
    registered = []

    def register(**overrides):
        fields = {
            "name": "temp_tool",
            "version": "1.0.0",
            "server_id": BUILTIN_SERVER_ID,
            "description": "Temporary test tool",
            "enabled": True,
            "allowed_agents": ["test-agent"],
            "parameters": {},
            "security": {"side_effect": "none", "egress": None},
            **overrides,
        }
        tool = RegisteredTool.model_validate(fields)
        register_tool(tool)
        registered.append(tool.name)
        return tool

    yield register
    for name in registered:
        unregister_tool(name)


# ---------------------------------------------------------------- settings / ML / Docker

import subprocess
from pathlib import Path

from app.config import get_settings
from app.ml import model_loader

SANDBOX_DIR = Path(__file__).resolve().parents[2] / "sandbox"


def pytest_configure(config):
    config.addinivalue_line("markers", "docker: needs a running Docker daemon and the sandbox image")


@pytest.fixture(autouse=True)
def _default_settings(request, monkeypatch):
    """Unit tests run verdict-only (SANDBOX_MODE=off); `docker` tests use the real sandbox."""
    if request.node.get_closest_marker("docker") is None:
        monkeypatch.setenv("SANDBOX_MODE", "off")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def configure(monkeypatch):
    """Override configuration through environment variables for one test."""

    def apply(**env):
        for name, value in env.items():
            monkeypatch.setenv(name, str(value))
        get_settings.cache_clear()
        if any(name.startswith("ML_") for name in env):
            model_loader.reset()
        return get_settings()

    yield apply
    get_settings.cache_clear()
    model_loader.reset()


def _docker_ok() -> bool:
    try:
        return subprocess.run(["docker", "version"], capture_output=True, timeout=20).returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


@pytest.fixture(scope="session")
def sandbox_image():
    """Build the sandbox image once per session (skip if Docker is not running)."""
    if not _docker_ok():
        pytest.skip("Docker daemon not available")
    image = get_settings().sandbox_image
    build = subprocess.run(["docker", "build", "-q", "-t", image, str(SANDBOX_DIR)], capture_output=True, timeout=600)
    if build.returncode != 0:
        pytest.fail(f"sandbox image build failed: {build.stderr.decode(errors='replace')[-500:]}")
    return image
