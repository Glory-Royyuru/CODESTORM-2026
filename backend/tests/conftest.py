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
