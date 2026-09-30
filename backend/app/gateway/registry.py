from typing import Dict, List, Literal, Optional

from pydantic import BaseModel, Field, model_validator

from app.gateway.canonicalizer import canonical_json, sha256_hex

ALL_AGENTS = "*"

# The demo tools are defined in this process; there is no remote tool server.
BUILTIN_SERVER_ID = "satg-builtin"

# The manifest fields that describe what a tool *is*. Operational state
# (`enabled`) and authorization policy (`allowed_agents`) are deliberately
# excluded: turning a tool off or granting an agent access is not a change
# to the tool, but a changed description, schema, or egress declaration is.
MANIFEST_HASH_FIELDS = {"name", "version", "server_id", "description", "parameters", "security"}


class ParameterSpec(BaseModel):
    type: Literal["string", "integer", "number", "boolean"]
    required: bool = True
    # Reject line breaks, e.g. for values that end up in an email header.
    single_line: bool = False


class EgressSpec(BaseModel):
    """Declares that a tool sends data to a caller-chosen destination."""

    # The destination validator fails closed on channels it has no parser for.
    channel: str
    destination_parameters: List[str] = Field(min_length=1)


class ToolSecurity(BaseModel):
    side_effect: Literal["none", "read", "write", "destructive"]
    # No default on purpose: every tool must state whether it has a
    # caller-chosen destination (None = no), so a new egress-capable tool
    # cannot skip destination validation by omission.
    egress: Optional[EgressSpec]


class RegisteredTool(BaseModel):
    """A tool's manifest: what it is, who may call it, and its security
    properties. The parameter schema lives here, so the registry is the
    single source of truth for a tool."""

    name: str
    version: str
    server_id: str
    description: str
    enabled: bool
    allowed_agents: List[str]
    parameters: Dict[str, ParameterSpec]
    security: ToolSecurity

    @model_validator(mode="after")
    def destinations_are_declared_strings(self) -> "RegisteredTool":
        if self.security.egress is not None:
            for name in self.security.egress.destination_parameters:
                spec = self.parameters.get(name)
                if spec is None or spec.type != "string" or not spec.required:
                    raise ValueError(f"destination parameter '{name}' must be a required string parameter")
        return self

    def manifest_hash(self) -> str:
        return sha256_hex(canonical_json(self.model_dump(mode="json", include=MANIFEST_HASH_FIELDS)))


TOOL_REGISTRY: Dict[str, RegisteredTool] = {}

# Hash of each manifest at registration time. A manifest that no longer
# matches its pinned hash has been changed after registration (the
# foundation for rug-pull detection) and is refused.
_PINNED_MANIFEST_HASHES: Dict[str, str] = {}


def register_tool(tool: RegisteredTool) -> str:
    manifest_hash = tool.manifest_hash()
    TOOL_REGISTRY[tool.name] = tool
    _PINNED_MANIFEST_HASHES[tool.name] = manifest_hash
    return manifest_hash


def unregister_tool(tool_name: str) -> None:
    TOOL_REGISTRY.pop(tool_name, None)
    _PINNED_MANIFEST_HASHES.pop(tool_name, None)


def get_tool(tool_name: str) -> Optional[RegisteredTool]:
    return TOOL_REGISTRY.get(tool_name)


def get_pinned_manifest_hash(tool_name: str) -> Optional[str]:
    return _PINNED_MANIFEST_HASHES.get(tool_name)


def is_manifest_intact(tool_name: str, tool: RegisteredTool) -> bool:
    pinned = _PINNED_MANIFEST_HASHES.get(tool_name)
    return tool.name == tool_name and pinned is not None and pinned == tool.manifest_hash()


def is_agent_authorized(tool: RegisteredTool, agent_id: str) -> bool:
    return ALL_AGENTS in tool.allowed_agents or agent_id in tool.allowed_agents


for _tool in (
    RegisteredTool(
        name="send_email",
        version="1.0.0",
        server_id=BUILTIN_SERVER_ID,
        description="Send an email on behalf of the agent",
        enabled=True,
        allowed_agents=["support-bot-3"],
        parameters={
            "to": ParameterSpec(type="string", single_line=True),
            "subject": ParameterSpec(type="string", single_line=True),
            "body": ParameterSpec(type="string"),
        },
        security=ToolSecurity(
            side_effect="write",
            egress=EgressSpec(channel="email", destination_parameters=["to"]),
        ),
    ),
    RegisteredTool(
        name="search_customer",
        version="1.0.0",
        server_id=BUILTIN_SERVER_ID,
        description="Search customer records by name or account id",
        enabled=True,
        allowed_agents=["support-bot-3", "sales-bot-1"],
        parameters={"customer_id": ParameterSpec(type="string")},
        security=ToolSecurity(side_effect="read", egress=None),
    ),
    RegisteredTool(
        name="get_weather",
        version="1.0.0",
        server_id=BUILTIN_SERVER_ID,
        description="Get current weather information for a location",
        enabled=True,
        allowed_agents=[ALL_AGENTS],
        parameters={"city": ParameterSpec(type="string")},
        security=ToolSecurity(side_effect="read", egress=None),
    ),
    RegisteredTool(
        name="delete_database",
        version="1.0.0",
        server_id=BUILTIN_SERVER_ID,
        description="Delete a database (dangerous, disabled by default)",
        enabled=False,
        allowed_agents=["admin-bot"],
        parameters={"database_name": ParameterSpec(type="string")},
        security=ToolSecurity(side_effect="destructive", egress=None),
    ),
):
    register_tool(_tool)
