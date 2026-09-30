from typing import Dict, List, Optional

from pydantic import BaseModel

ALL_AGENTS = "*"


class RegisteredTool(BaseModel):
    name: str
    description: str
    enabled: bool
    allowed_agents: List[str]


TOOL_REGISTRY: Dict[str, RegisteredTool] = {
    "send_email": RegisteredTool(
        name="send_email",
        description="Send an email on behalf of the agent",
        enabled=True,
        allowed_agents=["support-bot-3"],
    ),
    "search_customer": RegisteredTool(
        name="search_customer",
        description="Search customer records by name or account id",
        enabled=True,
        allowed_agents=["support-bot-3", "sales-bot-1"],
    ),
    "get_weather": RegisteredTool(
        name="get_weather",
        description="Get current weather information for a location",
        enabled=True,
        allowed_agents=[ALL_AGENTS],
    ),
    "delete_database": RegisteredTool(
        name="delete_database",
        description="Delete a database (dangerous, disabled by default)",
        enabled=False,
        allowed_agents=["admin-bot"],
    ),
}


def get_tool(tool_name: str) -> Optional[RegisteredTool]:
    return TOOL_REGISTRY.get(tool_name)


def is_agent_authorized(tool: RegisteredTool, agent_id: str) -> bool:
    return ALL_AGENTS in tool.allowed_agents or agent_id in tool.allowed_agents
