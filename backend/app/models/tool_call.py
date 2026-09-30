from typing import Any, Dict, Optional

from pydantic import BaseModel, Field, field_validator


class ToolCall(BaseModel):
    agent_id: str = Field(..., min_length=1)
    tool: str = Field(..., min_length=1)
    parameters: Dict[str, Any]
    context: Optional[Dict[str, Any]] = None

    @field_validator("agent_id", "tool")
    @classmethod
    def not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be empty or whitespace")
        return value
