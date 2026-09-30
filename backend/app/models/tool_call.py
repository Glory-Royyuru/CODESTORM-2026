import re
from typing import Any, Dict, Optional

from pydantic import BaseModel, ConfigDict, Field

# Agent and tool identifiers: ASCII, no whitespace, no look-alike characters.
IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
IDENTIFIER_RE = re.compile(IDENTIFIER_PATTERN)


class ToolCall(BaseModel):
    """The tool call exactly as the caller sent it (after strict JSON parsing).

    Unknown top-level fields are rejected and no type coercion happens.
    `agent_id` is a claim, not an authenticated identity; `context` is
    untrusted and never used for security decisions.
    """

    model_config = ConfigDict(extra="forbid", strict=True)

    agent_id: str = Field(..., pattern=IDENTIFIER_PATTERN)
    tool: str = Field(..., pattern=IDENTIFIER_PATTERN)
    parameters: Dict[str, Any]
    context: Optional[Dict[str, Any]] = None
