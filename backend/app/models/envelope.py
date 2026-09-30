import uuid
from typing import Any, Dict, Optional

from pydantic import BaseModel, ConfigDict


def new_request_id() -> str:
    return f"req_{uuid.uuid4().hex}"


class Principal(BaseModel):
    """The identity the gateway authorizes a tool call against.

    Until authentication exists (WP2), the only identity available is the
    agent_id the caller claims in the request body, so `authenticated` is
    False and `auth_method` says so explicitly.
    """

    model_config = ConfigDict(frozen=True)

    agent_id: str
    authenticated: bool
    auth_method: str


class ToolCallEnvelope(BaseModel):
    """The canonical form of a tool call.

    Security checks read the envelope, never the raw ToolCall, so every
    validator sees the same normalized values. Anything that later acts on
    an ALLOW verdict must use these canonical parameters -- the values that
    were actually checked, bound by `request_hash`.
    """

    model_config = ConfigDict(frozen=True)

    request_id: str
    principal: Principal
    tool: str
    parameters: Dict[str, Any]
    # Caller-supplied context is carried for reference only. It is not
    # authenticated and no security decision reads it.
    untrusted_context: Optional[Dict[str, Any]] = None
    request_hash: str
