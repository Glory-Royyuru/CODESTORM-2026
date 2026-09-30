from app.models.envelope import Principal

AUTH_METHOD_SELF_ASSERTED = "self_asserted"


def resolve_principal(claimed_agent_id: str) -> Principal:
    """Resolve the identity the gateway authorizes against.

    Authentication is not implemented yet (WP2). Until it is, the only
    identity available is the agent_id the caller put in the request body.
    It is used as-is but marked unauthenticated, so nothing downstream can
    mistake it for a verified identity. When authentication lands, this is
    the single place that changes: the principal will come from the
    verified credential, and the body's agent_id becomes a claim to check
    against it.
    """
    return Principal(agent_id=claimed_agent_id, authenticated=False, auth_method=AUTH_METHOD_SELF_ASSERTED)
