import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.audit.anomaly_ledger import append_anomaly, quarantine_record
from app.audit.logger import record_audit_event
from app.gateway.identity import resolve_principal
from app.gateway.ingress import IngressRejection, read_tool_call
from app.gateway.pipeline import CHECK_REQUEST_STRUCTURE, process_tool_call
from app.gateway.policy_engine import CheckOutcome, DecisionContext, decide
from app.models.envelope import new_request_id
from app.models.tool_call import ToolCall
from app.models.verdict import Severity, Verdict

app = FastAPI(title="PNC3 Secure Agent Tool Gateway")

_log = logging.getLogger("satg.gateway")

# Anomaly-ledger fields the verdict already carries elsewhere.
_LEDGER_ONLY_FIELDS = {"timestamp", "request_id", "agent_id", "tool"}

# The body is parsed by the strict ingress reader, not by FastAPI, so the
# request schema is declared here for the OpenAPI docs.
_TOOL_CALL_OPENAPI = {
    "requestBody": {
        "required": True,
        "content": {"application/json": {"schema": ToolCall.model_json_schema()}},
    }
}


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/v1/toolcalls", response_model=Verdict, openapi_extra=_TOOL_CALL_OPENAPI)
async def create_tool_call(request: Request):
    return await _handle_tool_call(request)


@app.post("/api/tool-call", response_model=Verdict, openapi_extra=_TOOL_CALL_OPENAPI, deprecated=True)
async def legacy_tool_call(request: Request):
    """Deprecated alias of POST /v1/toolcalls, kept for existing clients."""
    return await _handle_tool_call(request)


async def _handle_tool_call(request: Request):
    request_id = new_request_id()

    try:
        tool_call = await read_tool_call(request)
    except IngressRejection as rejection:
        quarantined = [
            quarantine_record(a, request_id, rejection.claimed_agent_id, rejection.claimed_tool) for a in rejection.anomalies
        ]
        verdict = decide(
            rejection.claimed_agent_id,
            rejection.claimed_tool,
            [CheckOutcome(CHECK_REQUEST_STRUCTURE, False, rejection.rule_id, rejection.reason, rejection.severity, rejection.stage)],
            DecisionContext(
                request_id=request_id,
                anomalies=tuple({k: v for k, v in r.items() if k not in _LEDGER_ONLY_FIELDS} for r in quarantined),
            ),
        )
        for record in quarantined:
            append_anomaly(record)
        record_audit_event(verdict)
        content = verdict.model_dump(mode="json")
        if rejection.errors:
            content["detail"] = rejection.errors
        return JSONResponse(status_code=rejection.status_code, content=content)

    principal = resolve_principal(tool_call.agent_id)
    try:
        verdict = process_tool_call(tool_call, principal, request_id).verdict
    except Exception:
        # Fail closed: an unexpected error in any check blocks the request.
        _log.exception("Gateway pipeline failed; blocking request %s", request_id)
        verdict = decide(
            principal.agent_id,
            tool_call.tool,
            [CheckOutcome("GATEWAY_INTERNAL", False, "GATEWAY-001", "Internal gateway error; request blocked", Severity.HIGH)],
            DecisionContext(request_id=request_id),
        )
        record_audit_event(verdict, principal)
        return JSONResponse(status_code=500, content=verdict.model_dump(mode="json"))

    record_audit_event(verdict, principal)
    return verdict
