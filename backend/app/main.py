from fastapi import FastAPI

from app.audit.logger import record_audit_event
from app.gateway.pipeline import process_tool_call
from app.models.tool_call import ToolCall
from app.models.verdict import Verdict

app = FastAPI(title="PNC3 Secure Agent Tool Gateway")


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/api/tool-call", response_model=Verdict)
def tool_call(request: ToolCall) -> Verdict:
    verdict = process_tool_call(request)
    record_audit_event(verdict)
    return verdict
