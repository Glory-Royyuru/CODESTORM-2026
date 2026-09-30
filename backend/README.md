# PNC3 — Secure Agent Tool Gateway

A security gateway that intercepts AI agent tool calls, validates them, and returns an ALLOW/BLOCK verdict before any tool executes.

## Phase 1 Scope

This phase proves the smallest working end-to-end skeleton: an agent sends a structured tool call to the gateway, the gateway validates the request's basic structure, runs it through a pipeline, returns an ALLOW verdict, and records an audit event.

**Not implemented in this phase:** authentication, database/persistence, frontend, LLM integration, tool/destination allowlists, prompt-injection or DLP detection, risk scoring, rate limiting, or any deployment infrastructure (Docker, etc.). These belong to later phases.

## Project Structure

```
backend/
├── app/
│   ├── main.py            # FastAPI app: /health and POST /api/tool-call
│   ├── models/
│   │   ├── tool_call.py   # ToolCall request model
│   │   └── verdict.py     # Verdict response model
│   ├── gateway/
│   │   └── pipeline.py    # Gateway pipeline: ToolCall -> Verdict
│   └── audit/
│       └── logger.py      # In-memory audit log
├── tests/
│   └── test_gateway.py
├── requirements.txt
└── README.md
```

## Requirements

- Python 3.11+ (tested on 3.13)

## Setup

```bash
cd backend
python -m venv venv
venv\Scripts\activate      # Windows
# source venv/bin/activate # macOS/Linux
pip install -r requirements.txt
```

## Run the Server

```bash
cd backend
uvicorn app.main:app --reload
```

Server runs at `http://127.0.0.1:8000`.

## Run Tests

```bash
cd backend
python -m pytest
```

## Example Request

```
POST /api/tool-call
Content-Type: application/json

{
  "agent_id": "support-bot-3",
  "tool": "send_email",
  "parameters": {
    "to": "user@company.com",
    "subject": "Support",
    "body": "Hello"
  },
  "context": {
    "session_id": "sess-001"
  }
}
```

## Example Response

```json
{
  "verdict": "ALLOW",
  "severity": "LOW",
  "agent_id": "support-bot-3",
  "tool": "send_email",
  "rule_id": "BASE-001",
  "reason": "Tool call passed basic gateway validation",
  "stage": "gateway"
}
```

No tool is actually executed in this phase — the gateway only validates and returns a verdict.
