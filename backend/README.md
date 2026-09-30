# `backend/` — PNC3 Secure Agent Tool Gateway (FastAPI)

A security gateway that intercepts AI agent tool calls, validates them, and returns an ALLOW/BLOCK verdict before any tool executes.

This directory is the **security authority** of the repository. The console in [`../frontend/`](../frontend/README.md) calls `POST /v1/toolcalls` and `GET /health` through its same-origin Next.js proxy and only displays the verdicts returned here; it makes no security decisions. See the [root README](../README.md) for running both together.

## Current Scope

The gateway implements the deterministic front half of the SATG architecture: strict ingress, canonicalization, the tool registry with manifest integrity, parameter/schema validation, destination (egress) validation, a single deterministic policy decision point, and an audit record for every decision.

**No tool is executed.** The gateway only returns a verdict. Execution, response inspection/DLP, ML scoring, authentication, rate limiting and persistence belong to later work packages.

## Request Flow

```
POST /v1/toolcalls
  → Ingress         strict JSON, size/depth limits, duplicate-key rejection, schema (INGRESS-*)
  → Canonicalize    NFKC normalization, control/invisible character rejection (CANON-*)
  → Registry        registered, manifest intact, enabled, agent authorized (TOOL-*)
  → Parameters      schema from the tool manifest (PARAM-*)
  → Destination     egress declared in the manifest, strict address parsing, allowlist (DEST-*)
  → Policy engine   single ALLOW/BLOCK decision (BASE-001 / POLICY-*)
  → Audit           every decision recorded, including ingress rejections
```

Checks stop at the first failure. An unauthorized caller learns nothing about a tool's schema or destinations, and later checks never run for a request that has already been vetoed. `checks_not_evaluated` lists the checks that were skipped.

## Rule IDs

| Rule | HTTP | Meaning |
|---|---|---|
| INGRESS-001 | 400 | Body is not valid UTF-8 JSON, or contains NaN/Infinity |
| INGRESS-002 | 400 | Duplicate JSON key (at any depth) |
| INGRESS-003 | 413 | Body larger than 64 KiB |
| INGRESS-004 | 400 | JSON nested deeper than 8 levels |
| INGRESS-005 | 422 | Does not match the tool call schema (missing/unknown field, wrong type, invalid identifier) |
| INGRESS-006 | 415 | Content-Type is not `application/json` (UTF-8) |
| CANON-001 | 200 | Control or invisible character (bidi override, zero-width, NUL, ...) |
| CANON-002 | 200 | Invalid Unicode (lone surrogate) |
| CANON-003 | 200 | Value too long after normalization |
| TOOL-001 | 200 | Tool is not registered |
| TOOL-002 | 200 | Tool is disabled |
| TOOL-003 | 200 | Agent is not authorized to use this tool |
| TOOL-004 | 200 | Tool manifest does not match its registered hash |
| PARAM-001 | 200 | Required parameter missing |
| PARAM-002 | 200 | Parameter has the wrong type |
| PARAM-003 | 200 | Unexpected parameter |
| PARAM-004 | 200 | Parameter is empty or whitespace |
| PARAM-005 | 200 | Line break in a single-line parameter (e.g. email header injection) |
| DEST-001 | 200 | Destination domain not in the allowlist |
| DEST-002 | 200 | Destination is not exactly one valid address (lists, multiple `@`, display names, ...) |
| DEST-003 | 200 | Tool declares an egress channel the gateway cannot validate (fail closed) |
| POLICY-001 | 200 | A check failed without its own rule ID |
| POLICY-002 | 200 | No checks were evaluated (fail closed) |
| POLICY-003 | 200 | A planned check was not evaluated (fail closed) |
| GATEWAY-001 | 500 | Internal error; request blocked (fail closed) |
| BASE-001 | 200 | All checks passed — ALLOW |

## Identity

Authentication is not implemented yet. `agent_id` is the caller's **unauthenticated claim**. It is recorded as `auth_method: "self_asserted"`, and `authenticated: false` in the audit log. `context` is carried for reference only and is never used for a security decision. [app/gateway/identity.py](app/gateway/identity.py) is the single place authentication will plug in.

## Tool Manifests

Each tool in [app/gateway/registry.py](app/gateway/registry.py) has one manifest, which is the single source of truth. The manifest holds the name, version, server id, description, parameter schema, allowed agents, enabled state, and security metadata. The security metadata declares the side effect and any caller-chosen egress destination.

The SHA-256 manifest hash covers everything except `enabled` and `allowed_agents`. The hash is pinned at registration, and a manifest that changes after registration is blocked (TOOL-004).

A tool with an egress destination must declare it (`security.egress`). Destination validation is driven by that declaration, not by the tool's name.

## Handoff Contract (for the execution layer)

Internally, `process_tool_call()` returns a `GatewayResult` with the `verdict` and the canonical `envelope`. Anything that executes a tool must:

- act only on `verdict == "ALLOW"` (treat any other value — including the reserved `ESCALATE` — as not allowed);
- use the **canonical** parameters from the envelope, not the raw request (`request_hash` identifies them);
- never use `untrusted_context` for security decisions.

## Project Structure

```
backend/
├── app/
│   ├── main.py                     # FastAPI app: /health, POST /v1/toolcalls (+ legacy /api/tool-call)
│   ├── models/
│   │   ├── tool_call.py            # ToolCall request model (strict)
│   │   ├── envelope.py             # Principal, canonical ToolCallEnvelope, request IDs
│   │   └── verdict.py              # Verdict response model
│   ├── gateway/
│   │   ├── ingress.py              # Strict JSON body reading and limits
│   │   ├── identity.py             # Principal resolution (authentication boundary)
│   │   ├── canonicalizer.py        # Canonical envelope, canonical JSON, SHA-256
│   │   ├── registry.py             # Tool manifests, manifest hashing, permissions
│   │   ├── parameter_validator.py  # Manifest-driven parameter validation
│   │   ├── destination_validator.py  # Egress parsing and allowlists
│   │   ├── policy_engine.py        # Single deterministic decision point
│   │   └── pipeline.py             # Runs the checks in order
│   └── audit/
│       └── logger.py               # Audit events (in memory + JSON log lines)
├── tests/
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

Server runs at `http://127.0.0.1:8000`. Interactive docs: `/docs`.

## Run Tests

```bash
cd backend
python -m pytest
```

## Example Request

```
POST /v1/toolcalls
Content-Type: application/json

{
  "agent_id": "support-bot-3",
  "tool": "send_email",
  "parameters": {
    "to": "user@company.com",
    "subject": "Support",
    "body": "Hello"
  }
}
```

`POST /api/tool-call` is a deprecated alias with identical behavior.

## Example Response

```json
{
  "verdict": "ALLOW",
  "severity": "LOW",
  "agent_id": "support-bot-3",
  "tool": "send_email",
  "rule_id": "BASE-001",
  "reason": "Tool call passed basic gateway validation",
  "stage": "gateway",
  "checks": [
    {"check": "REQUEST_STRUCTURE", "status": "PASSED"},
    {"check": "TOOL_REGISTRY", "status": "PASSED"},
    {"check": "TOOL_ENABLED", "status": "PASSED"},
    {"check": "AGENT_PERMISSION", "status": "PASSED"},
    {"check": "PARAMETER_VALIDATION", "status": "PASSED"},
    {"check": "DESTINATION_VALIDATION", "status": "PASSED"}
  ],
  "checks_not_evaluated": [],
  "request_id": "req_85263221661343d5b32800f17b0a937c",
  "policy_version": "deterministic-core-1.1.0",
  "tool_version": "1.0.0",
  "tool_manifest_hash": "sha256:03717e99...",
  "request_hash": "sha256:c079c942..."
}
```
