# SATG — Secure Agent Tool Gateway

SATG sits between an AI agent and the tools it can call. Every tool call is sent to the gateway first, checked deterministically, and answered with an **ALLOW** or **BLOCK** verdict **before** any tool runs.

**Why:** an agent that reads untrusted content (web pages, emails, documents) can be manipulated into calling tools with attacker-chosen arguments: emailing data to an outside domain, injecting email headers, calling tools it was never granted, or smuggling invisible Unicode past reviewers. SATG enforces what each agent may call and with which arguments, independently of what the model was told.

## Architecture

```
Browser (console)
   │  POST /api/satg/v1/toolcalls              same origin, raw body
   ▼
frontend/  Next.js route handler (proxy)       forwards bytes + status unchanged
   │  POST /v1/toolcalls                        SATG_BACKEND_URL (default http://127.0.0.1:8000)
   ▼
backend/   FastAPI SATG gateway                 the only security authority
   Ingress → Canonicalize → Registry → Parameters → Destination → Policy decision → Audit
   ▼
Verdict (ALLOW / BLOCK) — no tool is executed
```

The console never decides a verdict. If the backend is unreachable, the proxy returns `502`/`504` with no verdict and the UI shows a network error; an error can never become an ALLOW.

## Repository layout

| Path | What it is |
| --- | --- |
| [`backend/`](backend/README.md) | FastAPI deterministic gateway (Python). Checks, rule IDs and API contract are documented in its README. |
| [`frontend/`](frontend/README.md) | Next.js console. The **Live Gateway** screen uses the real backend; the other screens are labelled simulations. |

## Run locally

Requirements: Python 3.11+ (tested on 3.13) and Node.js 20.9+ (tested on 24). Ports: backend `8000`, frontend `3000`.

**Terminal 1 — backend**

```bash
cd backend
python -m venv venv
venv\Scripts\activate            # Windows; macOS/Linux: source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload    # http://127.0.0.1:8000  (API docs: /docs)
```

**Terminal 2 — frontend**

```bash
cd frontend
npm install
npm run dev                      # http://localhost:3000
```

### Configuration

| Variable | Where | Default | Purpose |
| --- | --- | --- | --- |
| `SATG_BACKEND_URL` | frontend (server-side only) | `http://127.0.0.1:8000` | Where the Next.js proxy forwards requests. Set it in `frontend/.env.local` (see `frontend/.env.example`). |

The backend reads no environment variables. No secrets or API keys are needed.

## Verify the live gateway

In the browser, open http://localhost:3000. The header should show **Backend online**. Pick an example request and press **Send Through Gateway**:

- **Email to an allow-listed domain** → `ALLOW · BASE-001`, with request ID, request hash and manifest hash.
- **Recipient outside the allowlist** → `BLOCK · DEST-001`.
- **Duplicate JSON key** → `BLOCK · INGRESS-002` (HTTP 400).
- Stop the backend and send again → **NETWORK ERROR**, no verdict; the header shows **Backend offline**.

From a terminal, through the same proxy:

```bash
curl -X POST http://localhost:3000/api/satg/v1/toolcalls -H "Content-Type: application/json" \
  -d '{"agent_id":"support-bot-3","tool":"send_email","parameters":{"to":"user@company.com","subject":"Hi","body":"Hello"}}'
# → "verdict": "ALLOW", "rule_id": "BASE-001"
```

Change `to` to `user@evil.example` to get `BLOCK` / `DEST-001`.

## What is implemented

In the backend, and therefore authoritative:

- **Strict ingress:** `application/json` only, 64 KiB limit, UTF-8, duplicate-key rejection, depth ≤ 8, no NaN/Infinity, strict schema (`INGRESS-*`).
- **Canonicalization:** NFKC normalization, rejection of control/invisible characters and lone surrogates, a SHA-256 `request_hash` (`CANON-*`).
- **Tool registry:** registration, a pinned manifest hash (tampering is refused), enabled state, per-agent permissions (`TOOL-*`).
- **Parameter validation:** checked against each tool's manifest (`PARAM-*`).
- **Destination validation:** strict email parsing and a domain allowlist (`DEST-*`).
- **One deterministic policy decision point:** fail-closed (`BASE-001`, `POLICY-*`, `GATEWAY-001`).
- **Audit:** an audit record for every decision, including rejections.

In the frontend:

- The **Live Gateway** screen, which uses the real backend.
- A backend health indicator.

**Simulations (in-browser demo engine, not authoritative, labelled in the UI):**

- Provenance DAG, Tool Registry, Audit Ledger, Eval Lab, Policies, Approvals, the Docs module overview, and the header kill switch.
- They illustrate the planned modules: taint tracking, ML scoring, decision fusion, sandbox, DLP and Ed25519 receipts. None of these exist in the backend yet.

## Current limitations

- **No authentication:** `agent_id` is self-asserted (`auth_method: "self_asserted"` in the audit record).
- **No tool execution:** the gateway returns verdicts only; there is no sandbox and no response DLP.
- **Fixed registry:** four demo tools are defined in code (`backend/app/gateway/registry.py`), and only the `email` egress channel has a destination validator.
- **Audit storage:** records are in memory and on stdout; there is no persistence and no read API, so the console shows only the responses it received itself.
- **No rate limiting or kill switch in the backend.**
- **`ESCALATE`:** reserved in the verdict model, but the backend never emits it yet.

## ML integration

The ML work lives on the `ml-model` branch as a top-level `ml/` directory and has not been merged yet.

- **Where it plugs in:** the backend pipeline (`backend/app/gateway/pipeline.py` → `policy_engine.py`), after the deterministic checks.
- **Authority:** deterministic checks stay authoritative. A deterministic BLOCK must stay a BLOCK.
- **Escalation:** the verdict model already reserves `ESCALATE` for a "hold" outcome. The frontend client already accepts `ESCALATE` and treats it as not allowed.
- **Frontend demo code:** `frontend/src/lib/gateway/ml.ts` belongs to the demo engine. It is not the integration point.

## Development and testing

```bash
# backend (from backend/)
python -m pytest -q              # 140 tests

# frontend (from frontend/)
npm run lint
npx next typegen && npx tsc --noEmit   # typegen creates Next route types on a fresh clone
npm run build
npm run check:engine             # demo engine sanity check
npm run check:bench              # demo engine benchmark suites
```
