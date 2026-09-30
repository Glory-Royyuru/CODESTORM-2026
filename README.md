# SATG — Secure Agent Tool Gateway

SATG sits between an AI agent and the tools it can call. Every tool call is sent to the gateway first, checked deterministically, scored by an ML risk model, and answered with **ALLOW**, **ESCALATE** or **BLOCK** **before** any tool runs. Only an ALLOW is executed, in a disposable, network-less Docker container.

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
   Ingress → Quarantine → Canonicalize → Registry → Parameters → Destination
     → Deterministic policy ── BLOCK ──────────────────────────────► BLOCK (ML not consulted, no sandbox)
     → ML risk (ml/ package) → Decision engine ── ESCALATE / BLOCK ─► stop (no sandbox)
                                               └─ ALLOW (HMAC-signed)
                                                    → Sandbox manager → Docker (sandbox/) → tool → result
     → Audit (verdict, ML risk, sandbox status; tool output only as a hash)
```

The console never decides a verdict or computes risk. If the backend is unreachable, the proxy returns `502`/`504` with no verdict and the UI shows a network error; an error can never become an ALLOW.

## Repository layout

| Path | What it is |
| --- | --- |
| [`backend/`](backend/README.md) | FastAPI deterministic gateway (Python). Checks, rule IDs and API contract are documented in its README. |
| [`frontend/`](frontend/README.md) | Next.js console. The **Live Gateway** screen uses the real backend; the other screens are labelled simulations. |
| [`ml/`](ml/README.md) | SATG ML risk package (`satg-ml-v0.1`): training, evaluation, artifacts. The backend uses its inference API. |
| [`sandbox/`](sandbox/Dockerfile) | Docker image for tool execution: a fixed runner that only dispatches registered tools. |
| [`backend/eval/`](backend/eval/attack_lab.py) | Attack lab: security scenarios through the real pipeline; results in `backend/eval/results/`. |

## Run locally

Requirements: Python 3.14 (tested on 3.14.7; 3.11+ should work), Node.js 20.9+ (tested on 24), and Docker (Linux containers; tested on Engine 29.8). Ports: backend `8000`, frontend `3000`.

**Once — build the sandbox image**

```bash
docker build -t satg-sandbox:0.1 sandbox/
```

**Terminal 1 — backend**

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate           # Windows; macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt  # includes the ML inference stack (no torch)
uvicorn app.main:app             # http://127.0.0.1:8000 (API docs: /docs); loads the model at start-up (~10 s)
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
| `SANDBOX_MODE` | backend | `docker` | `docker` runs ALLOWED calls in the sandbox; `off` returns verdicts only. |
| `SANDBOX_IMAGE` · `SANDBOX_MEMORY` · `SANDBOX_CPUS` · `SANDBOX_PIDS_LIMIT` · `SANDBOX_TIMEOUT` | backend | `satg-sandbox:0.1` · `256m` · `0.5` · `64` · `10` s | Container image and limits. `DOCKER_BIN` (default `docker`) and `SANDBOX_MAX_OUTPUT_BYTES` (16384) are also read. |
| `ML_MODE` | backend | `advisory` | `advisory`: ML failure keeps the deterministic decision (the ML contract). `required`: ML failure blocks (`ML-003`). `off`: no ML. |
| `ML_MODEL_PATH` · `ML_MODEL_VERSION` · `ML_PACKAGE_DIR` | backend | `ml/artifacts` · `satg-ml-v0.1` · `ml/` | Model location; a model with another version is refused. |
| `ML_HIGH_RISK_THRESHOLD` · `ML_CRITICAL_RISK_THRESHOLD` | backend | `0.60` · `0.80` | ML risk at or above → `ESCALATE` / `BLOCK`. The defaults are the existing HUMAN_APPROVAL and QUARANTINE levels in `ml/configs/decision_thresholds.json`. |
| `SATG_GATEWAY_HMAC_SECRET` | backend | random per process | Key for the request-integrity HMAC (≥ 32 bytes). |

No external API keys are needed.

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

- **Strict ingress:** `application/json` only, 64 KiB limit, UTF-8, duplicate-key rejection, depth ≤ 8, no NaN/Infinity, strict schema (`INGRESS-*`), plus a crypt-arithmetic quarantine (`CRYPTO-*`).
- **Canonicalization:** NFKC normalization, rejection of control/invisible characters and lone surrogates, a SHA-256 `request_hash` (`CANON-*`).
- **Tool registry:** registration, a pinned manifest hash (tampering is refused), enabled state, per-agent permissions (`TOOL-*`).
- **Parameter validation:** checked against each tool's manifest (`PARAM-*`).
- **Destination validation:** strict email parsing and allowlists; URL egress with IPv4/IPv6 deny ranges, eTLD+1 allowlist and DNS pinning (`DEST-*`).
- **Deterministic policy decision:** fail-closed (`BASE-001`, `POLICY-*`, `GATEWAY-001`).
- **ML risk assessment** ([`backend/app/ml/`](backend/app/ml/)): the `ml/` package scores every deterministically allowed call and returns calibrated risk, level, signals and XGBoost feature contributions. The decision engine can escalate (`ML-001`) or block (`ML-002`), and never relaxes a deterministic BLOCK.
- **Docker sandbox** ([`backend/app/sandbox/`](backend/app/sandbox/), [`sandbox/`](sandbox/)): one disposable container per ALLOW, run with `--rm`, `--network none`, `--read-only`, `--cap-drop ALL`, `no-new-privileges`, 256 MiB, 0.5 CPU, 64 pids, user 65532, no mounts, a timeout, and verified cleanup. The container only receives canonical parameters whose HMAC and `request_hash` verify. If Docker is unavailable, the call fails and is never run on the host.
- **Audit:** every decision with its ML model version, risk, level and factors, the decision trace, and the sandbox status, exit code and duration. Tool output is recorded as a SHA-256 hash only.

In the frontend:

- The **Live Gateway** screen, which uses the real backend and shows the ML risk, the decision trace and the sandbox result.
- A backend health indicator.

**Simulations (in-browser demo engine, not authoritative, labelled in the UI):**

- Provenance DAG, Tool Registry, Audit Ledger, Eval Lab, Policies, Approvals, the Docs module overview, and the header kill switch.
- Their ML, sandbox, DLP and receipt features are illustrations. The real ML and sandbox are the backend ones above, and the attack lab (`python -m eval.attack_lab`) exercises them.

## Current limitations

- **No authentication:** `agent_id` is self-asserted. The ML context (`task`, `observation`, `previous_steps`) is also caller-supplied: a lying caller can evade an ML escalation, but can never unlock something the deterministic policy blocks.
- **The ML model is out of distribution for these tools.** It was trained on AgentDrift trajectories (synthetic, Llama-generated), not on this gateway's tools. The single-step prompt-injection scenario scores 0.595 and is **allowed** (it then runs harmlessly in the sandbox). See the attack lab results and `ml/README.md` §14 (the step-position artifact).
- **ML latency:** about 5–25 ms per call when warm here, but up to about 350 ms with long histories on CPU. Loading takes about 10 s.
- **Sandbox tools are fixtures:** the tools read synthetic data baked into the image. The container has no network, so `send_email` renders but does not send, and `fetch_url` reports `network_unavailable`. There is no response DLP.
- **No deterministic lethal-trifecta rule in the backend:** it would need trusted session state. The multi-step chain is currently caught by the ML layer (`ML-002`).
- **Audit storage:** records are in memory and on stdout only.
- **No rate limiting or kill switch in the backend.**

## ML integration

`ml/` was merged from the `ml-model` branch. The backend loads it once per process ([`backend/app/ml/model_loader.py`](backend/app/ml/model_loader.py)) and builds its `MLRequest` deterministically from the canonical envelope ([`feature_extractor.py`](backend/app/ml/feature_extractor.py)). Training needs `ml/requirements.txt` (torch) and the AgentDrift dataset (a git submodule under `ml/data/raw/`, not checked out). Inference does not need either.

## Development and testing

```bash
# backend (from backend/)
python -m pytest -q                  # 281 tests; Docker tests are marked `docker` and skip without a daemon
python -m pytest -q -m "not docker"  # unit tests only
python -m eval.attack_lab            # attack lab through the real pipeline (exit 1 on any mismatch)

# ML package (from ml/)
python -m pytest -q                  # 3 embedding tests need torch (ml/requirements.txt)
python evaluate.py                   # needs the AgentDrift dataset

# frontend (from frontend/)
npm run lint
npx next typegen && npx tsc --noEmit   # typegen creates Next route types on a fresh clone
npm run build
npm run check:engine             # demo engine sanity check
npm run check:bench              # demo engine benchmark suites
npm run check:network            # demo engine network / quarantine checks
```
