# `backend/` — PNC3 Secure Agent Tool Gateway (FastAPI)

A security gateway that intercepts AI agent tool calls, validates them, scores them with an ML risk model, and returns an ALLOW / ESCALATE / BLOCK verdict before any tool executes. Only an ALLOW is executed, in a disposable Docker sandbox.

This directory is the **security authority** of the repository. The console in [`../frontend/`](../frontend/README.md) calls `POST /v1/toolcalls` and `GET /health` through its same-origin Next.js proxy and only displays the verdicts returned here; it makes no security decisions. See the [root README](../README.md) for running both together.

## Current Scope

The gateway implements the deterministic front half of the SATG architecture: strict ingress, canonicalization, the tool registry with manifest integrity, parameter/schema validation, destination (egress) validation, a single deterministic policy decision point, and an audit record for every decision.

**Only a final ALLOW is executed**, in a disposable Docker container (see *Sandbox*). BLOCK and ESCALATE never start a container. Response inspection/DLP, authentication, rate limiting and persistence belong to later work packages.

## Request Flow

```
POST /v1/toolcalls
  → Ingress         strict JSON, size/depth limits, duplicate-key rejection (INGRESS-*)
  → Quarantine      crypt-arithmetic guard before schema validation (CRYPTO-*), then schema (INGRESS-005)
  → Canonicalize    NFKC normalization, control/invisible character rejection (CANON-*)
  → Registry        registered, manifest intact, enabled, agent authorized (TOOL-*)
  → Parameters      schema from the tool manifest (PARAM-*)
  → Destination     egress declared in the manifest, strict address parsing, allowlist;
                    URL egress: IPv4/IPv6 deny ranges, eTLD+1 allowlist, DNS resolve-once-and-pin (DEST-*)
  → Policy engine   single deterministic ALLOW/BLOCK decision (BASE-001 / POLICY-*)
  → ML risk         only for a deterministic ALLOW: ml/ package risk score (can only make the decision stricter)
  → Decision        deterministic BLOCK stays BLOCK; ML may escalate to ESCALATE / BLOCK (ML-*)
  → Integrity       ALLOW verdicts carry an HMAC-SHA256 tag over the approved request
  → Sandbox         final ALLOW only: HMAC + request_hash verified, then one disposable container
  → Audit           every decision recorded, including ingress rejections; anomalies to the anomaly ledger
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
| DEST-004 | 200 | SSRF: URL host is a local name, or an IP literal / DNS answer in a denied range |
| DEST-005 | 200 | URL host could not be resolved (fail closed) |
| DEST-006 | 200 | URL scheme is not `https` |
| CRYPTO-001 | 400 | ARITHMETIC_INTEGER_OVERFLOW: numeric literal over 256 bits, or a float that overflows |
| CRYPTO-002 | 400 | MALFORMED_BIGINT: integer outside the IEEE-754 safe range (send it as a decimal string) |
| CRYPTO-003 | 400 | NON_CANONICAL_ENCODING: non-canonical hex/Base64, or homoglyphs in a crypto field name/value |
| CRYPTO-004 | 400 | CORRUPT_CRYPTO_TOKEN: wrong length, invalid curve point, all-zero nonce, CRC-32 mismatch |
| CRYPTO-005 | 400 | SIGNATURE_VERIFICATION_FAILURE: all-zero, degenerate, or malleable (S ≥ ℓ) signature |
| CRYPTO-006 | 400 | DPOP_PROOF_TAMPERING: DPoP proof not a valid RFC 9449 structure (alg `none`/HS*, private JWK, ...) |
| ML-001 | 200 | ESCALATE: ML risk ≥ `ML_HIGH_RISK_THRESHOLD`; held for review, not executed |
| ML-002 | 200 | BLOCK: ML risk ≥ `ML_CRITICAL_RISK_THRESHOLD` |
| ML-003 | 200 | BLOCK: `ML_MODE=required` and the model is unavailable or failed (fail closed) |
| POLICY-001 | 200 | A check failed without its own rule ID |
| POLICY-002 | 200 | No checks were evaluated (fail closed) |
| POLICY-003 | 200 | A planned check was not evaluated (fail closed) |
| GATEWAY-001 | 500 | Internal error; request blocked (fail closed) |
| BASE-001 | 200 | All checks passed — ALLOW |

## Network Boundary (URL egress)

A tool whose manifest declares `egress.channel = "https"` (e.g. `fetch_url`) has each destination checked by [app/gateway/network.py](app/gateway/network.py), in order:

1. strict URL parse: ASCII only, no userinfo, port 443 only, dotted-quad IPv4 only (integer/octal/hex forms such as `2852039166` are refused as ambiguous);
2. `https` only;
3. local names (`localhost`, `*.internal`, `*.local`, ...) are refused;
4. IP literals are checked against the deny ranges: loopback `127.0.0.0/8`, `::1`; zero `0.0.0.0/8`, `::`; RFC 1918; link-local and cloud metadata `169.254.0.0/16`, `fe80::/10`; unique local `fc00::/7`; multicast/broadcast `224.0.0.0/4`, `ff00::/8`, `255.255.255.255`. IPv4-mapped IPv6 is checked as IPv4;
5. the registrable domain (eTLD+1) must be on the allowlist; an unknown public suffix fails closed;
6. the name is resolved **once**; every answer must pass the deny ranges, and the first answer is pinned.

The verdict's `network` field reports every check (PASSED / BLOCKED / NOT_EVALUATED), the resolved IPs and the pinned IP. The execution layer must connect to `pinned_ip` (sending the hostname as SNI/Host) and never resolve the name again, otherwise DNS rebinding could swap in a private address.

## Crypt-Arithmetic Quarantine

[app/gateway/crypto_guard.py](app/gateway/crypto_guard.py) runs inside ingress, before the request becomes a typed ToolCall:

- numeric literals are intercepted by the JSON parser's `parse_int`/`parse_float` hooks and are never converted if they are too large. This avoids truncation, and Python's 4300-digit conversion limit is never reached;
- values of cryptographic fields in `parameters` (signature, nonce, DPoP, HMAC/MAC, CRC, public key, digest) must be canonically encoded and structurally possible. Field names that only *look* like these (homoglyphs) count as smuggling. `context` is not scanned, since it never drives a decision.

The checks are structural. The gateway holds no signer keys, so it refuses values that no valid signature, point or proof could have. It does not verify signatures.

Every anomaly goes to the append-only anomaly ledger ([app/audit/anomaly_ledger.py](app/audit/anomaly_ledger.py)) as a quarantine envelope: a SHA-256 fingerprint and at most 64 bytes of hex. The raw value is never stored or logged. The verdict carries the same envelopes in `anomalies`. The most severe anomaly (first on ties) sets the rule ID. `mitigation_action` is the recommended follow-up; the gateway itself always blocks.

## Request Integrity

Identity (who is calling) and request integrity (what was approved) are separate. Every ALLOW carries `request_integrity`, an HMAC-SHA256 tag over `request_id`, `agent_id`, `tool`, `request_hash`, `tool_manifest_hash`, `policy_version` and the pinned IPs ([app/gateway/request_integrity.py](app/gateway/request_integrity.py)). The execution layer recomputes it with `verify_request_integrity()` and must refuse the call if the tag is missing or differs. Set `SATG_GATEWAY_HMAC_SECRET` (≥ 32 bytes) to share the key with the execution layer. Without it, a random per-process key is used.

## ML Risk Layer

[app/ml/](app/ml/) connects the gateway to the ML package in [`../ml/`](../ml/README.md) (`satg-ml-v0.1`): MiniLM + LogisticRegression, IsolationForest, a trigram model and CUSUM, fused by a monotone XGBoost with isotonic calibration. It was trained on AgentDrift.

- **Loading:** [`model_loader.py`](app/ml/model_loader.py) loads the model once per process (at start-up, about 10 s) through the package's own API. A model with a different version than `ML_MODEL_VERSION` is refused. A failed load is remembered, not retried on every request.
- **Input:** [`feature_extractor.py`](app/ml/feature_extractor.py) builds the `MLRequest` deterministically: canonical tool and parameters, the registry description, the egress allowlists as known domains, and optional caller context (`context.task`, `context.observation`, `context.previous_steps`). The context is unauthenticated, but ML can only restrict.
- **Output (`verdict.ml`):** `risk_score` (calibrated `fused_risk`), `risk_level` (from `ml/configs/decision_thresholds.json`), `prediction` (at 0.5), the five signals, the 11 numeric fusion features, and `top_factors` (XGBoost contributions). No request text is echoed.
- **Decision ([`decision_engine.py`](app/gateway/decision_engine.py)):** deterministic BLOCK → BLOCK, and ML is not consulted. Otherwise risk ≥ critical (0.80) → BLOCK `ML-002`, risk ≥ high (0.60) → ESCALATE `ML-001`, else ALLOW. `verdict.decision` records the deterministic result, the thresholds and the final result.
- **Failure:** by default (`ML_MODE=required`), an unavailable model, a failed inference or a timed-out inference blocks a deterministic ALLOW (`ML-003`, fail closed). `ML_MODE=advisory` keeps the deterministic decision instead, which is the behaviour the ML integration contract (§1.4) describes; `ML_MODE=off` does not consult ML. Either way the failure is reported in `verdict.ml.status` (`unavailable` / `error`) and `verdict.ml.detail`, not hidden. A deterministic BLOCK is never changed by any mode.
- **Timeout:** each prediction runs on one dedicated worker thread and the request stops waiting after `ML_TIMEOUT_SECONDS` (default 3 s; measured on the development machine: about 0.07–0.27 s for typical calls, under 1 s near the 64 KiB body limit). A timeout is reported as `ml.status = "error"` with `detail: "inference timed out after …s"`. Model loading is not timed. Python cannot stop a running thread, so a stuck prediction keeps that worker busy until it returns; calls queued behind it time out as well (and are blocked under `ML_MODE=required`) instead of hanging.

## Sandbox

[app/sandbox/](app/sandbox/) runs a final ALLOW in the image built from [`../sandbox/`](../sandbox/Dockerfile).

- **Manager ([`manager.py`](app/sandbox/manager.py)):** it refuses (`not_executed` / `integrity_failed`) unless the verdict is ALLOW, its HMAC tag verifies, the envelope's canonical parameters reproduce `request_hash`, and the tool is registered and enabled. The container receives only `{tool, canonical arguments, pinned IPs}` on stdin.
- **Runner ([`docker_runner.py`](app/sandbox/docker_runner.py)):** the docker CLI with an argument list, never a shell: `--rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --memory 256m --memory-swap 256m --cpus 0.5 --pids-limit 64 --user 65532:65532 --ipc none --pull never`, with no mounts. On timeout the container is force-removed, and removal is verified (`container_removed`).
- **In the container ([`../sandbox/runner.py`](../sandbox/runner.py)):** a fixed entrypoint runs one registered tool from a static table, re-checks its argument schema, and uses read-only synthetic fixtures. Unknown tools or bad arguments exit 2. It never evaluates input, runs a shell, or resolves DNS.
- **`verdict.execution`:** `sandbox_id`, `status` (`success`, `tool_error`, `rejected`, `timeout`, `killed`, `sandbox_unavailable`, `integrity_failed`, `error`, `not_executed`), `exit_code`, `duration_ms`, `stdout`/`stderr` (capped), the parsed `result`, `error` and `container_removed`. The audit log keeps only a hash and size of the output.
- **Docker unavailable:** the result is `sandbox_unavailable`. There is no host fallback.

## Configuration

All settings are environment variables with built-in defaults ([app/config.py](app/config.py)); an invalid value stops start-up. [`.env.example`](.env.example) lists every variable the code reads, with its default. **The backend does not load `.env` files**: export the variables in the shell that runs uvicorn.

| Variable | Default | Meaning |
|---|---|---|
| `ML_MODE` | `required` | `required`: ML failure/timeout → BLOCK `ML-003`; `advisory`: deterministic decision stands; `off`: ML not consulted |
| `ML_TIMEOUT_SECONDS` | `3.0` | Bound on one prediction (0.1–30) |
| `ML_HIGH_RISK_THRESHOLD` / `ML_CRITICAL_RISK_THRESHOLD` | `0.60` / `0.80` | ESCALATE (`ML-001`) / BLOCK (`ML-002`) |
| `ML_PACKAGE_DIR` / `ML_MODEL_PATH` | `../ml` / `../ml/artifacts` | ML package and artifacts |
| `ML_MODEL_VERSION` | `satg-ml-v0.1` | The loaded model must report exactly this version |
| `SANDBOX_MODE` | `docker` | `docker`: run each final ALLOW in a container; `off`: verdict only, nothing executed |
| `SANDBOX_IMAGE` | `satg-sandbox:0.1` | Locally built image (`--pull never`) |
| `SANDBOX_MEMORY` / `SANDBOX_CPUS` / `SANDBOX_PIDS_LIMIT` | `256m` / `0.5` / `64` | Container limits |
| `SANDBOX_TIMEOUT` | `10` | Seconds per container run, start-up included (1–120) |
| `SANDBOX_MAX_OUTPUT_BYTES` | `16384` | Cap on stdout/stderr returned |
| `DOCKER_BIN` | `docker` | Docker CLI |
| `SATG_GATEWAY_HMAC_SECRET` | random per process | HMAC key for `request_integrity` (≥ 32 bytes) |

The console's proxy waits up to 25 s for a verdict ([`../frontend/src/lib/satg/proxy.ts`](../frontend/src/lib/satg/proxy.ts)): DNS pinning (2 s) + `ML_TIMEOUT_SECONDS` (3 s) + `SANDBOX_TIMEOUT` (10 s) + container clean-up and margin. Raise it if you raise those.

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
│   │   ├── network.py              # URL egress: deny ranges, eTLD+1 allowlist, DNS pinning
│   │   ├── crypto_guard.py         # Crypt-arithmetic quarantine guard
│   │   ├── request_integrity.py    # HMAC-SHA256 request-integrity tags
│   │   ├── decision_engine.py      # deterministic verdict + ML risk -> final verdict
│   │   ├── policy_engine.py        # Single deterministic decision point
│   │   └── pipeline.py             # Runs the checks in order
│   ├── config.py                   # all SANDBOX_* / ML_* settings
│   ├── ml/                         # feature_extractor, model_loader, predictor (MLRiskEngine)
│   ├── sandbox/                    # manager (preconditions), docker_runner (hardened docker run)
│   └── audit/
│       ├── logger.py               # Audit events (in memory + JSON log lines)
│       └── anomaly_ledger.py       # Append-only quarantine envelopes (in memory)
├── tests/
├── requirements.txt
└── README.md
```

## Requirements

- Python 3.13 (verified on 3.13.2, Windows 11, including a fresh virtual environment built from `requirements-dev.txt`). The ML package's authors report 3.14 as well; that was not re-verified here. The ML inference stack (numpy, scikit-learn 1.9.0, xgboost, onnxruntime, transformers/tokenizers, no torch) installs from wheels. scikit-learn is pinned to the version the model artifacts were pickled with.
- `requirements.txt` holds the runtime (gateway + ML inference); `requirements-dev.txt` adds the test tools (pytest, httpx). Training the model needs [`../ml/requirements.txt`](../ml/requirements.txt).
- Docker with Linux containers, and the image built once: `docker build -t satg-sandbox:0.1 ../sandbox`

## Setup

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate      # Windows
# source .venv/bin/activate # macOS/Linux
pip install -r requirements-dev.txt   # or requirements.txt to run without tests
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
python -m pytest                 # all 294 tests: 278 unit/integration + 16 Docker security tests (these skip without a daemon)
python -m pytest -m "not docker"
python -m eval.attack_lab        # scenarios through the real pipeline -> eval/results/
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
  "policy_version": "deterministic-core-1.2.0",
  "tool_version": "1.0.0",
  "tool_manifest_hash": "sha256:03717e99...",
  "request_hash": "sha256:c079c942..."
}
```
