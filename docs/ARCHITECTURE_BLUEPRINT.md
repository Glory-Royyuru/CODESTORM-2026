# Secure Agent Tool Gateway (SATG) — Master Architecture Blueprint

**Classification:** Zero-Trust, Policy-Enforced Runtime Firewall for Autonomous AI Agents  
**Target:** PNC3 Enterprise Agent Security Gateway  
**Document Version:** 2.4.0 (Production Blueprint)

---

## 1. Executive Summary & Core Product Definition

Autonomous AI agents leverage Large Language Models (LLMs) to reason over complex tasks and execute actions across external systems via tools (databases, APIs, email gateways, cloud infrastructure). However, these interactions introduce a fundamentally novel attack surface: untrusted external data (retrieved web pages, customer emails, uploaded documents) can hijack agent reasoning via indirect prompt injection, tool poisoning, parameter smuggling, and covert data exfiltration.

Traditional API gateways and network firewalls cannot differentiate a legitimate tool call from an injection-driven exfiltration attempt because both originate from a valid agent context with valid authentication tokens. Furthermore, using LLMs as security authorization gates introduces probabilistic failure and secondary prompt injection risks.

**SATG solves this problem by enforcing pre-action authorization through a hybrid decision architecture:**
- **Deterministic Rules (authoritative hard vetoes):** Unbypassable schema, manifest, parameter, cryptographic, and network destination checks.
- **Calibrated Behavioral ML (advisory escalation):** A 5-signal behavioral risk pipeline evaluating sequence surprisal, isolation forest anomalies, intent drift, and cumulative shift.
- **Monotonic Security Constraint:** ML models can only **escalate** or **block** a request. They can **NEVER** loosen, override, or downgrade a deterministic rule veto.

---

## 2. The 5 Independent Security Boundaries

Every AI agent tool call must cross five distinct security boundaries before execution and response delivery:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           1. IDENTITY BOUNDARY                              │
│   mTLS 1.3 · SPIFFE/SPIRE Workload Attestation · OAuth 2.0 + DPoP Tokens    │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                      2. DETERMINISTIC POLICY BOUNDARY                       │
│   Strict Ingress · Duplicate-Key Veto · Canonicalization · Tool Manifest    │
│            Parameter Schemas · OPA/Rego Rules · Crypt-Quarantine            │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                 3. BEHAVIORAL RISK & NETWORK/DATA BOUNDARY                  │
│   eTLD+1 Allowlist · DNS Resolve-and-Pin · Cloud Metadata & Deny Ranges     │
│       Behavioral ML Signals · Monotonic Decision Fusion (ALLOW/BLOCK)       │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                        4. EXECUTION SANDBOX BOUNDARY                        │
│   HMAC Request Integrity · Disposable Container · Rootless / Non-Root User │
│         Read-Only Root FS · Network None / Pinned Egress · Caps Dropped     │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                        5. RESPONSE SECURITY BOUNDARY                        │
│   Output DLP Secret Scan (AWS, JWT, PII) · Secondary Injection Detection    │
│             Ed25519-Signed Audit Receipts · SHA-256 Hash Chain              │
└─────────────────────────────────────────────────────────────────────────────┘
```

1. **Identity Boundary:** Establishes cryptographic identity and proof-of-possession. An agent cannot spoof another agent's identity or execute tools outside its role.
2. **Policy Boundary:** Enforces strict JSON parsing, canonicalization, duplicate-key rejection, parameter schemas, tool registration integrity (SHA-256 manifest verification), and crypt-arithmetic quarantine.
3. **Network / Data Boundary:** Evaluates egress destinations against public suffix allowlists, strictly rejects private IP literals and cloud metadata (e.g. `169.254.169.254`), resolves DNS once and pins the IP. Fuses deterministic checks with calibrated behavioral ML risk.
4. **Execution Boundary:** Dispatches approved calls into a disposable, rootless container with dropped Linux capabilities, CPU/memory quotas, read-only filesystem, and HMAC-verified arguments.
5. **Response Boundary:** Scans tool outputs for secret leakage (API keys, private tokens, PII) before returning sanitized data to the agent LLM context, emitting an immutable, Ed25519-signed verdict receipt.

---

## 3. Consolidated 11-Module Specification

| Module | Name | Purpose | Implementation Location |
|---|---|---|---|
| **M1** | **Ingress & Protocol Proxy** | Strict JSON, size ≤ 64 KiB, depth ≤ 8, duplicate-key rejection, crypt-arithmetic quarantine (`CRYPTO-*`). | [`backend/app/gateway/ingress.py`](file:///c:/Users/M%20ABHINAY/CODESTORM-2026/backend/app/gateway/ingress.py), [`crypto_guard.py`](file:///c:/Users/M%20ABHINAY/CODESTORM-2026/backend/app/gateway/crypto_guard.py) |
| **M2** | **Tool Registry & Integrity** | Tool manifests pinned by SHA-256 hash. Freezes/blocks modified tools (rug-pull defense `TOOL-004`). | [`backend/app/gateway/registry.py`](file:///c:/Users/M%20ABHINAY/CODESTORM-2026/backend/app/gateway/registry.py) |
| **M3** | **Deterministic Policy Core** | Single authoritative decision point. Strict parameter schemas, single-line validations (`PARAM-*`). | [`backend/app/gateway/policy_engine.py`](file:///c:/Users/M%20ABHINAY/CODESTORM-2026/backend/app/gateway/policy_engine.py) |
| **M4** | **Provenance & Data-Flow Firewall** | Tracks data origins across session turns (TRUSTED → TAINTED lattice). | Prototyped in [`frontend/src/lib/gateway/taint.ts`](file:///c:/Users/M%20ABHINAY/CODESTORM-2026/frontend/src/lib/gateway/taint.ts) |
| **M5** | **Lethal Trifecta & Egress Firewall** | Vetoes calls when Private Data + Untrusted Content + Outbound Egress meet. Denies private ranges & metadata. | [`backend/app/gateway/network.py`](file:///c:/Users/M%20ABHINAY/CODESTORM-2026/backend/app/gateway/network.py) |
| **M6** | **Behavioral ML Risk Pipeline** | 5 signals (`p_inject`, `p_misaligned`, `anomaly_score`, `sequence_surprisal`, `context_shift`). | [`ml/src/`](file:///c:/Users/M%20ABHINAY/CODESTORM-2026/ml/src/), [`backend/app/ml/`](file:///c:/Users/M%20ABHINAY/CODESTORM-2026/backend/app/ml/) |
| **M7** | **Decision Fusion & Calibration** | Monotone XGBoost + Isotonic calibration. Enforces monotonic severity hierarchy (ALLOW → BLOCK). | [`backend/app/gateway/decision_engine.py`](file:///c:/Users/M%20ABHINAY/CODESTORM-2026/backend/app/gateway/decision_engine.py) |
| **M8** | **Sandboxed Execution Harness** | Disposable Docker container per ALLOW. Non-root user, 256m, 0.5 CPU, `--network none`, no host mounts. | [`sandbox/`](file:///c:/Users/M%20ABHINAY/CODESTORM-2026/sandbox/), [`backend/app/sandbox/`](file:///c:/Users/M%20ABHINAY/CODESTORM-2026/backend/app/sandbox/) |
| **M9** | **Response Security & DLP** | Redacts API keys, passwords, and secondary prompt injections from tool outputs. | Prototyped in [`frontend/src/lib/gateway/dlp.ts`](file:///c:/Users/M%20ABHINAY/CODESTORM-2026/frontend/src/lib/gateway/dlp.ts) |
| **M10** | **Signed Audit Receipts** | Ed25519 signatures, HMAC request tags, and SHA-256 hash chaining for tamper-evident audit records. | [`backend/app/gateway/request_integrity.py`](file:///c:/Users/M%20ABHINAY/CODESTORM-2026/backend/app/gateway/request_integrity.py), [`frontend/src/lib/gateway/receipts.ts`](file:///c:/Users/M%20ABHINAY/CODESTORM-2026/frontend/src/lib/gateway/receipts.ts) |
| **M11** | **Control Plane & UI** | Next.js management console: Live Gateway, Provenance DAG, Registry, Audit Ledger, Eval Lab, Policies. | [`frontend/src/`](file:///c:/Users/M%20ABHINAY/CODESTORM-2026/frontend/src/) |

---

## 4. End-to-End Execution Sequence (15 Steps)

```
[Agent Tool Call Request]
  │
  ├─► Step 1:  TLS / Identity Termination (mTLS & DPoP Verification)
  ├─► Step 2:  Ingress Validation (Size ≤ 64KB, depth ≤ 8, duplicate-key rejection)
  ├─► Step 3:  Crypt-Arithmetic Quarantine (BigInt overflow, degenerate signatures)
  ├─► Step 4:  Canonicalization (NFKC normalization, lone surrogates, request_hash)
  ├─► Step 5:  Tool Registry & Integrity (Pinned SHA-256 manifest hash verification)
  ├─► Step 6:  Agent Capability Check (Role & tool authorization verification)
  ├─► Step 7:  Parameter Schema Validation (Strict type, regex, CRLF rejection)
  ├─► Step 8:  Destination & SSRF Validation (Private IP deny ranges, eTLD+1, DNS pin)
  ├─► Step 9:  Deterministic Policy Decision (Single authoritative ALLOW/BLOCK veto)
  │            └─ If Deterministic BLOCK ───────────► Immediate BLOCK (ML skipped)
  │
  ├─► Step 10: ML Feature Extraction (Causal embeddings, trigrams, CUSUM drift)
  ├─► Step 11: Monotonic Decision Fusion (risk ≥ 0.80 BLOCK; risk ≥ 0.60 ESCALATE)
  │            └─ If ESCALATE or BLOCK ─────────────► Review Queue or Immediate BLOCK
  │
  ├─► Step 12: HMAC Request Integrity Tagging (Cryptographic approved request seal)
  ├─► Step 13: Sandboxed Execution (Disposable rootless Docker container, verified timeout)
  ├─► Step 14: Output DLP & Redaction (Secrets masked, output hashed)
  └─► Step 15: Signed Audit Receipt & Response (SHA-256 chained, immutable log)
```

---

## 5. Technology Stack Summary

- **Gateway Ingress & Policy:** Python 3.14 / FastAPI / Uvicorn (sub-15ms deterministic path)
- **Database (Durable Store):** PostgreSQL 16 (Row-level security, append-only triggers, Alembic)
- **Hot State & Cache:** Redis 7 (sliding-window rate-limiting, session taint state)
- **ML Intelligence:** Sentence-Transformers (MiniLM-L6-v2), Scikit-Learn (IsolationForest, LogisticRegression), XGBoost, Isotonic Calibration
- **Execution Harness:** Docker Engine with Linux containers (`satg-sandbox:0.1`), resource caps, non-root user (65532), `--network none`
- **Control Plane Console:** Next.js 16, React 19, TypeScript, Tailwind CSS, Framer Motion
