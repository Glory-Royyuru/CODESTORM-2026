# SATG — Secure Agent Tool Gateway

> **A Zero-Trust Runtime Firewall, Data Provenance Engine, and Calibrated Behavioral ML Guardrail for Autonomous AI Agents.**

[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Next.js](https://img.shields.io/badge/Next.js-16.3-black?logo=next.js&logoColor=white)](https://nextjs.org)
[![Python](https://img.shields.io/badge/Python-3.14-3776AB?logo=python&logoColor=white)](https://python.org)
[![Docker](https://img.shields.io/badge/Docker-Sandbox-2496ED?logo=docker&logoColor=white)](https://docker.com)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-336791?logo=postgresql&logoColor=white)](https://postgresql.org)
[![Redis](https://img.shields.io/badge/Redis-7-DC382D?logo=redis&logoColor=white)](https://redis.io)

SATG sits synchronously between autonomous AI agents and external tools (databases, APIs, web endpoints, email servers). Every tool call is intercepted, checked deterministically, scored by an ML risk pipeline, and answered with **ALLOW**, **ESCALATE**, or **BLOCK** **before** any tool executes. Approved calls execute inside a disposable, network-less Docker sandbox.

---

## 📌 Architecture Documentation

Comprehensive architecture specifications are documented in the [`docs/`](docs/) directory:

- 🏛️ **[Master Architecture Blueprint](docs/ARCHITECTURE_BLUEPRINT.md)**: Zero-trust paradigm, 5 independent security boundaries, 11 functional modules, and system topography.
- 📋 **[Phase-by-Phase Technical Implementation Specification](docs/PHASE_IMPLEMENTATION_SPECIFICATION.md)**: Detailed breakdown of all 15 implementation phases, data contracts, guardrails, and rule IDs.

---

## 🛡️ The 5-Layer Security Architecture

```
Browser / Agent Caller
   │  POST /v1/toolcalls (via Next.js Same-Origin Proxy)
   ▼
[1. IDENTITY BOUNDARY] ─────────────── mTLS 1.3 · OAuth 2.0 / DPoP · SPIFFE/SPIRE Attestation
   │
[2. POLICY BOUNDARY] ───────────────── Ingress (size/depth/duplicate-keys) · Crypt-Arithmetic Quarantine
   │                                   NFKC Canonicalization · Tool Manifest SHA-256 Check
   │                                   Parameter Validation · Deterministic Policy Veto
   ├─► [BLOCK] ───────────────────────► Immediate Veto (ML skipped, sandbox never reached)
   ▼
[3. BEHAVIORAL ML & NETWORK] ───────── URL Egress (eTLD+1 allowlist, private IP deny, DNS pinning)
   │                                   ML Risk Pipeline (MiniLM embeddings, IsolationForest, CUSUM drift)
   │                                   Monotonic Decision Fusion (risk ≥ 0.80 BLOCK; risk ≥ 0.60 ESCALATE)
   ├─► [ESCALATE / BLOCK] ────────────► Review Queue / Immediate Veto (sandbox never reached)
   ▼
[4. EXECUTION SANDBOX BOUNDARY] ────── HMAC-SHA256 Approved Request Integrity Check
   │                                   Disposable Rootless Docker Sandbox (satg-sandbox:0.1)
   │                                   --network none · --read-only · --cap-drop ALL · 256m RAM · 0.5 CPU
   ▼
[5. RESPONSE SECURITY & AUDIT] ─────── Output Redaction (Secret/DLP filtering) · Output Hash
                                       Cryptographic Ed25519-Signed Receipts · SHA-256 Hash Chaining
```

### The Monotonic Security Invariant
Deterministic rules maintain absolute authority. ML risk pipeline models operate exclusively in an advisory and escalation capacity:
$$\text{FinalVerdict} = \max(\text{DeterministicRuleVerdict}, \text{MLVerdict})$$
Under no circumstances can an ML model convert a `BLOCK` into an `ALLOW`.

---

## 📂 Repository Layout

```
CODESTORM-2026/
├── backend/                       # FastAPI Deterministic Gateway & Security Authority
│   ├── app/
│   │   ├── main.py                # FastAPI entry point: /v1/toolcalls, /health
│   │   ├── gateway/               # Ingress, canonicalizer, registry, policy engine, network
│   │   ├── ml/                    # ML risk engine loader, feature extractor, predictor
│   │   ├── sandbox/               # Docker sandbox manager and hardened CLI runner
│   │   └── audit/                 # Audit logging and crypt-quarantine anomaly ledger
│   ├── eval/                      # Security attack lab (15 scenarios through real pipeline)
│   ├── tests/                     # 281 tests (265 unit/integration + 16 Docker isolation tests)
│   └── requirements.txt
├── frontend/                      # Next.js 16 Console (Tailwind CSS, Framer Motion)
│   ├── src/app/                   # App router pages: /, /audit, /provenance, /registry, /eval-lab
│   ├── src/components/            # Visual console panels, live gateway form, graph visualizers
│   └── src/lib/gateway/           # In-browser reference simulation engine & benchmark suites
├── ml/                            # Behavioral ML Package (satg-ml-v0.1)
│   ├── src/                       # Text cleaning, causal feature pipeline, component models
│   ├── artifacts/                 # Serialized model weights (XGBoost, IsolationForest, MiniLM)
│   ├── train.py                   # Model training and calibration pipeline
│   └── evaluate.py                # Evaluation on task-disjoint AgentDrift splits
├── sandbox/                       # Hardened Tool Execution Sandbox
│   ├── Dockerfile                 # Rootless, non-root user (65532), zero-package attack surface
│   └── runner.py                  # Fixed tool dispatcher with HMAC parameter verification
└── docs/                          # Architecture Specifications
    ├── ARCHITECTURE_BLUEPRINT.md
    └── PHASE_IMPLEMENTATION_SPECIFICATION.md
```

---

## 🚀 Quickstart Guide

### Prerequisites
- **Python:** 3.14 (3.11+ compatible)
- **Node.js:** 20.9+ (tested on Node 24)
- **Docker:** Engine with Linux containers running

### 1. Start Infrastructure (PostgreSQL 16 & Redis via Docker)

```bash
# Start PostgreSQL 16
docker run -d --name satg-postgres -e POSTGRES_USER=satg -e POSTGRES_PASSWORD=satg -e POSTGRES_DB=satg -p 5432:5432 postgres:16

# Start Redis 7
docker run -d --name satg-redis -p 6379:6379 redis:latest

# Build the sandbox execution image
docker build -t satg-sandbox:0.1 sandbox/
```

### 2. Start Backend (FastAPI Gateway)

```bash
cd backend
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```
> The backend runs at **`http://127.0.0.1:8000`** (Swagger docs at **`/docs`**).

### 3. Start Frontend (Next.js Web Console)

```bash
cd frontend
npm install
npm run dev
```
> The console runs at **`http://localhost:3000`**.

---

## 🧪 Testing & Verification

### Backend Tests & Docker Security Tests
```bash
cd backend
# 1. Run all unit and deterministic policy tests (265 passed)
python -m pytest -q -m "not docker"

# 2. Run the 16 hardened Docker security isolation tests
python -m pytest -q -m "docker"

# 3. Run the security attack lab (exercises 15 attack scenarios)
python -m eval.attack_lab
```

### Attack Lab Results (15 Real Pipeline Scenarios)

| Scenario | Category | Expected | Actual | Rule ID | Execution | Status |
|---|---|---|---|---|---|---|
| `benign-weather` | Benign | ALLOW | ALLOW | `BASE-001` | Success (Sandbox) | ✅ PASS |
| `benign-customer` | Benign | ALLOW | ALLOW | `BASE-001` | Success (Sandbox) | ✅ PASS |
| `benign-email` | Benign | ALLOW | ALLOW | `BASE-001` | Success (Sandbox) | ✅ PASS |
| `lethal-trifecta` | Exfiltration | BLOCK | BLOCK | `ML-002` | Not reached | ✅ PASS |
| `exfil-external` | Exfiltration | BLOCK | BLOCK | `DEST-001` | Not reached | ✅ PASS |
| `ssrf-metadata` | SSRF | BLOCK | BLOCK | `DEST-004` | Not reached | ✅ PASS |
| `ssrf-integer-ip` | SSRF | BLOCK | BLOCK | `DEST-002` | Not reached | ✅ PASS |
| `ssrf-localhost` | SSRF | BLOCK | BLOCK | `DEST-004` | Not reached | ✅ PASS |
| `credential-misuse`| Permissions | BLOCK | BLOCK | `TOOL-003` | Not reached | ✅ PASS |
| `disabled-destructive`| Integrity | BLOCK | BLOCK | `TOOL-002` | Not reached | ✅ PASS |
| `header-injection` | Smuggling | BLOCK | BLOCK | `PARAM-005` | Not reached | ✅ PASS |
| `zero-width` | Smuggling | BLOCK | BLOCK | `CANON-001` | Not reached | ✅ PASS |
| `crypto-tampering` | Quarantine | BLOCK | BLOCK | `CRYPTO-001` | Not reached | ✅ PASS |
| `duplicate-key` | Ingress | BLOCK | BLOCK | `INGRESS-002` | Not reached | ✅ PASS |
| `prompt-injection-1step` | Injection | ESCALATE | ALLOW | `BASE-001` | Success (Sandbox) | ⚠️ Missed (0.595 vs 0.60) |

---

## 📊 11-Module Implementation Status

| Module | Name | Implemented State |
|---|---|---|
| **M1** | Ingress & Protocol Proxy | 🟢 100% Authoritative (Strict JSON, limits, crypt-quarantine) |
| **M2** | Tool Registry & Integrity | 🟢 100% Authoritative (Pinned manifest hashes, rug-pull defense) |
| **M3** | Deterministic Policy Core | 🟢 100% Authoritative (Single decision point, parameter checks) |
| **M4** | Provenance & Data Flow | 🟡 ML CUSUM active; Redis hot state ready for taint tracking |
| **M5** | Lethal Trifecta & Egress | 🟢 100% Network boundary; multi-step trifecta blocked by ML |
| **M6** | Behavioral ML Risk | 🟢 100% Authoritative (5 signals, calibrated XGBoost fusion) |
| **M7** | Monotonic Decision Fusion | 🟢 100% Authoritative (ML cannot lower a deterministic veto) |
| **M8** | Sandboxed Execution | 🟢 100% Authoritative (Disposable container, dropped caps, 256m) |
| **M9** | Response Security & DLP | 🟡 Output hashed; secret redaction prototyped in UI |
| **M10** | Cryptographically Signed Receipts | 🟡 HMAC integrity live; PostgreSQL 16 ready for hash chaining |
| **M11** | Control Plane Console | 🟢 Live Gateway live with backend; other screens in simulation |

---

## 📜 License

Licensed under the [Apache License, Version 2.0](LICENSE).
