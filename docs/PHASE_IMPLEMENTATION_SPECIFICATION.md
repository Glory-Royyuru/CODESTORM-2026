# SATG — Phase-by-Phase Technical Implementation Specification

This document details the fifteen core implementation phases of the **Secure Agent Tool Gateway (SATG)**, defining inputs, outputs, guardrails, exact rule IDs, and current verification status across the codebase.

---

## Summary Matrix of All 15 Phases

| Phase | Title | Primary Responsibility | Guardrails & Rule IDs | Status in Repository |
|---|---|---|---|---|
| **Phase 1** | **Deterministic Gateway Core** | Ingress, strict JSON, limits, canonicalization | `INGRESS-*`, `CANON-*`, `BASE-001` | 🟢 **100% Implemented & Verified** |
| **Phase 2** | **Tool Registry & Integrity** | Manifest hashing, permissions, rug-pull defense | `TOOL-001` through `TOOL-004` | 🟢 **100% Implemented & Verified** |
| **Phase 3** | **Identity & Principal Attestation** | Agent authentication, mTLS, DPoP, SPIFFE/SPIRE | Token verification, role claims | 🟡 **Phase 1 MVP (`self_asserted`)** |
| **Phase 4** | **Network Boundary & SSRF Firewall** | Strict URL parse, private IP deny, DNS pinning | `DEST-001` through `DEST-006` | 🟢 **100% Implemented & Verified** |
| **Phase 5** | **Crypt-Arithmetic Quarantine Guard** | Numeric overflow, non-canonical encodings | `CRYPTO-001` through `CRYPTO-006` | 🟢 **100% Implemented & Verified** |
| **Phase 6** | **Provenance & Data-Flow Security** | Taint lattice (TRUSTED → TAINTED), atom matching | Untrusted data reaching sinks | 🟡 **Prototyped in Frontend UI** |
| **Phase 7** | **Lethal Trifecta Prevention** | Private Data + Untrusted Content + Egress Sink | Deterministic session hard veto | 🟡 **Active in ML; State in Redis** |
| **Phase 8** | **Behavioral ML Risk Pipeline** | MiniLM embeddings, IsolationForest, CUSUM drift | 5 risk signals, calibrated fused risk | 🟢 **100% Implemented & Verified** |
| **Phase 9** | **Monotonic Decision Fusion** | Monotone XGBoost, fail-closed ML adapter | `ML-001` (Escalate), `ML-002` (Block) | 🟢 **100% Implemented & Verified** |
| **Phase 10** | **Request Integrity Tagging** | HMAC-SHA256 signature over approved parameters | Verification before sandbox run | 🟢 **100% Implemented & Verified** |
| **Phase 11** | **Sandboxed Container Execution** | Disposable rootless Docker container | `--network none`, caps dropped, 256m | 🟢 **100% Implemented & Verified** |
| **Phase 12** | **Response Security & DLP** | Tool output scanning for secrets & secondary injection | Redaction of AWS keys, JWTs, PII | 🟡 **Prototyped in Frontend UI** |
| **Phase 13** | **Cryptographic Audit Ledger** | Ed25519 signatures, SHA-256 hash chaining | Tamper-evident ledger, hash verify | 🟡 **Infrastructure Running (PG16)** |
| **Phase 14** | **Control Plane & Web Console** | Next.js interactive UI: live gateway, DAG, ledger | Real-time proxy, health monitoring | 🟢 **Live Gateway 100%; Others Demo** |
| **Phase 15** | **Attack Simulation & Eval Lab** | 15 security scenarios, benchmark suites | Benchmark evaluation, FPR/FNR stats | 🟢 **14/15 Match in Live Lab** |

---

## Detailed Phase Breakdown

### Phase 1: Deterministic Gateway Core
- **Source Files:** [`backend/app/gateway/ingress.py`](file:///c:/Users/M%20ABHINAY/CODESTORM-2026/backend/app/gateway/ingress.py), [`canonicalizer.py`](file:///c:/Users/M%20ABHINAY/CODESTORM-2026/backend/app/gateway/canonicalizer.py), [`policy_engine.py`](file:///c:/Users/M%20ABHINAY/CODESTORM-2026/backend/app/gateway/policy_engine.py)
- **Input:** Raw HTTP POST stream to `/v1/toolcalls`.
- **Enforcement Rules:**
  - `INGRESS-001` (400): Body is not valid UTF-8 JSON or contains NaN/Infinity.
  - `INGRESS-002` (400): Duplicate JSON keys at any depth (differential parsing defense).
  - `INGRESS-003` (413): Payload exceeds 64 KiB.
  - `INGRESS-004` (400): JSON nesting depth > 8 levels.
  - `INGRESS-005` (422): Schema mismatch (missing/unexpected field).
  - `CANON-001` (200): Control or invisible Unicode characters (zero-width, bidi override).
  - `CANON-002` (200): Lone surrogate code points.
  - `BASE-001` (200): Passed all deterministic checks (ALLOW).

### Phase 2: Tool Registry & Integrity Engine
- **Source Files:** [`backend/app/gateway/registry.py`](file:///c:/Users/M%20ABHINAY/CODESTORM-2026/backend/app/gateway/registry.py)
- **Input:** Tool name and declared parameter schema.
- **Enforcement Rules:**
  - Manifest SHA-256 hash calculated over `{name, version, server_id, description, parameters, security}`.
  - `TOOL-001`: Tool is not registered.
  - `TOOL-002`: Tool is administratively disabled.
  - `TOOL-003`: Agent principal lacks permission for this tool.
  - `TOOL-004`: Manifest hash does not match registered hash (rug-pull defense).

### Phase 3: Identity & Principal Attestation (WP2)
- **Source Files:** [`backend/app/gateway/identity.py`](file:///c:/Users/M%20ABHINAY/CODESTORM-2026/backend/app/gateway/identity.py), [`models/envelope.py`](file:///c:/Users/M%20ABHINAY/CODESTORM-2026/backend/app/models/envelope.py)
- **Current State:** `Principal(agent_id=claimed_id, authenticated=False, auth_method="self_asserted")`.
- **Target Specification:** Cryptographic mTLS 1.3 + RFC 9449 DPoP + OAuth 2.0 access tokens. `resolve_principal()` validates the token subject against the body claim.

### Phase 4: Network Security & SSRF Firewall
- **Source Files:** [`backend/app/gateway/network.py`](file:///c:/Users/M%20ABHINAY/CODESTORM-2026/backend/app/gateway/network.py), [`destination_validator.py`](file:///c:/Users/M%20ABHINAY/CODESTORM-2026/backend/app/gateway/destination_validator.py)
- **Enforcement Rules:**
  - Strict URL parse: HTTPS only (`DEST-006`), port 443 only, dotted-quad IPv4 only (no octal/integer formats).
  - Public Suffix List check: Registrable domain (eTLD+1) must be in the allowlist (`DEST-001`).
  - Deny IP Ranges (`DEST-004`): Loopback (`127.0.0.0/8`, `::1`), Private (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), Cloud Metadata (`169.254.169.254`, `fe80::/10`).
  - DNS Resolve-Once-and-Pin: Resolves DNS once; validates all addresses; pins the first IP (`pinned_ip`) to prevent DNS rebinding.

### Phase 5: Crypt-Arithmetic Quarantine Guard
- **Source Files:** [`backend/app/gateway/crypto_guard.py`](file:///c:/Users/M%20ABHINAY/CODESTORM-2026/backend/app/gateway/crypto_guard.py), [`audit/anomaly_ledger.py`](file:///c:/Users/M%20ABHINAY/CODESTORM-2026/backend/app/audit/anomaly_ledger.py)
- **Enforcement Rules:**
  - Intercepts numeric literals during parsing before IEEE-754 conversion.
  - `CRYPTO-001`: Numeric literal over 256 bits or float overflow.
  - `CRYPTO-002`: Integer outside IEEE-754 safe range (`Number.MAX_SAFE_INTEGER`).
  - `CRYPTO-003`: Non-canonical Base64/Hex encoding, or homoglyphs in cryptographic keys.
  - `CRYPTO-004`: Corrupt crypto token (all-zero nonce, invalid curve point).
  - `CRYPTO-005`: Degenerate or malleable signature ($S \ge \ell$).
  - `CRYPTO-006`: DPoP proof tampering (algorithm `none`, HMAC with public key).

### Phase 6 & 7: Provenance & Lethal Trifecta Prevention
- **Concept:** Prevent untrusted web data from being exfiltrated via private data tools.
- **Specification:** Taint tracking state flags (`private_data_acquired`, `untrusted_content_acquired`).
- **Current Execution:**
  - Evaluated in ML risk engine: multi-step exfiltration triggers CUSUM drift and scores risk = 1.000 (`ML-002` BLOCK).
  - Hot state store in Redis (`satg:session:{id}`) enables server-side deterministic vetoes across turns.

### Phase 8 & 9: Behavioral ML Risk & Monotonic Fusion
- **Source Files:** [`backend/app/ml/`](file:///c:/Users/M%20ABHINAY/CODESTORM-2026/backend/app/ml/), [`ml/src/`](file:///c:/Users/M%20ABHINAY/CODESTORM-2026/ml/src/), [`decision_engine.py`](file:///c:/Users/M%20ABHINAY/CODESTORM-2026/backend/app/gateway/decision_engine.py)
- **Signals:** `p_inject`, `p_misaligned`, `anomaly_score` (IsolationForest), `sequence_surprisal` (Trigram), `context_shift` (CUSUM).
- **Invariants:**
  - Monotonicity: Deterministic `BLOCK` is final. ML is never consulted for a deterministic veto.
  - For deterministic `ALLOW`:
    - `risk >= 0.80`: Final `BLOCK` (`ML-002`).
    - `risk >= 0.60`: Final `ESCALATE` (`ML-001`) held for human approval.
    - `risk < 0.60`: Final `ALLOW`.

### Phase 10: Request Integrity Tagging
- **Source Files:** [`backend/app/gateway/request_integrity.py`](file:///c:/Users/M%20ABHINAY/CODESTORM-2026/backend/app/gateway/request_integrity.py)
- **Tag:** HMAC-SHA256 calculated over canonical JSON of `(request_id, agent_id, tool, request_hash, tool_manifest_hash, policy_version, pinned_ips)`.
- **Purpose:** Prevents internal man-in-the-middle attacks between gateway and execution sandbox.

### Phase 11: Sandboxed Container Execution
- **Source Files:** [`backend/app/sandbox/docker_runner.py`](file:///c:/Users/M%20ABHINAY/CODESTORM-2026/backend/app/sandbox/docker_runner.py), [`sandbox/Dockerfile`](file:///c:/Users/M%20ABHINAY/CODESTORM-2026/sandbox/Dockerfile)
- **Container Hardening:**
  - Image: `satg-sandbox:0.1` (digest-pinned, non-root user `uid 65532`).
  - Runtime flags: `--rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --memory 256m --memory-swap 256m --cpus 0.5 --pids-limit 64 --ipc none --pull never`.
  - Zero host mounts. Pre-verifies HMAC and `request_hash` on stdin before tool dispatch.
  - Verified container cleanup on completion or timeout.

### Phase 12: Response Security & DLP
- **Specification:** Scans raw stdout/stderr from container execution for leaked secrets (AWS tokens, private keys, JWTs) and secondary prompt injections before returning sanitized data.
- **Current State:** Backend hashes tool output to SHA-256 for audit safety; DLP pattern redaction is active in the frontend demo engine (`frontend/src/lib/gateway/dlp.ts`).

### Phase 13: Cryptographic Audit Trail & Persistence
- **Specification:** Every decision produces a canonical JSON receipt signed via Ed25519, chained via SHA-256 (`prev_receipt_hash`).
- **Active Infrastructure:** PostgreSQL 16 container (`satg-postgres`) running on port 5432; Redis container (`satg-redis`) running on port 6379.

### Phase 14: Control Plane Console (Next.js)
- **Source Files:** [`frontend/src/`](file:///c:/Users/M%20ABHINAY/CODESTORM-2026/frontend/src/)
- **Screens:**
  - `/` (Live Gateway): Direct integration with FastAPI backend via same-origin route proxy.
  - `/audit`: Cryptographic receipt explorer and chain verification.
  - `/provenance`: Interactive session data-flow graph.
  - `/registry`: Live tool manifest hashes and rug-pull simulator.
  - `/eval-lab`: Security benchmark suites and payload mutator.
  - `/policies`: YAML policy bundle editor and replay time-machine.
  - `/approvals`: Dual-custody review queue for held calls.

### Phase 15: Security Evaluation & Attack Lab
- **Source Files:** [`backend/eval/attack_lab.py`](file:///c:/Users/M%20ABHINAY/CODESTORM-2026/backend/eval/attack_lab.py), [`ml/evaluate.py`](file:///c:/Users/M%20ABHINAY/CODESTORM-2026/ml/evaluate.py)
- **Scenarios:** 15 live attack scenarios spanning benign calls, SSRF IP variants, prompt injections, lethal trifecta exfiltration, CRLF smuggling, zero-width Unicode, duplicate keys, and crypto tampering.
- **Results:** 14/15 match expectations; single-step injection documented at 0.595 (close to 0.60 threshold).
