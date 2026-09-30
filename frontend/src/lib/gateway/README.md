# `src/lib/gateway/` — the in-browser demo engine

> **Simulation.** This engine powers the simulated screens (Provenance, Registry, Audit, Eval Lab, Policies, Approvals, kill switch). It is **not** used by the Live Gateway, whose verdicts come only from the real SATG backend (`backend/`, via `src/lib/satg/`). Nothing here is a security authority.

Pure TypeScript, no React. It runs in the browser (and in Node for the `scripts/` checks).

## How one tool call flows

`Gateway.process(request)` in **`engine.ts`** is the heart of the app. Given a raw payload and a session id, it runs these stages in order and records each one (status, latency, detail) for the UI's pipeline stepper:

| # | Stage | What happens | File |
| --- | --- | --- | --- |
| 0 | **Ingress** (M1) | Kill switch check → rate limit (20 burst, 2/s per agent) → crypt-arithmetic quarantine scan of the *raw text* (see below) → strict JSON parse (duplicate keys rejected, depth ≤ 16, ≤ 256 KB) → protocol adapter turns MCP / OpenAI / REST into one `ToolCallEnvelope` | `ingress.ts` |
| 1 | **Canonicalize** | Every string argument is decoded through up to 4 layers (URL, hex, Base64, `\u` escapes, HTML entities) and Unicode-normalized | `decoder.ts` |
| 2 | **Registry** (M2) | Tool must be registered. If the server advertises a manifest whose SHA-256 differs from the pinned one → tool is quarantined | `registry.ts` |
| 3 | **Policy** (M3/M4/M5) | The 12 rules in the YAML bundle run; each can return a verdict + reason + counterfactual | `policy.ts`, `taint.ts` |
| 4 | **ML scoring** (M6) | 5 scores → one calibrated risk → an ML verdict (or "abstain" when unsure) | `ml.ts` |
| 5 | **Fusion** (M7) | `final = max(rule verdict, ML verdict)` — ML can raise, never lower | `engine.ts` |
| 6 | **Sandbox** (M8) | Only if final ≤ `MONITOR`: destination firewall (resolve once, pin), HMAC request-integrity tag verified by the tool, simulated gVisor container, Vault lease, eBPF-enforced egress via the pinned-IP proxy; returns output | `sandbox.ts`, `network/` |
| 7 | **DLP** (M9) | Output scanned: secrets/PII redacted, honeytoken leaks, "instructions aimed at the agent" fenced as untrusted | `dlp.ts` |
| 8 | **Receipt** (M10) | Canonical JSON body → SHA-256 → Ed25519 signature, chained to the previous receipt | `receipts.ts`, `crypto.ts` |

Afterwards the engine updates the **session**: adds graph nodes/edges for the Provenance DAG, stores the output's data atoms, updates the lethal-trifecta flags and egress budgets, and creates an **approval request** if the verdict was `STEP_UP` or `HUMAN_APPROVAL`.

## Files

| File | Responsibility |
| --- | --- |
| `types.ts` | Every data model: `ToolCallEnvelope`, `DecisionReceipt`, `SessionState`, `PolicyRule`, `TaintLattice`, verdict order, etc. Start here. |
| `engine.ts` | The `Gateway` class: `process()`, sessions, approvals (`approve`, `reject`, `executeApproved`), operations (`setMode`, `setBundle`, `setMlEnabled`, `simulateRugPull`, `restore`, `repin`, `registerTool`). Calls `emit()` after every change so React re-renders. |
| `ingress.ts` | Strict JSON parser, protocol adapters (`normalize`), `toWire` (build a payload in any protocol), token-bucket `RateLimiter`. |
| `decoder.ts` | Differential smuggling fuzzer: `decodeLayers()` returns the decode chain and whether the *decoded* value reveals danger the *raw* value hid ("parser disagreement"). `MUTATORS` are the encoders used by the Eval Lab. |
| `registry.ts` | 12 seed tools (with tier, capability, egress/untrusted/sensitive flags), `manifestHash`, the poisoning scanner, and `rugPullManifest` (the malicious manifest swap). |
| `policy.ts` | `DEFAULT_BUNDLE` (the 12 rules and their parameters), one check function per rule, `evaluatePolicies`, grant validation, and YAML ↔ bundle conversion for the Policies editor. |
| `taint.ts` | The label lattice (`TRUSTED, INTERNAL, UNTRUSTED, SENSITIVE, SECRET, TAINTED`), `join` (untrusted + sensitive ⇒ TAINTED), atom extraction from outputs, and `matchAtoms` (find known atoms inside new arguments). |
| `ml.ts` | The ML layer (see below) and `fuse()` which turns scores into risk, SHAP-style contributions and an ML verdict. |
| `sandbox.ts` | Simulated execution: container metadata, Vault lease, egress proxy, scripted or default tool output. |
| `dlp.ts` | Response inspection and redaction. |
| `crypto.ts` | Ed25519 key generation, sign, verify (via `@noble/curves`). |
| `receipts.ts` | `signReceipt` and `verifyReceipt` (re-derives canonical JSON, hash, signature and chain link). |
| `util.ts` | Canonical JSON, SHA-256 hex, seeded random, verdict ordering (`maxVerdict`), percentile, etc. |
| `scenarios.ts` | The 5 Attack Studio scenarios (A–E) and the object-ownership table (`ORD-456` → `u_maya`, `ORD-999` → `u_derek`, …). |
| `runner.ts` | `runScript` (run a multi-step session through a gateway) and `timeMachine` (replay recorded history under two policy bundles and diff the verdicts). |
| `seed.ts` | Builds the gateway shown on page load: runs the 5 scenarios plus background sessions (SSRF, secret leak to Slack, slow-drip, SQL injection, honeytoken, Tier-4 operations, a poisoned tool…) spread over the last 6 hours. |
| `network/cidr.ts` | Strict IPv4/IPv6 parsing and the deny ranges (loopback, zero, RFC 1918, link-local/metadata, ULA, multicast/broadcast). |
| `network/resolver.ts` | Deterministic simulated DNS, including a TTL-0 rebinding name (`assets.partner-portal.com`). |
| `network/firewall.ts` | `inspectDestination`: parse → https → local names → deny ranges → eTLD+1 allowlist → resolve once and pin. `hostIsDenied` backs the policy's SSRF check. |
| `network/ebpf.ts` | Simulated Cilium/eBPF connect hooks: only the egress proxy to the pinned IP is allowed; per-session byte budget with EWMA slow-drip. |
| `network/identity.ts` | Simulated workload identity (mTLS 1.3, SPIFFE SVID, DPoP key bound to the task token) and **real** HMAC-SHA256 request-integrity tags. |
| `anomaly/guard.ts` | `quarantineScan`: a lexer over the raw payload. Numeric literals are judged as written, never passed through `JSON.parse`; crypto fields must be canonical and structurally valid. |
| `anomaly/ledger.ts` | `AnomalyLedger`: append-only, frozen `CryptArithmeticAnomalyRecord`s with their own pub/sub; `quarantineEnvelope` keeps only a SHA-256 fingerprint and ≤ 64 bytes of hex. |
| `benchmarks.ts` | Generates the synthetic benchmark cases, runs one case (`runCase`) and computes detection rate / false-positive rate / p95 latency (`summarize`). |

## The policy rules (`policy.ts`)

| Rule | Blocks / escalates when… |
| --- | --- |
| `tool_integrity` | tool hash drifted (QUARANTINE) or description is poisoned (BLOCK) |
| `capability_scope` | task token expired, belongs to another session, or lacks the tool's capability |
| `object_ownership` | `order_id` / `account_id` / `from_account` belongs to someone else |
| `sql_semantic` | read-only SQL contains DDL/DML, stacked statements, comments, system tables; missing/huge `LIMIT` → STEP_UP |
| `path_traversal` | a file path (raw or decoded) resolves outside `/workspace` |
| `destination_allowlist` | URL not https / private or metadata IP (SSRF) / domain not allow-listed; email recipient or payee not allow-listed |
| `param_smuggling` | decoded value is dangerous but raw value looked clean, or decode limits exceeded |
| `taint_flow` | an `UNTRUSTED`/`TAINTED`/`SECRET` atom reaches an egress or destructive tool |
| `lethal_trifecta` | session has private data **and** untrusted content, and this call is outbound |
| `egress_budget` | too many sensitive rows/bytes leave the session, or the EWMA "slow-drip" pattern appears |
| `canary_honeytoken` | a planted fake credential / order id is used |
| `tier4_approval` | Tier-4 tool without a valid two-person grant → HUMAN_APPROVAL |

Each rule can be disabled or put in `monitor` (shadow) mode from the Policies screen. A few extra checks live directly in `engine.ts`: `kill_switch`, `rate_limit`, `ingress.*` parse errors, `registry.unknown_tool`, `session_quarantine`, `capability_grant` (consumed grant) and the DLP findings.

## Network boundary and quarantine

- **Quarantine.** A payload with any crypt-arithmetic anomaly is hard-denied at ingress: one `BLOCK` finding per anomaly. The counterfactual cites its `anomaly_fingerprint`, and the receipt's `anomalyFingerprints` lists the fingerprints, never the values. Each anomaly is appended to `gw.anomalies` with the receipt id (Audit → Anomaly Inspector). A `DPOP_PROOF_TAMPERING` anomaly isolates the session, so later calls are quarantined.
- **Egress.** For an executing call, the gateway resolves the URL once, signs `{decision, session, tool, argsDigest, manifestHash, pinnedIp}` with HMAC-SHA256, and the sandbox verifies that tag before running. Every socket goes through `enforceConnect`. A firewall HARD_DENY, a dropped socket (proxy bypass, rebinding, budget) or a bad tag becomes a `BLOCK` finding (`egress.destination_firewall`, `ebpf.egress_enforcement`, `request_integrity`).
- `npm run check:network` asserts the deny ranges, pinning, eBPF decisions, HMAC and the guard.

## The ML layer (`ml.ts`)

| Score | How it is computed |
| --- | --- |
| `p_injection` | logistic model over injection phrases in the arguments, untrusted atoms in the arguments, and whether the session already ingested injected instructions |
| `p_misaligned` | cosine similarity between the user's goal and the call (hashed character-trigram embeddings — a lightweight stand-in for sentence-transformers) |
| `isolation_forest_anomaly` | a real isolation forest (60 trees) trained at startup on synthetic "normal call" features |
| `trigram_surprise` | how unusual this tool is after the previous two tools (trigram model over benign sequences) |
| `cusum_shift` | running CUSUM of per-call risk across the session |

`fuse()` combines them with fixed weights into a risk probability, derives per-feature contributions (the SHAP-style bars in the receipt inspector), and maps risk to a verdict. If risk falls in the uncertain band (0.46–0.56) the model **abstains**, which forces `STEP_UP`.

## Key rules of thumb when changing the engine

- Anything that mutates state must end with `this.emit()` (except in *ephemeral* gateways used by the Eval Lab and Time Machine, which are throwaway copies).
- Receipts are only valid in order — never reorder or edit `ledger` entries.
- Run `npm run check:engine` after changes: it prints every seeded verdict and confirms the chain verifies.
