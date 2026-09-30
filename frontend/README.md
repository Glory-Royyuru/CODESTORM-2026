# `frontend/` — SATG console (Next.js)

The SATG console: a Next.js app that demonstrates a zero-trust firewall sitting between AI agents and the tools they call.
The visual style comes from the React Bits landing page (dark background, orange glow ribbon, cursor-reactive dot grid, glass panels).

The **Live Gateway** (`/`) is connected to the real SATG backend in [`backend/`](../backend/README.md) — the FastAPI Phase 1–5 deterministic gateway. The backend is the only security authority: the console sends the request, shows the backend's verdict, and never decides anything itself. No tool is executed.

All **other screens** (Provenance, Registry, Audit, Eval Lab, Policies, Approvals, the kill switch) still run on an in-browser TypeScript demo engine (`src/lib/gateway/`) and are labelled as simulations in the UI.

## Run it

Start the backend first (see the [root README](../README.md#run-locally)), then, from this directory:

```bash
npm install
npm run dev          # http://localhost:3000
```

The console reaches the backend through its own same-origin proxy, so no CORS setup is needed. The backend address is read server-side from `SATG_BACKEND_URL` (default `http://127.0.0.1:8000`); to change it, copy `.env.example` to `.env.local`. If the backend is down, the Live Gateway shows a network error and no verdict.

Checks (all run from `frontend/`):

```bash
npm run lint
npx next typegen && npx tsc --noEmit   # typecheck (typegen creates Next route types on a fresh clone)
npm run build        # production build
npm run check:engine # demo engine: print every seeded decision + verify the receipt chain
npm run check:bench  # demo engine: run the benchmark suites headlessly
```

## How the Live Gateway talks to the backend

```
browser ──POST /api/satg/v1/toolcalls──▶ Next.js route handler ──POST /v1/toolcalls──▶ FastAPI SATG backend
        ◀── backend status + body, unchanged ──                  ◀── Verdict (ALLOW / BLOCK) ──
```

- `src/app/api/satg/v1/toolcalls/route.ts` and `src/app/api/satg/health/route.ts` forward to the backend (`src/lib/satg/proxy.ts`). The raw request bytes and `Content-Type` are forwarded unchanged, so the backend's strict ingress judges exactly what the user typed. The backend's status code and body are relayed unchanged.
- If the backend cannot be reached, the proxy answers `502`/`504` with an `x-satg-proxy-error` header and **no verdict**.
- `src/lib/satg/client.ts` validates every response against the backend's `Verdict` model. Anything else (wrong shape, unknown verdict, an `ALLOW` on a non-200 status) is shown as a backend error, never as a verdict.
- `src/lib/satg/presets.ts` holds example request bodies built from the backend's registered tools. They are inputs only; the result always comes from the backend.

## The mental model of the demo engine (read this first)

> This section describes the full 11-module design as implemented by the in-browser demo engine. The real backend currently implements the deterministic front half (ingress → canonicalize → registry → parameters → destination → policy decision → audit) and returns ALLOW/BLOCK only.

1. An **agent** (e.g. `agent:research-assistant@v3.2`) works for a **user** (e.g. `u_maya`) inside a **session** that has a goal ("Summarize the Q3 partner report…") and a short-lived token listing what it may do (`db:read`, `email:send`, …).
2. Every tool call the agent makes (a JSON payload in MCP, OpenAI-function or REST format) goes through the gateway **pipeline**:

   ```
   Ingress → Canonicalize → Registry → Policy → ML Scoring → Decision Fusion → Sandbox → DLP → Receipt
   ```

3. The pipeline produces a **verdict**, in increasing severity:
   `ALLOW` → `MONITOR` → `STEP_UP` → `HUMAN_APPROVAL` → `QUARANTINE` → `BLOCK`.
   Rules can block on their own; ML can only *raise* the verdict, never lower it.
4. Every call — allowed or blocked — gets a **signed receipt** appended to a hash chain (the Audit Ledger).
5. If the call executes, its output is split into labelled **data atoms** (e.g. an email address marked `UNTRUSTED` because it came from a web page). Later calls are checked for those atoms, which is how "copy data from a web page into an email" gets caught.

When the app loads, it replays ~40 realistic calls (`src/lib/gateway/seed.ts`), so every screen already has data.

## The screens

| Nav item | Route | What you do there | Code |
| --- | --- | --- | --- |
| Live Gateway | `/` | **Real backend.** Pick an example request (or edit the raw body), press **Send Through Gateway**, see the backend's checks and verdict | `src/components/gateway/`, `src/lib/satg/` |
| Provenance DAG | `/provenance` | Pick a session, see its graph of prompts → tool calls → data → external targets, click nodes | `src/components/provenance/` |
| Tool Registry | `/registry` | See each tool's pinned hash and status; simulate a rug-pull; register a new tool | `src/components/registry/` |
| Audit Ledger | `/audit` | Browse all receipts, verify the whole chain, open one and verify / tamper-test it | `src/components/audit/` |
| Eval Lab | `/eval-lab` | Run the benchmark suites; fuzz a payload with stacked encodings | `src/components/eval/` |
| Policies | `/policies` | Edit the YAML policy, replay history against it (Time Machine), publish it | `src/components/policies/` |
| Approvals | `/approvals` | Approve/reject held calls; two approvals issue a single-use signed grant | `src/components/approvals/` |
| Docs | `/docs` | Architecture summary and what is real vs simulated | `src/components/docs/` |

Always visible in the header: the backend health indicator (`GET /health`), the **Kill Switch** of the demo engine (simulation only — it does not affect the backend), the theme toggle and the GitHub counter.

## Folder map

```
frontend/
├── public/            static files (currently none)
├── scripts/           terminal checks for the engine and benchmarks
└── src/
    ├── app/           Next.js routes — each page.tsx just renders a View component
    ├── components/    all UI, one folder per screen + shared shell/ui/hero
    └── lib/
        ├── store.ts   connects React to the demo engine; UI state (theme, toasts)
        ├── satg/      real backend integration: proxy, client, request presets
        └── gateway/   the in-browser demo engine — one file per security module
```

Every folder has its own README with more detail. Suggested reading order:
`src/lib/gateway/README.md` → `src/lib/README.md` → `src/components/README.md` → the screen folders.

## What is real and what is simulated

- **Real security decisions:** only the SATG backend (`backend/`), used by the Live Gateway. See [backend/README.md](../backend/README.md) for its checks and rule IDs.
- **Demo engine (every other screen), real code but not authoritative:** JSON parsing and limits, protocol adapters, the multi-layer decoder, all policy rules, taint tracking, the ML models (small, but genuine — e.g. an isolation forest trained at startup), SHA-256 hashing, Ed25519 signatures, the hash chain, approval grants, policy replay.
- **Simulated:** tool execution (scripted outputs), the sandbox container and Vault secrets, stage latencies (modelled production costs + measured browser time), and the benchmark suites (synthetic cases shaped like AgentDojo / InjecAgent / MCPTox / agent-egress-bench, not the real datasets).
- State lives in memory and **resets on page reload**. A new Ed25519 signing key is generated each load.

## Tech

Next.js 16 (App Router) · React 19 · Tailwind CSS v4 · Framer Motion · Lucide icons · Zustand · `@noble/curves` + `@noble/hashes` (crypto) · `yaml`.
