# SATG — Secure Agent Tool Gateway console

A Next.js app that demonstrates a zero-trust firewall sitting between AI agents and the tools they call.
The visual style comes from the React Bits landing page (dark background, orange glow ribbon, cursor-reactive dot grid, glass panels).

Everything runs **in the browser**: there is no backend. A TypeScript "gateway engine" (`src/lib/gateway/`) makes real decisions — parsing, policy rules, taint tracking, ML scoring, Ed25519 signing — and every screen reads from it.

## Run it

```bash
npm install
npm run dev          # http://localhost:3000
npm run build        # production build (typecheck + static pages)
npm run lint
npm run check:engine # print every seeded decision + verify the receipt chain
npm run check:bench  # run the benchmark suites headlessly
```

## The mental model (read this first)

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
| Live Gateway | `/` | Pick an attack scenario, edit its payload, press **Execute Through Gateway**, watch the 9 stages light up | `src/components/gateway/` |
| Provenance DAG | `/provenance` | Pick a session, see its graph of prompts → tool calls → data → external targets, click nodes | `src/components/provenance/` |
| Tool Registry | `/registry` | See each tool's pinned hash and status; simulate a rug-pull; register a new tool | `src/components/registry/` |
| Audit Ledger | `/audit` | Browse all receipts, verify the whole chain, open one and verify / tamper-test it | `src/components/audit/` |
| Eval Lab | `/eval-lab` | Run the benchmark suites; fuzz a payload with stacked encodings | `src/components/eval/` |
| Policies | `/policies` | Edit the YAML policy, replay history against it (Time Machine), publish it | `src/components/policies/` |
| Approvals | `/approvals` | Approve/reject held calls; two approvals issue a single-use signed grant | `src/components/approvals/` |
| Docs | `/docs` | Architecture summary and what is real vs simulated | `src/components/docs/` |

Always visible in the header: the **Kill Switch** (puts the gateway into `FAIL_CLOSED` — everything is blocked and the background ribbon turns red), the theme toggle and the GitHub counter.

## Folder map

```
reactbits-hero/
├── public/            static files (only create-next-app leftovers)
├── scripts/           terminal checks for the engine and benchmarks
└── src/
    ├── app/           Next.js routes — each page.tsx just renders a View component
    ├── components/    all UI, one folder per screen + shared shell/ui/hero
    └── lib/
        ├── store.ts   connects React to the engine; UI state (theme, toasts)
        └── gateway/   the engine itself — one file per security module
```

Every folder has its own README with more detail. Suggested reading order:
`src/lib/gateway/README.md` → `src/lib/README.md` → `src/components/README.md` → the screen folders.

## What is real and what is simulated

- **Real:** JSON parsing and limits, protocol adapters, the multi-layer decoder, all policy rules, taint tracking, the ML models (small, but genuine — e.g. an isolation forest trained at startup), SHA-256 hashing, Ed25519 signatures, the hash chain, approval grants, policy replay.
- **Simulated:** tool execution (scripted outputs), the sandbox container and Vault secrets, stage latencies (modelled production costs + measured browser time), and the benchmark suites (synthetic cases shaped like AgentDojo / InjecAgent / MCPTox / agent-egress-bench, not the real datasets).
- State lives in memory and **resets on page reload**. A new Ed25519 signing key is generated each load.

## Tech

Next.js 16 (App Router) · React 19 · Tailwind CSS v4 · Framer Motion · Lucide icons · Zustand · `@noble/curves` + `@noble/hashes` (crypto) · `yaml`.
