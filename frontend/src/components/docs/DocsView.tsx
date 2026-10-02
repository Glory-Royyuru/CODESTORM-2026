"use client";

import { motion } from "framer-motion";
import Link from "next/link";
import { cx, DemoTag, Disclosure, PageHeader, Panel, SectionTitle } from "@/components/ui/primitives";

type Status = "implemented" | "partial" | "demo" | "planned";

/** How much of each module the SATG backend implements (see the root README's implementation status). */
const STATUS: Record<Status, { label: string; cls: string }> = {
  implemented: { label: "Backend: implemented", cls: "text-emerald-300 bg-emerald-400/10 ring-emerald-400/30" },
  partial: { label: "Backend: partial", cls: "text-fg/85 bg-surface ring-line" },
  demo: { label: "Demo only", cls: "text-amber-300 bg-amber-400/10 ring-amber-400/30" },
  planned: { label: "Planned", cls: "text-subtle bg-transparent ring-line" },
};

function StatusChip({ status }: { status: Status }) {
  const s = STATUS[status];
  return <span className={cx("whitespace-nowrap rounded-md px-2 py-0.5 font-mono text-[11px] font-semibold ring-1", s.cls)}>{s.label}</span>;
}

/** `body` describes the full design as built in the in-browser demo engine; `backend` says what the real SATG backend does today. */
const MODULES: { id: string; name: string; status: Status; body: string; backend: string; where: string }[] = [
  {
    id: "M1",
    name: "Ingress & Protocol Proxy",
    status: "partial",
    body: "MCP, OpenAI function-calling and REST adapters normalize into a ToolCallEnvelope. Strict JSON (duplicate keys rejected), depth ≤ 16, size ≤ 256KB, token-bucket rate limiting and the global kill switch.",
    backend: "One strict HTTP JSON endpoint: duplicate keys, NaN, content type, depth ≤ 8, 64 KiB, crypt-arithmetic quarantine. Protocol adapters, rate limiting and the kill switch are demo only.",
    where: "ingress.ts",
  },
  {
    id: "M2",
    name: "Tool Registry & Integrity",
    status: "partial",
    body: "SHA-256 over canonical {name, description, parameters, required, server}. Poisoning scanner for hidden directives, bidi/zero-width text and schema expansion. Drift at call time quarantines the tool.",
    backend: "Pinned SHA-256 manifest hashes; a manifest that drifts is refused (TOOL-004). The poisoning scanner and quarantine/re-pin workflow are demo only.",
    where: "registry.ts",
  },
  {
    id: "M3",
    name: "Deterministic Policy Core",
    status: "partial",
    body: "Declarative YAML bundle: capability tokens, object ownership, semantic SQL, path traversal, destination allowlists + SSRF ranges, parameter-smuggling fuzzer, Tier-4 two-person grants.",
    backend: "A single deterministic decision point with agent permissions, manifest parameter schemas, destination allowlists and SSRF deny ranges. Policy lives in code; the YAML bundle, capability tokens, ownership, SQL/path rules and two-person grants are demo only.",
    where: "policy.ts · decoder.ts",
  },
  {
    id: "M4",
    name: "Provenance & Data-Flow Firewall",
    status: "demo",
    body: "Tool outputs are split into labelled atoms (TRUSTED → TAINTED lattice). Arguments are matched against known atoms so untrusted or secret data cannot reach egress sinks.",
    backend: "Not implemented. The backend does not track where data came from; it only passes the caller-supplied context to the ML model.",
    where: "taint.ts",
  },
  {
    id: "M5",
    name: "Lethal Trifecta & Egress",
    status: "partial",
    body: "Session flags for private data, untrusted content and outbound channel; hard veto when all three meet. Row/byte budgets, EWMA slow-drip detection and canary honeytokens.",
    backend: "The egress boundary is enforced (allowlists, private/metadata IP deny ranges, DNS pinning). There is no deterministic trifecta rule or session state; multi-step exfiltration is caught only by the ML score. Budgets, slow-drip and honeytokens are demo only.",
    where: "policy.ts · engine.ts",
  },
  {
    id: "M6",
    name: "Behavioral ML",
    status: "implemented",
    body: "p_injection (logistic), p_misaligned (hashed-trigram embeddings vs. user goal), a real isolation forest, tool-sequence trigram surprise and session CUSUM.",
    backend: "The backend runs its own model, satg-ml-v0.1 (ml/): MiniLM embeddings with LogisticRegression, IsolationForest, trigram surprisal and CUSUM, fused by calibrated XGBoost. The demo-engine design below describes its smaller in-browser model.",
    where: "ml.ts",
  },
  {
    id: "M7",
    name: "Monotonic Decision Fusion",
    status: "implemented",
    body: "final = max(rules, ML). ML can escalate but never loosen a rule veto. A split-conformal band forces STEP_UP when the model is unsure.",
    backend: "ML is consulted only for a deterministic ALLOW and can only escalate (ML-001) or block (ML-002); an unavailable or timed-out model blocks (ML-003). The conformal STEP_UP band is demo only.",
    where: "ml.ts · engine.ts",
  },
  {
    id: "M8",
    name: "Sandboxed Execution",
    status: "partial",
    body: "Simulated rootless Docker + gVisor: non-root user, read-only root FS, CPU/memory quotas, pinned-IP egress proxy and 60-second scoped Vault leases.",
    backend: "A real disposable Docker container per final ALLOW: non-root user, read-only filesystem, no network, dropped capabilities, CPU/memory/PID limits and a timeout. gVisor, the pinned-IP egress proxy and Vault leases are not implemented; the Docker daemon is not rootless.",
    where: "sandbox.ts",
  },
  {
    id: "M9",
    name: "Response DLP",
    status: "demo",
    body: "Redacts AWS keys, JWTs, API tokens, private keys and PII; detects honeytoken leaks and fences secondary prompt injections as untrusted data.",
    backend: "Not implemented. The backend returns tool output unredacted; its audit log keeps only a hash and size of the output.",
    where: "dlp.ts",
  },
  {
    id: "M10",
    name: "Signed Audit Receipts",
    status: "partial",
    body: "Every decision (including BLOCK) is canonical JSON, SHA-256 hashed, Ed25519-signed and chained to the previous receipt. Verification runs in your browser.",
    backend: "Every ALLOW carries an HMAC-SHA256 request-integrity tag, checked before the sandbox runs, and every decision goes to an in-memory audit log. Ed25519 receipts and the hash chain exist only in the demo engine.",
    where: "receipts.ts · crypto.ts",
  },
  {
    id: "M11",
    name: "Control Plane",
    status: "partial",
    body: "This console: live pipeline, provenance DAG, registry, ledger, policy time machine, approvals, eval lab and kill switches.",
    backend: "The Live Gateway shows real backend verdicts. Provenance, Registry, Audit, Eval Lab, Policies, Approvals and the kill switch run on the demo engine.",
    where: "src/components",
  },
];

const PHASES = [
  ["0 · Ingress", "Raw payload + task token", "Strict JSON, depth ≤ 16, ≤ 256KB, rate limit, kill switch"],
  ["1 · Canonicalize", "Raw envelope", "NFKC, ≤ 4 decode layers (URL/hex/Base64/\\u), 10x expansion cap"],
  ["2 · Registry", "Tool name + advertised manifest", "SHA-256 vs. pinned hash → quarantine on drift"],
  ["3 · Policy", "Canonical call + token + session", "Capability, ownership, SQL/path/URL, taint flow, trifecta, budgets"],
  ["4 · ML", "Call + goal + session features", "Risk vector + conformal abstention"],
  ["5 · Fusion", "Rule verdict + ML verdict", "Monotonic max; valid grants satisfy approval-type escalations only"],
  ["6 · Sandbox", "Args + scoped secret", "gVisor, read-only FS, pinned-IP egress proxy"],
  ["7 · DLP", "Raw tool output", "Secret/PII redaction, honeytokens, secondary injection, atom extraction"],
  ["8 · Receipt", "Everything above", "Ed25519 signature + SHA-256 hash chain"],
];

/** [criterion, where to check it, real backend or simulated] */
const ACCEPTANCE: [string, string, "real" | "sim"][] = [
  ["Duplicate JSON keys rejected", "Live Gateway → Advanced · Manual tool call → Ingress preset", "real"],
  ["SSRF to 169.254.169.254 BLOCKS (DEST-004)", "Live Gateway → agent console example, or the SSRF preset", "real"],
  ["Deterministic BLOCK never consults ML", "Live Gateway → email to attacker@evil.com: ML not evaluated", "real"],
  ["Only a final ALLOW runs in the Docker sandbox", "Live Gateway → Execution section of any result", "real"],
  ["Kill switch blocks the next call", "Header kill switch fires a probe call", "sim"],
  ["Description edit freezes tool", "Registry → Simulate Tool Rug-pull", "sim"],
  ["Order 999 denied for user owning 456", "Provenance DAG → seeded scenario D", "sim"],
  ["Email copy from web result BLOCKS", "Provenance DAG → seeded scenario A", "sim"],
  ["Tampered receipt fails verification", "Audit → receipt → Tamper test", "sim"],
  ["Approved grant is single-use", "Approvals → execute, then replay grant", "sim"],
  ["ML cannot lower a rule veto", "Any demo receipt: rules=BLOCK · ML=ALLOW → BLOCK", "sim"],
];

export default function DocsView() {
  return (
    <div className="space-y-10">
      <PageHeader
        eyebrow="Master reference architecture"
        title={
          <>
            Secure Agent Tool Gateway, <span className="text-accent">in 11 modules</span>
          </>
        }
        description="A zero-trust, provenance-aware runtime firewall that sits synchronously between autonomous agents and their tools. The Live Gateway is backed by the real SATG backend (FastAPI deterministic core, escalation-only ML risk layer and Docker sandbox). The other screens illustrate the full 11-module design with an in-browser simulation."
      />

      <Panel className="p-5 sm:p-6">
        <SectionTitle>What is real and what is simulated</SectionTitle>
        <div className="grid gap-6 text-[13.5px] leading-relaxed text-muted md:grid-cols-2">
          <div>
            <p className="mb-2 font-semibold text-emerald-400">Real — the SATG backend (Live Gateway)</p>
            <p>
              Every request sent from the Live Gateway goes to <code className="font-mono text-code">POST /v1/toolcalls</code> on the FastAPI backend, which is
              the only security authority: strict ingress (64 KiB limit, UTF-8 JSON, duplicate keys, depth ≤ 8, NaN/Infinity, content type), NFKC
              canonicalization and invisible-character rejection, request hashing, the hash-pinned tool registry, agent permissions, manifest-driven
              parameter validation, email and URL destination allowlists with private-IP denial and DNS pinning, one deterministic policy decision, an
              ML risk score that can only escalate or block an allowed call (and blocks it, ML-003, if the model is unavailable or times out), an
              HMAC-SHA256 tag on every ALLOW, and a disposable, network-less, non-root Docker container that runs only a final ALLOW. Every decision is
              kept in an in-memory audit log. The console only displays the backend&apos;s verdict; it never decides.
            </p>
          </div>
          <div>
            <p className="mb-2 font-semibold text-amber-400">Simulated — every other screen</p>
            <p>
              Provenance DAG, Tool Registry, Audit Ledger, Eval Lab, Policies, Approvals and the header kill switch run on an in-browser TypeScript demo
              engine. Its protocol adapters, taint tracking, ML scoring, fusion, sandbox, DLP, Ed25519 receipts and approval grants are not part of the
              backend yet and are not authoritative. Tool execution is scripted, benchmark suites are synthetic, and state resets on reload.
            </p>
          </div>
        </div>
        <div className="mt-5 flex flex-wrap items-center gap-2 text-[12.5px] text-subtle">
          <span>Module labels below:</span>
          {(Object.keys(STATUS) as Status[]).map((s) => (
            <StatusChip key={s} status={s} />
          ))}
        </div>
        <p className="mt-4 text-[13.5px]">
          <Link href="/" className="font-semibold text-accent hover:underline">
            Start with the Live Gateway →
          </Link>
        </p>
      </Panel>

      <section>
        <SectionTitle>Modules</SectionTitle>
        <div className="grid gap-4 md:grid-cols-2 2xl:grid-cols-3">
          {MODULES.map((m, i) => (
            <motion.div key={m.id} initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.03 }}>
              <Panel className="h-full p-5">
                <div className="flex flex-wrap items-center gap-3">
                  <span className="rounded-md bg-accent/15 px-2 py-0.5 font-mono text-[12px] font-bold text-accent">{m.id}</span>
                  <h3 className="text-[15.5px] font-semibold text-fg">{m.name}</h3>
                  <span className="ml-auto">
                    <StatusChip status={m.status} />
                  </span>
                </div>
                <p className="mt-3 text-[13px] leading-relaxed text-fg/85">
                  <span className="font-semibold text-fg">Backend: </span>
                  {m.backend}
                </p>
                <Disclosure className="mt-3 border-t border-line pt-3" summary="Full design in the demo engine">
                  <p className="text-[13px] leading-relaxed text-muted">{m.body}</p>
                  <p className="mt-2 font-mono text-[11.5px] text-subtle">demo engine: src/lib/gateway/{m.where}</p>
                </Disclosure>
              </Panel>
            </motion.div>
          ))}
        </div>
      </section>

      <section className="grid gap-5 xl:grid-cols-2">
        <Panel className="min-w-0 self-start p-5 sm:p-6">
          <SectionTitle right={<StatusChip status="demo" />}>Stage contracts · demo engine</SectionTitle>
          <p className="mb-3 text-[12.5px] leading-snug text-subtle">
            Limits and stages of the in-browser demo engine. The SATG backend enforces depth ≤ 8 and 64 KiB with no rate limiting, has no DLP stage, and issues
            HMAC-SHA256 request-integrity tags instead of Ed25519 receipts; its sandbox is Docker, not gVisor.
          </p>
          <Disclosure summary={`Show the ${PHASES.length} demo-engine stages`}>
          <div className="scrollbar-thin overflow-x-auto">
            <table className="w-full min-w-[560px] text-left text-[13px]">
              <thead>
                <tr className="border-b border-line font-mono text-[11px] uppercase tracking-[0.08em] text-subtle">
                  <th className="py-2 pr-3 font-medium">Phase</th>
                  <th className="py-2 pr-3 font-medium">Input</th>
                  <th className="py-2 font-medium">Guardrail</th>
                </tr>
              </thead>
              <tbody>
                {PHASES.map(([p, i, g]) => (
                  <tr key={p} className="border-b border-line/60 last:border-0">
                    <td className="py-2.5 pr-3 font-mono text-[12.5px] text-accent">{p}</td>
                    <td className="py-2.5 pr-3 text-muted">{i}</td>
                    <td className="py-2.5 text-fg/85">{g}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          </Disclosure>
        </Panel>

        <Panel className="min-w-0 p-5 sm:p-6">
          <SectionTitle>Acceptance criteria you can check here</SectionTitle>
          <ul className="space-y-2">
            {ACCEPTANCE.map(([c, how, kind]) => (
              <li key={c} className="flex flex-col gap-0.5 rounded-lg border border-line bg-surface px-3 py-2 sm:flex-row sm:items-center sm:justify-between sm:gap-3">
                <span className="flex items-center gap-2 text-[13.5px] text-fg">
                  {kind === "real" ? (
                    <span title="Checked against the real SATG backend" className="rounded bg-emerald-400/10 px-1 font-mono text-[10px] text-emerald-300">
                      REAL
                    </span>
                  ) : (
                    <DemoTag />
                  )}
                  {c}
                </span>
                <span className="font-mono text-[12px] text-subtle">{how}</span>
              </li>
            ))}
          </ul>
        </Panel>
      </section>
    </div>
  );
}
