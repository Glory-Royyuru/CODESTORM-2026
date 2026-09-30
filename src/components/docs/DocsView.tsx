"use client";

import { motion } from "framer-motion";
import Link from "next/link";
import { PageHeader, Panel, SectionTitle } from "@/components/ui/primitives";

const MODULES = [
  { id: "M1", name: "Ingress & Protocol Proxy", body: "MCP, OpenAI function-calling and REST adapters normalize into a ToolCallEnvelope. Strict JSON (duplicate keys rejected), depth ≤ 16, size ≤ 256KB, token-bucket rate limiting and the global kill switch.", where: "ingress.ts" },
  { id: "M2", name: "Tool Registry & Integrity", body: "SHA-256 over canonical {name, description, parameters, required, server}. Poisoning scanner for hidden directives, bidi/zero-width text and schema expansion. Drift at call time quarantines the tool.", where: "registry.ts" },
  { id: "M3", name: "Deterministic Policy Core", body: "Declarative YAML bundle: capability tokens, object ownership, semantic SQL, path traversal, destination allowlists + SSRF ranges, parameter-smuggling fuzzer, Tier-4 two-person grants.", where: "policy.ts · decoder.ts" },
  { id: "M4", name: "Provenance & Data-Flow Firewall", body: "Tool outputs are split into labelled atoms (TRUSTED → TAINTED lattice). Arguments are matched against known atoms so untrusted or secret data cannot reach egress sinks.", where: "taint.ts" },
  { id: "M5", name: "Lethal Trifecta & Egress", body: "Session flags for private data, untrusted content and outbound channel; hard veto when all three meet. Row/byte budgets, EWMA slow-drip detection and canary honeytokens.", where: "policy.ts · engine.ts" },
  { id: "M6", name: "Behavioral ML", body: "p_injection (logistic), p_misaligned (hashed-trigram embeddings vs. user goal), a real isolation forest, tool-sequence trigram surprise and session CUSUM.", where: "ml.ts" },
  { id: "M7", name: "Monotonic Decision Fusion", body: "final = max(rules, ML). ML can escalate but never loosen a rule veto. A split-conformal band forces STEP_UP when the model is unsure.", where: "ml.ts · engine.ts" },
  { id: "M8", name: "Sandboxed Execution", body: "Simulated rootless Docker + gVisor: non-root user, read-only root FS, CPU/memory quotas, pinned-IP egress proxy and 60-second scoped Vault leases.", where: "sandbox.ts" },
  { id: "M9", name: "Response DLP", body: "Redacts AWS keys, JWTs, API tokens, private keys and PII; detects honeytoken leaks and fences secondary prompt injections as untrusted data.", where: "dlp.ts" },
  { id: "M10", name: "Signed Audit Receipts", body: "Every decision (including BLOCK) is canonical JSON, SHA-256 hashed, Ed25519-signed and chained to the previous receipt. Verification runs in your browser.", where: "receipts.ts · crypto.ts" },
  { id: "M11", name: "Control Plane", body: "This console: live pipeline, provenance DAG, registry, ledger, policy time machine, approvals, eval lab and kill switches.", where: "src/components" },
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

const ACCEPTANCE = [
  ["Duplicate JSON keys rejected", "Edit the Attack Studio payload to repeat a key"],
  ["Kill switch blocks the next call < 2ms", "Header kill switch fires a probe call"],
  ["Description edit freezes tool", "Registry → Simulate Tool Rug-pull"],
  ["Order 999 denied for user owning 456", "Scenario D"],
  ["Email copy from web result BLOCKS", "Scenario A"],
  ["Tampered receipt fails verification", "Audit → receipt → Tamper test"],
  ["SSRF to 169.254.169.254 BLOCKS", "Seeded devops session, or the payload mutator"],
  ["Approved grant is single-use", "Approvals → execute, then replay grant"],
  ["ML cannot lower a rule veto", "Any receipt: rules=BLOCK · ML=ALLOW → BLOCK"],
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
        description="A zero-trust, provenance-aware runtime firewall that sits synchronously between autonomous agents and their tools. This console runs a complete in-browser implementation of the pipeline so every screen is backed by real decisions."
      />

      <section>
        <SectionTitle>Modules</SectionTitle>
        <div className="grid gap-4 md:grid-cols-2 2xl:grid-cols-3">
          {MODULES.map((m, i) => (
            <motion.div key={m.id} initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.03 }}>
              <Panel className="h-full p-5">
                <div className="flex items-center gap-3">
                  <span className="rounded-md bg-accent/15 px-2 py-0.5 font-mono text-[12px] font-bold text-accent">{m.id}</span>
                  <h3 className="text-[15.5px] font-semibold text-fg">{m.name}</h3>
                </div>
                <p className="mt-3 text-[13.5px] leading-relaxed text-muted">{m.body}</p>
                <p className="mt-3 font-mono text-[11.5px] text-subtle">src/lib/gateway/{m.where}</p>
              </Panel>
            </motion.div>
          ))}
        </div>
      </section>

      <section className="grid gap-5 xl:grid-cols-2">
        <Panel className="min-w-0 p-5 sm:p-6">
          <SectionTitle>Stage contracts</SectionTitle>
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
        </Panel>

        <Panel className="min-w-0 p-5 sm:p-6">
          <SectionTitle>Acceptance criteria you can check here</SectionTitle>
          <ul className="space-y-2">
            {ACCEPTANCE.map(([c, how]) => (
              <li key={c} className="flex flex-col gap-0.5 rounded-lg border border-line bg-surface px-3 py-2 sm:flex-row sm:items-center sm:justify-between">
                <span className="text-[13.5px] text-fg">{c}</span>
                <span className="font-mono text-[12px] text-subtle">{how}</span>
              </li>
            ))}
          </ul>
        </Panel>
      </section>

      <Panel className="p-5 sm:p-6">
        <SectionTitle>What is real and what is simulated</SectionTitle>
        <div className="grid gap-6 text-[13.5px] leading-relaxed text-muted md:grid-cols-2">
          <div>
            <p className="mb-2 font-semibold text-emerald-400">Real, running in your browser</p>
            <p>
              Strict JSON parsing, protocol adapters, the multi-layer decoder, every policy rule, atom-level taint tracking, the isolation forest and other
              models, monotonic fusion, DLP regexes, SHA-256 manifest pinning, Ed25519 signing and verification, hash chaining, capability grants and the
              policy replay engine.
            </p>
          </div>
          <div>
            <p className="mb-2 font-semibold text-amber-400">Simulated</p>
            <p>
              Tool execution (scripted outputs), the container runtime and Vault leases, and stage latencies — reported as modelled costs of the production
              Go/OPA/ONNX stack plus measured in-browser compute. Benchmark suites are synthetic cases shaped like AgentDojo, InjecAgent, MCPTox and
              agent-egress-bench, not the official datasets. State lives in memory and resets on reload.
            </p>
          </div>
        </div>
        <p className="mt-5 text-[13.5px]">
          <Link href="/" className="font-semibold text-accent hover:underline">
            Start with the Live Gateway →
          </Link>
        </p>
      </Panel>
    </div>
  );
}
