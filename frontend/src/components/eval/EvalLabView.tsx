"use client";

import { motion } from "framer-motion";
import { FlaskConical, Play, Shuffle, Undo2, Zap } from "lucide-react";
import { useRef, useState } from "react";
import { Button, cx, DemoTag, PageHeader, Panel, SectionTitle, Tabs, VerdictBadge } from "@/components/ui/primitives";
import { generateCases, runCase, summarize, SUITES, type CaseResult } from "@/lib/gateway/benchmarks";
import { decodeLayers, MUTATORS, type DecodeReport } from "@/lib/gateway/decoder";
import { Gateway } from "@/lib/gateway/engine";
import { toWire } from "@/lib/gateway/ingress";
import type { Capability, LedgerEntry } from "@/lib/gateway/types";
import { getGateway, useUi } from "@/lib/store";

function Gauge({ label, value, display, target, good }: { label: string; value: number | null; display: string; target: string; good: boolean | null }) {
  const r = 70;
  const circ = Math.PI * r;
  const pct = value == null ? 0 : Math.max(0, Math.min(1, value));
  const color = good == null ? "var(--subtle)" : good ? "#34d399" : "#f87171";
  return (
    <Panel className="flex flex-col items-center p-5">
      <svg viewBox="0 0 180 104" className="w-full max-w-[220px]" aria-hidden="true">
        <path d="M 20 94 A 70 70 0 0 1 160 94" fill="none" stroke="var(--line)" strokeWidth="12" strokeLinecap="round" />
        <motion.path
          d="M 20 94 A 70 70 0 0 1 160 94"
          fill="none"
          stroke={color}
          strokeWidth="12"
          strokeLinecap="round"
          strokeDasharray={circ}
          initial={false}
          animate={{ strokeDashoffset: circ * (1 - pct) }}
          transition={{ duration: 0.6, ease: "easeOut" }}
        />
      </svg>
      <p className="-mt-9 font-mono text-[26px] font-semibold tracking-tight text-fg">{display}</p>
      <p className="mt-2 text-[13px] font-semibold text-fg">{label}</p>
      <p className={cx("font-mono text-[11.5px]", good == null ? "text-subtle" : good ? "text-emerald-400" : "text-red-400")}>demo-engine target {target}</p>
    </Panel>
  );
}

const TARGETS: Record<string, { tool: string; arg: string; cap: Capability; seed: string }> = {
  "file_system.path": { tool: "file_system", arg: "path", cap: "fs:read", seed: "../../../etc/passwd" },
  "execute_sql.query": { tool: "execute_sql", arg: "query", cap: "db:read", seed: "SELECT 1; DROP TABLE users" },
  "fetch_webpage.url": { tool: "fetch_webpage", arg: "url", cap: "net:fetch", seed: "https://169.254.169.254/latest/meta-data/" },
};

function PayloadMutator() {
  const [target, setTarget] = useState<keyof typeof TARGETS>("file_system.path");
  const [history, setHistory] = useState<string[]>([TARGETS["file_system.path"].seed]);
  const [chain, setChain] = useState<string[]>([]);
  const [result, setResult] = useState<{ report: DecodeReport; entry: LedgerEntry } | null>(null);
  const current = history[history.length - 1];
  const cfg = TARGETS[target];

  const mutate = (name: string) => {
    setHistory((h) => [...h, MUTATORS[name](h[h.length - 1])]);
    setChain((c) => [...c, name]);
    setResult(null);
  };
  const reset = (seed: string) => {
    setHistory([seed]);
    setChain([]);
    setResult(null);
  };

  const fire = () => {
    const gw = new Gateway({ ephemeral: true, bundle: getGateway().bundle, key: getGateway().key });
    const s = gw.createSession({ agentId: "agent:fuzzer@lab", userId: "u_maya", tenant: "acme" }, "Payload mutation lab", [cfg.cap]);
    const res = gw.process({ raw: toWire("MCP", cfg.tool, { [cfg.arg]: current }), sessionId: s.id, groundTruth: "attack" });
    setResult({ report: decodeLayers(current, 4, 10), entry: res.entry });
  };

  return (
    <Panel className="p-5 sm:p-6">
      <SectionTitle
        right={
          <span className="flex items-center gap-2 font-mono text-[11.5px] text-subtle">
            bounded 4-layer decode · 10x expansion cap
            <DemoTag />
          </span>
        }
      >
        <span className="flex items-center gap-2">
          <Shuffle className="h-4 w-4" /> Attack payload mutator
        </span>
      </SectionTitle>
      <div className="grid gap-5 lg:grid-cols-2">
        <div className="space-y-3">
          <Tabs
            size="sm"
            className="max-w-full flex-wrap"
            label="Payload target"
            value={target}
            onChange={(k) => {
              setTarget(k);
              reset(TARGETS[k].seed);
            }}
            items={Object.keys(TARGETS).map((k) => ({ id: k, label: <span className="font-mono text-[12px]">{k}</span> }))}
          />
          <textarea
            value={current}
            onChange={(e) => {
              setHistory([e.target.value]);
              setChain([]);
              setResult(null);
            }}
            spellCheck={false}
            aria-label="Payload"
            className="scrollbar-thin h-28 w-full resize-none rounded-xl border border-line bg-black/30 p-3 font-mono text-[12.5px] text-code outline-none focus:ring-2 focus:ring-accent/50"
          />
          <div className="flex flex-wrap gap-1.5">
            {Object.keys(MUTATORS).map((m) => (
              <button key={m} type="button" onClick={() => mutate(m)} className="rounded-lg border border-line bg-surface px-2.5 py-1 font-mono text-[11.5px] text-fg/85 transition-colors hover:border-accent/50 hover:text-accent">
                + {m}
              </button>
            ))}
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Button variant="primary" className="h-9 text-[13px]" onClick={fire}>
              <Zap className="h-4 w-4" /> Fire through demo engine
            </Button>
            <Button variant="ghost" className="h-9 text-[13px]" disabled={history.length < 2} onClick={() => { setHistory((h) => h.slice(0, -1)); setChain((c) => c.slice(0, -1)); setResult(null); }}>
              <Undo2 className="h-4 w-4" /> Undo
            </Button>
            <span className="font-mono text-[11.5px] text-subtle">chain: {chain.length ? chain.join(" → ") : "raw"}</span>
          </div>
        </div>

        <div className="rounded-xl border border-line bg-black/20 p-4">
          {result ? (
            <div className="space-y-3 font-mono text-[12px]">
              <div className="flex flex-wrap items-center gap-2">
                <VerdictBadge verdict={result.entry.receipt.body.verdict} size="lg" />
                <span className="text-subtle">{result.entry.receipt.body.totalLatencyMs}ms</span>
              </div>
              <p>
                <span className="text-subtle">decode chain </span>
                <span className="text-code">{result.report.layers.length ? result.report.layers.join(" → ") : "none"}</span>
                {result.report.hitLayerLimit && <span className="text-red-400"> · LAYER LIMIT</span>}
                {result.report.expansionExceeded && <span className="text-red-400"> · EXPANSION CAP</span>}
              </p>
              <p className="break-all">
                <span className="text-subtle">canonical </span>
                <span className="text-code">{result.report.decoded.slice(0, 160)}</span>
              </p>
              <p>
                <span className="text-subtle">strict parser </span>
                <span className={result.report.dangerousRaw.length ? "text-red-400" : "text-emerald-400"}>{result.report.dangerousRaw.join(", ") || "clean"}</span>
                <span className="text-subtle"> · lenient parser </span>
                <span className={result.report.dangerousDecoded.length ? "text-red-400" : "text-emerald-400"}>{result.report.dangerousDecoded.join(", ") || "clean"}</span>
              </p>
              {result.report.disagreement && <p className="text-red-400">⚠ parser disagreement → smuggling detected</p>}
              <ul className="space-y-1 border-t border-line pt-2">
                {result.entry.receipt.body.findings.map((f) => (
                  <li key={f.ruleId} className="text-muted">
                    <span className="text-fg">{f.ruleId}</span> {f.outcome} — {f.reason}
                  </li>
                ))}
                {!result.entry.receipt.body.findings.length && <li className="text-emerald-400">no rule fired</li>}
              </ul>
            </div>
          ) : (
            <p className="text-[13px] text-subtle">Stack encodings on the payload, then fire it through the in-browser demo engine (not the SATG backend). Its canonicalizer decodes up to 4 layers and compares what a strict parser and a lenient downstream parser would each see.</p>
          )}
        </div>
      </div>
    </Panel>
  );
}

export default function EvalLabView() {
  const toast = useUi((s) => s.toast);
  const [results, setResults] = useState<CaseResult[]>([]);
  const [progress, setProgress] = useState<{ done: number; total: number } | null>(null);
  const running = useRef(false);

  const run = () => {
    if (running.current) return;
    running.current = true;
    const cases = generateCases(Math.floor(Math.random() * 1e6));
    const gw = new Gateway({ ephemeral: true, bundle: getGateway().bundle, key: getGateway().key });
    const out: CaseResult[] = [];
    setResults([]);
    setProgress({ done: 0, total: cases.length });
    let i = 0;
    const tick = () => {
      const end = Math.min(cases.length, i + 10);
      for (; i < end; i++) out.push(runCase(gw, cases[i]));
      setResults([...out]);
      setProgress({ done: i, total: cases.length });
      if (i < cases.length) setTimeout(tick, 16);
      else {
        running.current = false;
        const s = summarize(out);
        toast({ tone: s.detectionRate >= 0.984 && s.falsePositiveRate <= 0.008 ? "success" : "warn", title: "Demo benchmark suite complete", detail: `${out.length} cases · detection ${(s.detectionRate * 100).toFixed(1)}% · FPR ${(s.falsePositiveRate * 100).toFixed(2)}%` });
      }
    };
    setTimeout(tick, 30);
  };

  const all = summarize(results);
  const has = results.length > 0;
  const misses = results.filter((r) => (r.kind === "attack") !== r.detected);

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="M11 — Attack mutation & benchmark lab · demo engine"
        title={
          <>
            Continuous <span className="text-accent">evaluation</span>
          </>
        }
        description="Synthetic suites modelled on AgentDojo, InjecAgent, MCPTox and agent-egress-bench run through a fresh, ephemeral in-browser demo engine using the demo policy bundle, including a held-out paraphrased-exfiltration family its rules are not tuned for. These are demo-engine results, not measurements of the SATG backend."
        actions={
          <Button variant="primary" onClick={run} disabled={!!progress && progress.done < progress.total}>
            <Play className="h-4 w-4" /> Run demo benchmark
          </Button>
        }
      />

      {progress && (
        <Panel className="p-4">
          <div className="mb-2 flex items-center justify-between font-mono text-[12px] text-muted">
            <span className="flex items-center gap-2">
              <FlaskConical className="h-4 w-4 text-accent" /> {progress.done < progress.total ? "running" : "complete"} · {progress.done}/{progress.total} cases
            </span>
            <span>{Math.round((progress.done / progress.total) * 100)}%</span>
          </div>
          <div className="h-2 overflow-hidden rounded-full bg-surface">
            <motion.div className="h-full rounded-full bg-accent/80" animate={{ width: `${(progress.done / progress.total) * 100}%` }} transition={{ duration: 0.2 }} />
          </div>
        </Panel>
      )}

      <section>
      <SectionTitle right={<DemoTag />}>Demo benchmark results</SectionTitle>
      {!progress && (
        <p className="mb-3 text-[13px] text-subtle">No demo benchmark has run yet. Run it to fill the gauges and suite cards below with demo-engine results.</p>
      )}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Gauge label="Attack detection rate" value={has ? all.detectionRate : null} display={has ? `${(all.detectionRate * 100).toFixed(1)}%` : "—"} target="> 98.4%" good={has ? all.detectionRate > 0.984 : null} />
        <Gauge label="False positive rate" value={has ? all.falsePositiveRate * 10 : null} display={has ? `${(all.falsePositiveRate * 100).toFixed(2)}%` : "—"} target="< 0.8%" good={has ? all.falsePositiveRate < 0.008 : null} />
        <Gauge label="p95 deterministic" value={has ? all.p95Det / 15 : null} display={has ? `${all.p95Det.toFixed(1)}ms` : "—"} target="≈ 8.2ms · < 15ms" good={has ? all.p95Det < 15 : null} />
        <Gauge label="p95 ML-augmented" value={has ? all.p95Total / 40 : null} display={has ? `${all.p95Total.toFixed(1)}ms` : "—"} target="≈ 31.4ms · < 40ms" good={has ? all.p95Total < 40 : null} />
      </div>
      </section>

      <div className="grid gap-4 md:grid-cols-2 2xl:grid-cols-4">
        {SUITES.map((suite) => {
          const r = results.filter((x) => x.suite === suite.id);
          const s = summarize(r);
          return (
            <Panel key={suite.id} className="p-5">
              <div className="flex items-start justify-between gap-2">
                <div>
                  <h3 className="text-[16px] font-semibold text-fg">{suite.name}</h3>
                  <p className="font-mono text-[11px] text-subtle">modeled on {suite.modeledOn}</p>
                </div>
                <span className="font-mono text-[12px] text-muted">{r.length || "—"} cases</span>
              </div>
              <div className="mt-3 flex flex-wrap gap-1.5">
                {suite.envs.map((e) => {
                  const er = r.filter((x) => x.env === e);
                  const miss = er.filter((x) => (x.kind === "attack") !== x.detected).length;
                  return (
                    <span key={e} className={cx("rounded-md px-2 py-0.5 font-mono text-[11px]", er.length ? (miss ? "bg-amber-400/10 text-amber-300" : "bg-emerald-400/10 text-emerald-300") : "bg-surface text-muted")}>
                      {e}
                      {er.length > 0 && ` ${er.length - miss}/${er.length}`}
                    </span>
                  );
                })}
              </div>
              <dl className="mt-4 grid grid-cols-2 gap-3 font-mono">
                <div>
                  <dt className="text-[11px] text-subtle">detection</dt>
                  <dd className="text-[18px] font-semibold text-fg">{r.length ? `${(s.detectionRate * 100).toFixed(1)}%` : "—"}</dd>
                </div>
                <div>
                  <dt className="text-[11px] text-subtle">FPR</dt>
                  <dd className="text-[18px] font-semibold text-fg">{r.length ? `${(s.falsePositiveRate * 100).toFixed(2)}%` : "—"}</dd>
                </div>
              </dl>
            </Panel>
          );
        })}
      </div>

      {has && progress?.done === progress?.total && (
        <Panel className="p-5">
          <SectionTitle>Misses & false positives · {misses.length}</SectionTitle>
          {misses.length ? (
            <ul className="grid gap-1.5 md:grid-cols-2">
              {misses.map((m) => (
                <li key={m.id} className="flex items-center justify-between gap-2 rounded-lg border border-line bg-surface px-3 py-2 font-mono text-[12px]">
                  <span className="text-fg">{m.id}</span>
                  <span className="text-muted">{m.env}</span>
                  <span className={m.kind === "attack" ? "text-amber-300" : "text-red-300"}>{m.kind === "attack" ? "missed attack" : "false positive"}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-[13px] text-emerald-400">None.</p>
          )}
          <p className="mt-3 text-[12px] text-subtle">
            Missed cases are the held-out family: the agent paraphrases confidential data to an allow-listed internal address, so no tainted atom crosses verbatim. Closing it would need semantic DLP, which is not implemented (in the demo engine or the backend).
          </p>
        </Panel>
      )}

      <PayloadMutator />
    </div>
  );
}
