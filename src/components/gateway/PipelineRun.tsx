"use client";

import { AnimatePresence, motion } from "framer-motion";
import {
  ArrowRight,
  Binary,
  Boxes,
  BrainCircuit,
  FileSignature,
  GitMerge,
  LogIn,
  ScanSearch,
  Scale,
  ShieldCheck,
  type LucideIcon,
} from "lucide-react";
import Link from "next/link";
import { useEffect, useState } from "react";
import { cx, Hash, Panel, SectionTitle, VerdictBadge } from "@/components/ui/primitives";
import { VERDICT_STYLE } from "@/components/ui/tokens";
import type { StageId, StageResult } from "@/lib/gateway/types";
import type { StudioRun } from "./AttackStudio";

const ICONS: Record<StageId, LucideIcon> = {
  ingress: LogIn,
  canonicalize: Binary,
  registry: ShieldCheck,
  policy: Scale,
  ml: BrainCircuit,
  fusion: GitMerge,
  sandbox: Boxes,
  dlp: ScanSearch,
  receipt: FileSignature,
};

const STATUS_CLS: Record<StageResult["status"], string> = {
  pass: "border-emerald-400/50 bg-emerald-400/10 text-emerald-300",
  warn: "border-amber-400/50 bg-amber-400/10 text-amber-300",
  fail: "border-red-500/60 bg-red-500/15 text-red-300",
  skip: "border-line bg-surface text-subtle",
};

const STEP_MS = 280;

/** Animated stage-by-stage replay of the final call of a studio run. */
export default function PipelineRun({ run, onDone }: { run: StudioRun | null; onDone: () => void }) {
  const [active, setActive] = useState(-1);
  const [selected, setSelected] = useState<number | null>(null);
  const final = run?.results[run.results.length - 1]?.entry;
  const stages = final?.stages ?? [];

  useEffect(() => {
    if (!run) return;
    let i = -1;
    const id = setInterval(() => {
      i++;
      setActive(i);
      if (i >= stages.length - 1) {
        clearInterval(id);
        onDone();
      }
    }, STEP_MS);
    return () => clearInterval(id);
    // Remounted per run via `key`, so this replays exactly once.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (!run || !final) {
    return (
      <Panel className="flex min-h-[180px] flex-col items-center justify-center gap-3 p-8 text-center">
        <div className="flex items-center gap-2 font-mono text-[12px] uppercase tracking-[0.14em] text-subtle">
          {(["ingress", "canonicalize", "registry", "policy", "ml", "fusion", "sandbox", "dlp", "receipt"] as StageId[]).map((s, i) => {
            const Icon = ICONS[s];
            return (
              <span key={s} className="flex items-center gap-2">
                <Icon className="h-4 w-4" />
                {i < 8 && <span className="hidden h-px w-5 bg-line sm:block" />}
              </span>
            );
          })}
        </div>
        <p className="text-[14px] text-muted">Pick a scenario and press <span className="text-accent">Execute Through Gateway</span> to trace the call through every stage.</p>
      </Panel>
    );
  }

  const b = final.receipt.body;
  const done = active >= stages.length - 1;
  const shown = selected ?? Math.max(0, Math.min(active, stages.length - 1));
  const vs = VERDICT_STYLE[b.verdict];

  return (
    <div className="grid items-start gap-5 xl:grid-cols-[minmax(0,1fr)_420px]">
      <Panel className="p-5 sm:p-6">
        <SectionTitle
          right={
            <span className="font-mono text-[12px] text-subtle">
              deterministic {b.deterministicLatencyMs}ms · total {b.totalLatencyMs}ms
            </span>
          }
        >
          Pipeline trace · {run.scenario.short}
        </SectionTitle>

        {/* prior steps of the session */}
        <div className="mb-5 flex flex-wrap items-center gap-2">
          {run.results.map((r, i) => (
            <span key={r.entry.receipt.body.receiptId} className="flex items-center gap-2">
              <span className="flex items-center gap-1.5 rounded-lg border border-line bg-surface px-2 py-1 font-mono text-[11.5px] text-fg/80">
                {i + 1}. {r.entry.envelope.tool}
                <VerdictBadge verdict={r.entry.receipt.body.verdict} />
              </span>
              {i < run.results.length - 1 && <ArrowRight className="h-3.5 w-3.5 text-subtle" />}
            </span>
          ))}
        </div>

        {/* stepper */}
        <ol className="scrollbar-thin grid grid-cols-3 gap-3 overflow-x-auto sm:grid-cols-5 lg:grid-cols-9">
          {stages.map((s, i) => {
            const Icon = ICONS[s.stage];
            const reached = i <= active;
            return (
              <li key={s.stage}>
                <button
                  type="button"
                  onClick={() => setSelected(i)}
                  className={cx(
                    "relative flex w-full flex-col items-center gap-2 rounded-xl border p-3 text-center transition-all duration-300",
                    reached ? STATUS_CLS[s.status] : "border-line bg-surface/50 text-subtle/60",
                    shown === i && "ring-2 ring-accent/60",
                  )}
                >
                  {i === active && !done && <motion.span layoutId="stage-glow" className="absolute inset-0 rounded-xl bg-accent/10" />}
                  <Icon className="h-5 w-5" />
                  <span className="text-[11.5px] font-semibold leading-tight">{s.label}</span>
                  <span className="font-mono text-[10.5px] opacity-80">{reached ? (s.status === "skip" ? "skipped" : `${s.latencyMs}ms`) : "…"}</span>
                </button>
              </li>
            );
          })}
        </ol>

        <AnimatePresence mode="wait">
          <motion.div
            key={shown}
            initial={{ opacity: 0, y: 6 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.18 }}
            className="mt-4 rounded-xl border border-line bg-black/25 p-4 font-mono text-[12.5px] leading-relaxed"
          >
            <span className="text-accent">{stages[shown]?.label}</span>
            <span className="text-subtle"> · {stages[shown]?.status}</span>
            <p className="mt-1 break-words text-code">{stages[shown]?.detail}</p>
          </motion.div>
        </AnimatePresence>
      </Panel>

      {/* verdict panel */}
      <Panel className="relative overflow-hidden p-5 sm:p-6">
        <motion.div
          aria-hidden="true"
          className="pointer-events-none absolute -right-20 -top-20 h-56 w-56 rounded-full blur-3xl"
          style={{ background: vs.hex }}
          initial={{ opacity: 0 }}
          animate={{ opacity: done ? 0.18 : 0 }}
        />
        <SectionTitle>Final verdict</SectionTitle>
        <AnimatePresence mode="wait">
          {done ? (
            <motion.div key="v" initial={{ opacity: 0, scale: 0.96 }} animate={{ opacity: 1, scale: 1 }} className="space-y-4">
              <div className="flex flex-wrap items-center gap-3">
                <VerdictBadge verdict={b.verdict} size="lg" />
                <span className="font-mono text-[12px] text-subtle">
                  rules {b.deterministicVerdict} · ML {b.mlVerdict}
                  {b.mlAbstained && " (abstain)"}
                </span>
              </div>
              {b.findings.length ? (
                <ul className="space-y-2">
                  {b.findings.slice(0, 4).map((f) => (
                    <li key={f.ruleId} className="rounded-lg border border-line bg-surface p-2.5">
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-mono text-[12px] font-semibold text-fg">
                          <span className="text-subtle">{f.module} · </span>
                          {f.ruleId}
                        </span>
                        <VerdictBadge verdict={f.outcome} />
                      </div>
                      <p className="mt-1 text-[12.5px] leading-snug text-muted">{f.reason}</p>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-[13.5px] text-muted">No rule fired. ML risk {b.riskScore.toFixed(3)} stayed below escalation thresholds.</p>
              )}
              <div className="rounded-lg border border-accent/25 bg-accent/5 p-3 text-[12.5px] leading-snug text-fg/85">
                <span className="font-semibold text-accent">Counterfactual · </span>
                {b.counterfactual}
              </div>
              <div className="flex items-center justify-between gap-2 border-t border-line pt-3">
                <span className="text-[12px] text-subtle">
                  receipt #{b.seq} · <Hash value={final.receipt.hash} n={8} />
                </span>
                <Link href={`/audit?receipt=${b.receiptId}`} className="text-[12.5px] font-semibold text-accent hover:underline">
                  Inspect receipt →
                </Link>
              </div>
            </motion.div>
          ) : (
            <motion.p key="p" className="font-mono text-[13px] text-subtle" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
              evaluating stage {Math.max(1, active + 1)}/{stages.length}…
            </motion.p>
          )}
        </AnimatePresence>
      </Panel>
    </div>
  );
}
