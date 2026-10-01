"use client";

import { motion } from "framer-motion";
import { Box, BrainCircuit, CheckCircle2, CircleDashed, Container, Scale, XCircle } from "lucide-react";
import type { ReactNode } from "react";
import { cx, JsonBlock, Panel, SectionTitle } from "@/components/ui/primitives";
import type { SatgExecution, SatgVerdict } from "@/lib/satg/client";
import type { StudioRun } from "./AttackStudio";
import { SatgVerdictBadge } from "./PipelineRun";

/** Display names for the ML package's signals (ml/README.md §6). */
const SIGNAL_LABELS: Record<string, string> = {
  p_inject: "Injection",
  p_misaligned: "Misalignment",
  anomaly_score: "Behavioural anomaly",
  sequence_surprisal: "Sequence surprisal",
  context_shift: "Context shift (CUSUM)",
};

const EXEC_TONE: Record<SatgExecution["status"], string> = {
  success: "text-emerald-300 bg-emerald-400/10 ring-emerald-400/30",
  tool_error: "text-amber-300 bg-amber-400/10 ring-amber-400/30",
  rejected: "text-amber-300 bg-amber-400/10 ring-amber-400/30",
  timeout: "text-red-300 bg-red-500/15 ring-red-500/40",
  killed: "text-red-300 bg-red-500/15 ring-red-500/40",
  sandbox_unavailable: "text-red-300 bg-red-500/15 ring-red-500/40",
  integrity_failed: "text-red-300 bg-red-500/15 ring-red-500/40",
  error: "text-red-300 bg-red-500/15 ring-red-500/40",
  not_executed: "text-subtle bg-surface ring-line",
};

const HARDENING = ["--network none", "--read-only", "--cap-drop ALL", "no-new-privileges", "user 65532", "256m · 0.5 CPU · 64 pids", "--rm"];

function Step({ icon: Icon, title, state, children }: { icon: typeof Box; title: string; state: "pass" | "fail" | "skip" | "warn"; children: ReactNode }) {
  const tone = { pass: "border-emerald-400/40", fail: "border-red-500/50", warn: "border-amber-400/50", skip: "border-line border-dashed" }[state];
  const StateIcon = state === "pass" ? CheckCircle2 : state === "skip" ? CircleDashed : XCircle;
  return (
    <section className={cx("min-w-0 rounded-xl border bg-surface/60 p-4", tone)}>
      <p className="mb-3 flex items-center justify-between gap-2 text-[13px] font-semibold text-fg">
        <span className="flex items-center gap-2">
          <Icon className="h-4 w-4 text-accent" /> {title}
        </span>
        <StateIcon className={cx("h-4 w-4", state === "pass" ? "text-emerald-300" : state === "skip" ? "text-subtle" : state === "warn" ? "text-amber-300" : "text-red-300")} />
      </p>
      {children}
    </section>
  );
}

function RiskBar({ score, high, critical }: { score: number; high: number; critical: number }) {
  return (
    <div className="relative mt-1 h-2.5 rounded-full bg-gradient-to-r from-emerald-500/30 via-amber-400/30 to-red-500/40">
      <span className="absolute inset-y-[-3px] w-px bg-amber-300" style={{ left: `${high * 100}%` }} title={`high ${high}`} />
      <span className="absolute inset-y-[-3px] w-px bg-red-400" style={{ left: `${critical * 100}%` }} title={`critical ${critical}`} />
      <motion.span
        className="absolute top-1/2 h-4 w-4 -translate-x-1/2 -translate-y-1/2 rounded-full border-2 border-fg bg-accent shadow"
        initial={{ left: "0%" }}
        animate={{ left: `${score * 100}%` }}
        transition={{ duration: 0.8, ease: [0.22, 1, 0.36, 1] }}
      />
    </div>
  );
}

function MlStep({ v }: { v: SatgVerdict }) {
  const ml = v.ml;
  const d = v.decision;
  if (!ml || ml.status === "not_consulted") {
    return (
      <Step icon={BrainCircuit} title="ML risk assessment" state="skip">
        <p className="font-mono text-[13px] font-semibold text-fg/85">NOT EVALUATED</p>
        <p className="mt-1 text-[12.5px] leading-snug text-subtle">A deterministic security rule ({v.rule_id}) blocked the request before ML scoring. ML can never relax a BLOCK.</p>
      </Step>
    );
  }
  if (ml.status !== "ok" || ml.risk_score === null) {
    const why =
      ml.status === "disabled"
          ? "ML_MODE=off."
          : `ML ${ml.status}${ml.detail ? `: ${ml.detail}` : ""} (ML_MODE=${ml.mode}). ${
              v.rule_id === "ML-003" ? "Blocked: ML is required and no assessment was available (ML-003, fail closed)." : "The deterministic decision was kept."
            }`;
    const failed = ml && (ml.status === "unavailable" || ml.status === "error");
    return (
      <Step icon={BrainCircuit} title="ML risk assessment" state={!failed ? "skip" : v.rule_id === "ML-003" ? "fail" : "warn"}>
        <p className="text-[12.5px] leading-snug text-subtle">{why}</p>
      </Step>
    );
  }
  const high = d?.ml_high_risk_threshold ?? 0.6;
  const critical = d?.ml_critical_risk_threshold ?? 0.8;
  const escalated = ml.risk_score >= high;
  return (
    <Step icon={BrainCircuit} title="ML risk assessment" state={ml.risk_score >= critical ? "fail" : escalated ? "warn" : "pass"}>
      <div className="flex items-baseline justify-between gap-2">
        <span className="font-mono text-[26px] font-semibold text-fg">{ml.risk_score.toFixed(3)}</span>
        <span className="font-mono text-[11px] text-subtle">
          level {ml.risk_level} · {ml.prediction}
          {ml.conformal_abstain ? " · abstain" : ""}
        </span>
      </div>
      <RiskBar score={ml.risk_score} high={high} critical={critical} />
      <p className="mt-1.5 flex justify-between font-mono text-[10.5px] text-subtle">
        <span>0</span>
        <span>
          escalate ≥ {high} · block ≥ {critical}
        </span>
      </p>
      <details className="mt-3">
        <summary className="cursor-pointer text-[12px] font-semibold text-accent hover:underline">Signals and model details</summary>
      <ul className="mt-2 space-y-1">
        {Object.entries(ml.signals).map(([k, value]) => (
          <li key={k} className="grid grid-cols-[132px_minmax(0,1fr)_40px] items-center gap-2 font-mono text-[11px]">
            <span className="truncate text-muted">{SIGNAL_LABELS[k] ?? k}</span>
            <span className="h-1.5 overflow-hidden rounded bg-surface">
              <span className="block h-full bg-accent/70" style={{ width: `${value * 100}%` }} />
            </span>
            <span className="text-right text-code">{value.toFixed(2)}</span>
          </li>
        ))}
      </ul>
      {ml.top_factors.length > 0 && (
        <p className="mt-3 text-[11.5px] text-subtle">
          Top factors (XGBoost contributions):{" "}
          <span className="font-mono text-code">{ml.top_factors.slice(0, 3).map((f) => `${f.feature} ${(f.contribution * 100).toFixed(0)}%`).join(" · ")}</span>
        </p>
      )}
      <p className="mt-1 font-mono text-[10.5px] text-subtle">
        {ml.model_version} · {ml.latency_ms ?? "?"} ms · context: {ml.context_used.length ? ml.context_used.join(", ") : "none supplied"}
      </p>
      </details>
    </Step>
  );
}

function DecisionStep({ v }: { v: SatgVerdict }) {
  const d = v.decision;
  return (
    <Step icon={Scale} title="Policy decision" state={v.verdict === "ALLOW" ? "pass" : v.verdict === "ESCALATE" ? "warn" : "fail"}>
      {d ? (
        <ol className="space-y-2 font-mono text-[12px]">
          <li className="flex items-center justify-between gap-2">
            <span className="text-subtle">1 · deterministic</span>
            <span className="flex items-center gap-2">
              <SatgVerdictBadge verdict={d.deterministic_verdict} /> <span className="text-muted">{d.deterministic_rule_id}</span>
            </span>
          </li>
          <li className="flex items-center justify-between gap-2">
            <span className="text-subtle">2 · ML ({d.ml_mode})</span>
            <span className="text-muted">{v.ml?.status === "ok" ? `risk ${v.ml.risk_score?.toFixed(3)}` : (v.ml?.status ?? "—")}</span>
          </li>
          <li className="flex items-center justify-between gap-2 border-t border-line pt-2">
            <span className="text-fg">final</span>
            <span className="flex items-center gap-2">
              <SatgVerdictBadge verdict={d.final_verdict} /> <span className="text-muted">{d.final_rule_id}</span>
            </span>
          </li>
        </ol>
      ) : (
        <p className="text-[12.5px] text-subtle">Refused at {v.stage} before the policy/ML stages ({v.rule_id}).</p>
      )}
      <p className="mt-3 text-[11.5px] leading-snug text-subtle">ML can only make a decision stricter: it never relaxes a deterministic BLOCK. Only a final ALLOW is signed and sent to the sandbox.</p>
    </Step>
  );
}

function SandboxStep({ v }: { v: SatgVerdict }) {
  const e = v.execution;
  if (!e)
    return (
      <Step icon={Container} title="Docker sandbox" state="skip">
        <p className="font-mono text-[13px] font-semibold text-fg/85">NOT EXECUTED</p>
        <p className="mt-1 text-[12.5px] leading-snug text-subtle">
          Execution was withheld because the request did not receive a final ALLOW ({v.verdict} · {v.rule_id}). No container was started.
        </p>
      </Step>
    );
  return (
    <Step icon={Container} title="Docker sandbox" state={e.status === "success" ? "pass" : e.status === "not_executed" ? "skip" : e.status === "tool_error" || e.status === "rejected" ? "warn" : "fail"}>
      <div className="flex flex-wrap items-center gap-2">
        <span className={cx("rounded-md px-2 py-0.5 font-mono text-[11px] font-semibold ring-1", EXEC_TONE[e.status])}>{e.status.toUpperCase()}</span>
        {e.exit_code !== null && <span className="font-mono text-[11px] text-subtle">exit {e.exit_code}</span>}
        {e.duration_ms !== null && <span className="font-mono text-[11px] text-subtle">{e.duration_ms} ms</span>}
        {e.container_removed !== null && (
          <span className={cx("font-mono text-[11px]", e.container_removed ? "text-emerald-300" : "text-red-300")}>{e.container_removed ? "container removed" : "container NOT removed"}</span>
        )}
      </div>
      {e.error && <p className="mt-2 break-words font-mono text-[11.5px] text-amber-200/90">{e.error}</p>}
      {e.result ? <JsonBlock value={e.result} className="mt-3 max-h-[200px] text-[11.5px]" /> : e.stdout ? <JsonBlock value={e.stdout} className="mt-3 max-h-[160px] text-[11.5px]" /> : null}
      <details className="mt-3">
        <summary className="cursor-pointer text-[12px] font-semibold text-accent hover:underline">Sandbox details</summary>
      <ul className="mt-2 flex flex-wrap gap-1.5">
        {HARDENING.map((h) => (
          <li key={h} className="rounded border border-line px-1.5 py-0.5 font-mono text-[10px] text-subtle">
            {h}
          </li>
        ))}
      </ul>
      {e.sandbox_id && <p className="mt-2 font-mono text-[10.5px] text-subtle">{e.sandbox_id}</p>}
      </details>
    </Step>
  );
}

/** REQUEST → SECURITY ANALYSIS → ML RISK → POLICY DECISION → SANDBOX → RESULT, from the backend's own answer. */
export default function RiskSandboxPanel({ run }: { run: StudioRun | null }) {
  const v = run?.outcome.kind === "verdict" ? run.outcome.verdict : null;
  return (
    <Panel className="p-5 sm:p-6">
      <SectionTitle right={<span className="font-mono text-[11.5px] text-subtle">computed by the backend · displayed only</span>}>
        <span className="flex items-center gap-2">
          <BrainCircuit className="h-4 w-4" /> ML risk · decision · sandbox execution
        </span>
      </SectionTitle>
      {v ? (
        <motion.div key={run?.runId} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="grid gap-4 lg:grid-cols-3">
          <MlStep v={v} />
          <DecisionStep v={v} />
          <SandboxStep v={v} />
        </motion.div>
      ) : run ? (
        <p className="rounded-xl border border-dashed border-amber-400/40 bg-amber-400/5 p-6 text-center text-[13.5px] text-amber-200/90">
          No backend verdict for the last request, so nothing was evaluated or executed.
        </p>
      ) : (
        <p className="rounded-xl border border-dashed border-line p-6 text-center text-[13.5px] text-muted">
          Send a request to see the ML risk score, how it combined with the deterministic policy, and what happened in the Docker sandbox.
        </p>
      )}
    </Panel>
  );
}
