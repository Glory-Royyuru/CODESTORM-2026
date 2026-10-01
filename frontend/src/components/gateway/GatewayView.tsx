"use client";

import { motion, type Variants } from "framer-motion";
import { ArrowRight, BrainCircuit, ChevronDown, Container, ServerCog, ShieldBan } from "lucide-react";
import Link from "next/link";
import { useCallback, useRef, useState } from "react";
import { categorize, submitToolCall } from "@/lib/satg/client";
import { useSatgLog } from "@/lib/satg/log";
import type { RequestPreset } from "@/lib/satg/presets";
import { useUi } from "@/lib/store";
import { cx } from "@/components/ui/primitives";
import AgentConsole, { type AgentResult } from "./AgentConsole";
import AttackStudio, { type StudioRun } from "./AttackStudio";
import EgressInspector from "./EgressInspector";
import RiskSandboxPanel from "./RiskSandboxPanel";
import LiveTelemetry from "./LiveTelemetry";
import PipelineRun from "./PipelineRun";

const container: Variants = { hidden: {}, show: { transition: { staggerChildren: 0.09, delayChildren: 0.1 } } };
const item: Variants = {
  hidden: { opacity: 0, y: 18, filter: "blur(6px)" },
  show: { opacity: 1, y: 0, filter: "blur(0px)", transition: { duration: 0.7, ease: [0.22, 1, 0.36, 1] } },
};

const STATS = [
  { icon: ServerCog, label: "Live FastAPI Backend" },
  { icon: ShieldBan, label: "Deterministic Fail-Closed Veto" },
  { icon: BrainCircuit, label: "ML Risk Escalation" },
  { icon: Container, label: "Docker-Sandboxed Execution" },
];

export default function GatewayView() {
  const [run, setRun] = useState<StudioRun | null>(null);
  const [busy, setBusy] = useState(false);
  const [manualOpen, setManualOpen] = useState(false);
  const runSeq = useRef(0);
  const toast = useUi((s) => s.toast);
  const log = useSatgLog((s) => s.add);

  const onRun = async (preset: RequestPreset, body: string) => {
    setBusy(true);
    // The verdict comes only from the backend; errors are shown as errors, never as a verdict.
    const outcome = await submitToolCall(body);
    log(preset.title, outcome);
    setRun({ title: preset.title, requestBody: body, outcome, runId: ++runSeq.current });
    document.getElementById("pipeline")?.scrollIntoView({ behavior: "smooth", block: "start" });
  };

  // The agent console made the one backend request itself; the panels below show that same response.
  const onAgentResult = useCallback(({ title, requestBody, outcome }: AgentResult) => {
    setRun({ title, requestBody, outcome, runId: ++runSeq.current });
  }, []);

  const onDone = useCallback(() => {
    setBusy(false);
    if (!run) return;
    const o = run.outcome;
    const category = categorize(o);
    if (o.kind === "verdict") {
      const v = o.verdict;
      toast({
        tone: category === "ALLOWED" ? "success" : category === "BLOCKED" ? "danger" : "warn",
        title: `${v.tool ?? "request"} → ${v.verdict}`,
        detail: `${v.rule_id} · ${v.reason} · ${o.roundTripMs}ms${category === "ALLOWED" ? ` · sandbox ${v.execution?.status ?? "not reported"}` : ""}`,
      });
    } else {
      toast({
        tone: "warn",
        title: o.kind === "network_error" ? "SATG backend unreachable — no verdict" : `Backend error (HTTP ${o.httpStatus}) — no verdict`,
        detail: o.message,
      });
    }
  }, [run, toast]);

  return (
    <div className="space-y-12">
      <section className="grid grid-cols-1 items-start gap-12 pt-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,660px)] xl:gap-[clamp(3rem,5vw,7rem)] xl:pt-16">
        <motion.div variants={container} initial="hidden" animate="show" className="max-w-[820px]">
          <motion.div variants={item}>
            <Link
              href="/provenance"
              className="group inline-flex items-center gap-3 rounded-[10px] border border-line bg-surface p-[6px] pr-4 backdrop-blur-sm transition-colors hover:bg-surface-hover"
            >
              <span className="rounded-md bg-accent px-3 py-[6px] text-[13.5px] font-medium text-[#1a0d03]">SIMULATION</span>
              <span className="flex items-center gap-2 text-[13.5px] font-medium text-fg/85">
                LETHAL-TRIFECTA PREVIEW
                <ArrowRight className="h-4 w-4 transition-transform group-hover:translate-x-0.5" />
              </span>
            </Link>
          </motion.div>

          <motion.h1 variants={item} className="mt-8 text-[clamp(2.5rem,4.4vw,5.1rem)] font-medium leading-[1.04] tracking-[-0.035em] text-fg">
            Zero-Trust Runtime Firewall
            <br />
            <span className="text-accent">for Autonomous AI Agents</span>
          </motion.h1>

          <motion.p variants={item} className="mt-7 max-w-[680px] text-[clamp(1.05rem,1.2vw,1.3rem)] leading-[1.55] text-muted">
            SATG sits synchronously between agents and their tools. This console talks to the live SATG backend: strict ingress, canonicalization,
            a hash-pinned tool registry, parameter and destination validation, a deterministic policy decision that ML risk scoring can only escalate, and disposable Docker sandboxes for allowed calls.
          </motion.p>

          <motion.ul variants={item} className="mt-8 flex flex-wrap gap-2.5">
            {STATS.map(({ icon: Icon, label }) => (
              <li key={label} className="flex items-center gap-2 rounded-lg border border-line bg-surface px-3 py-2 font-mono text-[12.5px] font-medium text-fg/90 backdrop-blur-sm">
                <Icon className="h-4 w-4 text-accent" />
                {label}
              </li>
            ))}
          </motion.ul>

          <motion.div variants={item} className="mt-10 flex flex-wrap items-center gap-4">
            <a
              href="#pipeline"
              className="group inline-flex h-[56px] items-center gap-2.5 rounded-xl bg-accent px-7 text-[17px] font-semibold text-[#1a0d03] shadow-[0_10px_40px_-10px_rgba(249,115,22,0.7),inset_0_1px_0_rgba(255,255,255,0.25)] transition-[filter,transform] hover:brightness-110 active:scale-[0.98]"
            >
              View Live Pipeline
              <ArrowRight className="h-5 w-5 transition-transform group-hover:translate-x-1" />
            </a>
            <Link
              href="/audit"
              className="inline-flex h-[56px] items-center gap-3 rounded-xl border border-[#fb923c]/40 bg-[#f97316]/75 px-7 text-[17px] font-semibold text-white shadow-[inset_0_1px_0_rgba(255,255,255,0.2)] backdrop-blur-md transition-colors hover:bg-[#f97316]/90"
            >
              Audit Ledger
              <span className="font-mono text-[13px] font-medium text-white/60">simulated</span>
            </Link>
          </motion.div>

          <motion.p variants={item} className="mt-8 flex flex-wrap items-center gap-3 text-[13.5px] font-semibold text-subtle">
            6 LIVE CHECKS <span aria-hidden="true">·</span> 1 POLICY DECISION POINT <span aria-hidden="true">·</span> FAIL-CLOSED BY DEFAULT
          </motion.p>
        </motion.div>

        <div id="agent" className="scroll-mt-28">
          <AgentConsole onResult={onAgentResult} />
        </div>
      </section>

      <section id="manual" className="scroll-mt-28">
        <button
          type="button"
          aria-expanded={manualOpen}
          onClick={() => setManualOpen((o) => !o)}
          className="flex w-full items-center justify-between gap-4 rounded-xl border border-line bg-surface px-5 py-3.5 text-left transition-colors hover:bg-surface-hover"
        >
          <span>
            <span className="block text-[13px] font-semibold uppercase tracking-[0.1em] text-subtle">Advanced · Manual tool call</span>
            <span className="mt-0.5 block text-[13px] text-muted">Edit and send a raw POST /v1/toolcalls JSON body, with presets for every rule.</span>
          </span>
          <ChevronDown className={cx("h-5 w-5 shrink-0 text-muted transition-transform", manualOpen && "rotate-180")} />
        </button>
        {manualOpen && (
          <div className="mt-4 max-w-[760px]">
            <AttackStudio busy={busy} onRun={onRun} />
          </div>
        )}
      </section>

      <section id="pipeline" className="scroll-mt-28">
        <PipelineRun key={run?.runId ?? 0} run={run} onDone={onDone} />
      </section>

      <section>
        <RiskSandboxPanel run={run} />
      </section>

      <section>
        <EgressInspector run={run} />
      </section>

      <section>
        <LiveTelemetry />
      </section>
    </div>
  );
}
