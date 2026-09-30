"use client";

import { motion, type Variants } from "framer-motion";
import { ArrowRight, FileSignature, Gauge, ShieldBan } from "lucide-react";
import Link from "next/link";
import { useCallback, useState } from "react";
import { useUi } from "@/lib/store";
import AttackStudio, { type StudioRun } from "./AttackStudio";
import LiveTelemetry from "./LiveTelemetry";
import PipelineRun from "./PipelineRun";

const container: Variants = { hidden: {}, show: { transition: { staggerChildren: 0.09, delayChildren: 0.1 } } };
const item: Variants = {
  hidden: { opacity: 0, y: 18, filter: "blur(6px)" },
  show: { opacity: 1, y: 0, filter: "blur(0px)", transition: { duration: 0.7, ease: [0.22, 1, 0.36, 1] } },
};

const STATS = [
  { icon: Gauge, label: "< 15ms Latency" },
  { icon: ShieldBan, label: "100% Deterministic Veto" },
  { icon: FileSignature, label: "Ed25519 Signed" },
];

export default function GatewayView() {
  const [run, setRun] = useState<StudioRun | null>(null);
  const [busy, setBusy] = useState(false);
  const toast = useUi((s) => s.toast);

  const onRun = (r: StudioRun) => {
    setBusy(true);
    setRun(r);
    document.getElementById("pipeline")?.scrollIntoView({ behavior: "smooth", block: "start" });
  };

  const onDone = useCallback(() => {
    setBusy(false);
    if (!run) return;
    const b = run.results[run.results.length - 1].entry.receipt.body;
    const tone = b.verdict === "ALLOW" ? "success" : b.verdict === "MONITOR" ? "info" : b.verdict === "BLOCK" || b.verdict === "QUARANTINE" ? "danger" : "warn";
    toast({
      tone,
      title: `${b.tool} → ${b.verdict}`,
      detail: `${b.findings.map((f) => f.ruleId).join(", ") || "no rule fired"} · ${b.totalLatencyMs}ms · receipt #${b.seq}`,
    });
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
              <span className="rounded-md bg-accent px-3 py-[6px] text-[13.5px] font-medium text-[#1a0d03]">NEW MODULE</span>
              <span className="flex items-center gap-2 text-[13.5px] font-medium text-fg/85">
                LETHAL-TRIFECTA FIREWALL
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
            SATG sits synchronously between agents and their tools — deterministic hard vetoes, provenance-aware taint tracking and calibrated ML
            that can only ever escalate. Every decision fails closed and ships an Ed25519-signed receipt.
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
              <span className="font-mono text-[13px] font-medium text-white/60">Ed25519</span>
            </Link>
          </motion.div>

          <motion.p variants={item} className="mt-8 flex flex-wrap items-center gap-3 text-[13.5px] font-semibold text-subtle">
            11 MODULES <span aria-hidden="true">·</span> 6 SECURITY ZONES <span aria-hidden="true">·</span> FAIL-CLOSED BY DEFAULT
          </motion.p>
        </motion.div>

        <AttackStudio busy={busy} onRun={onRun} />
      </section>

      <section id="pipeline" className="scroll-mt-28">
        <PipelineRun key={run?.runId ?? 0} run={run} onDone={onDone} />
      </section>

      <section>
        <LiveTelemetry />
      </section>
    </div>
  );
}
