"use client";

import { AnimatePresence, motion } from "framer-motion";
import { CheckCircle2, History, Rocket, RotateCcw, Sparkles, XCircle } from "lucide-react";
import { useMemo, useRef, useState } from "react";
import { Button, cx, DemoTag, PageHeader, Panel, SectionTitle, VerdictBadge } from "@/components/ui/primitives";
import { bundleToYaml, yamlToBundle } from "@/lib/gateway/policy";
import { timeMachine, type ReplayReport } from "@/lib/gateway/runner";
import type { PolicyBundle } from "@/lib/gateway/types";
import { getGateway, useGateway, useUi } from "@/lib/store";

const PRESETS: { label: string; apply: (b: PolicyBundle) => void }[] = [
  { label: "Disable lethal_trifecta", apply: (b) => void (b.rules.find((r) => r.id === "lethal_trifecta")!.enabled = false) },
  { label: "Shadow-mode taint_flow", apply: (b) => void (b.rules.find((r) => r.id === "taint_flow")!.mode = "monitor") },
  { label: "Allow exfil-collector.net", apply: (b) => void (b.rules.find((r) => r.id === "destination_allowlist")!.params.email_domains as string[]).push("exfil-collector.net") },
  { label: "Tighten SQL max_limit → 20", apply: (b) => void (b.rules.find((r) => r.id === "sql_semantic")!.params.max_limit = 20) },
  { label: "Slow-drip after 2 calls", apply: (b) => void (b.rules.find((r) => r.id === "egress_budget")!.params.slow_drip_calls = 2) },
];

function Delta({ label, before, after, goodWhenUp }: { label: string; before: number; after: number; goodWhenUp: boolean }) {
  const d = after - before;
  const good = d === 0 ? null : goodWhenUp ? d > 0 : d < 0;
  return (
    <div className="rounded-xl border border-line bg-surface p-4">
      <p className="text-[12px] font-semibold uppercase tracking-[0.08em] text-subtle">{label}</p>
      <p className="mt-2 font-mono text-[24px] font-semibold text-fg">
        {before} <span className="text-subtle">→</span> {after}
      </p>
      <p className={cx("font-mono text-[12px]", good == null ? "text-subtle" : good ? "text-emerald-400" : "text-red-400")}>{d === 0 ? "no change" : `${d > 0 ? "+" : ""}${d}`}</p>
    </div>
  );
}

export default function PoliciesView() {
  const gw = useGateway();
  const toast = useUi((s) => s.toast);
  const [draft, setDraft] = useState(() => bundleToYaml(gw.bundle));
  const [report, setReport] = useState<ReplayReport | null>(null);
  const gutter = useRef<HTMLDivElement>(null);

  const parsed = useMemo(() => yamlToBundle(draft, gw.bundle), [draft, gw.bundle]);
  const activeYaml = bundleToYaml(gw.bundle);
  const dirty = draft !== activeYaml;
  const lines = draft.split("\n").length;

  const edit = (fn: (b: PolicyBundle) => void) => {
    if (!parsed.bundle) return toast({ tone: "warn", title: "Fix YAML errors first" });
    const b = structuredClone(parsed.bundle);
    fn(b);
    setDraft(bundleToYaml(b));
    setReport(null);
  };

  const simulate = () => {
    if (!parsed.bundle) return;
    const t0 = performance.now();
    const r = timeMachine(getGateway(), parsed.bundle);
    setReport(r);
    toast({ tone: "info", title: "Demo time machine replay complete", detail: `${r.calls} historical calls re-evaluated in ${Math.round(performance.now() - t0)}ms · ${r.diffs.length} decision(s) changed` });
  };

  const publish = () => {
    if (!parsed.bundle) return;
    const [y, m, n] = gw.bundle.version.split(".");
    const next = { ...parsed.bundle, version: `${y}.${m}.${Number(n) + 1}` };
    getGateway().setBundle(next);
    setDraft(bundleToYaml(next));
    toast({ tone: "success", title: `Demo policy bundle ${next.version} published`, detail: "New demo-engine receipts reference the updated rule versions · the SATG backend is not affected" });
  };

  return (
    <div>
      <PageHeader
        eyebrow="M3 · M11 — Policy manager & control plane · demo engine"
        title={
          <>
            Policy-as-code with a <span className="text-accent">time machine</span>
          </>
        }
        description="Edit the demo engine's declarative YAML bundle, replay every recorded demo session against the candidate, and only publish when it stops more attacks without blocking legitimate work. This runs in the browser; the FastAPI backend's policy is defined in its code and is not changed from here."
      />

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1.15fr)_minmax(0,1fr)]">
        <div className="min-w-0 space-y-5">
          <Panel className="overflow-hidden">
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-line px-5 py-3">
              <div className="flex items-center gap-2 font-mono text-[12.5px] text-muted">
                <span className="text-fg">policy.yaml</span>
                <span className="text-subtle">· active {gw.bundle.version}</span>
                {dirty && <span className="text-accent">● modified</span>}
              </div>
              <div className="flex items-center gap-2">
                {parsed.errors.length ? (
                  <span className="flex items-center gap-1.5 font-mono text-[12px] text-red-400">
                    <XCircle className="h-4 w-4" /> invalid
                  </span>
                ) : (
                  <span className="flex items-center gap-1.5 font-mono text-[12px] text-emerald-400">
                    <CheckCircle2 className="h-4 w-4" /> valid schema
                  </span>
                )}
              </div>
            </div>
            <div className="relative flex h-[560px] bg-black/25">
              <div ref={gutter} aria-hidden="true" className="w-12 shrink-0 overflow-hidden border-r border-line py-4 text-right font-mono text-[12px] leading-[1.6] text-subtle/70">
                {Array.from({ length: lines }, (_, i) => (
                  <div key={i} className="pr-3">
                    {i + 1}
                  </div>
                ))}
              </div>
              <textarea
                value={draft}
                onChange={(e) => {
                  setDraft(e.target.value);
                  setReport(null);
                }}
                onScroll={(e) => gutter.current && (gutter.current.scrollTop = e.currentTarget.scrollTop)}
                spellCheck={false}
                aria-label="Policy YAML"
                className="scrollbar-thin h-full flex-1 resize-none whitespace-pre bg-transparent px-4 py-4 font-mono text-[12.5px] leading-[1.6] text-code caret-accent outline-none"
              />
            </div>
            <AnimatePresence>
              {parsed.errors.length > 0 && (
                <motion.ul initial={{ height: 0 }} animate={{ height: "auto" }} exit={{ height: 0 }} className="overflow-hidden border-t border-red-500/30 bg-red-500/10 px-5 font-mono text-[12px] text-red-300">
                  {parsed.errors.map((e) => (
                    <li key={e} className="py-1.5">
                      {e}
                    </li>
                  ))}
                </motion.ul>
              )}
            </AnimatePresence>
            <div className="flex flex-wrap items-center gap-2 border-t border-line px-5 py-3">
              <Button variant="primary" className="h-9 text-[13px]" disabled={!parsed.bundle} onClick={simulate}>
                <History className="h-4 w-4" /> Simulate against history
              </Button>
              <Button className="h-9 text-[13px]" disabled={!parsed.bundle || !dirty} onClick={publish}>
                <Rocket className="h-4 w-4" /> Publish bundle
              </Button>
              <Button
                variant="ghost"
                className="h-9 text-[13px]"
                disabled={!dirty}
                onClick={() => {
                  setDraft(activeYaml);
                  setReport(null);
                }}
              >
                <RotateCcw className="h-4 w-4" /> Revert
              </Button>
            </div>
          </Panel>

          <Panel className="p-5">
            <SectionTitle>
              <span className="flex items-center gap-2">
                <Sparkles className="h-4 w-4" /> Quick edits to try in the time machine
              </span>
            </SectionTitle>
            <div className="flex flex-wrap gap-2">
              {PRESETS.map((p) => (
                <button key={p.label} type="button" onClick={() => edit(p.apply)} className="rounded-lg border border-line bg-surface px-3 py-1.5 font-mono text-[12px] text-fg/85 transition-colors hover:border-accent/50 hover:text-accent">
                  {p.label}
                </button>
              ))}
            </div>
          </Panel>
        </div>

        <div className="min-w-0 space-y-5">
          <Panel className="p-5 sm:p-6">
            <SectionTitle right={report && <span className="font-mono text-[11.5px] text-subtle">{report.calls} calls · {report.attacks} attacks · {report.benign} benign</span>}>
              <span className="flex items-center gap-2">
                <History className="h-4 w-4" /> Policy Time Machine
              </span>
            </SectionTitle>
            {report ? (
              <div className="space-y-4">
                <div className="grid gap-3 sm:grid-cols-2">
                  <Delta label="Attacks prevented" before={report.preventedBefore} after={report.preventedAfter} goodWhenUp />
                  <Delta label="Benign calls escalated" before={report.falsePositivesBefore} after={report.falsePositivesAfter} goodWhenUp={false} />
                </div>
                <div
                  className={cx(
                    "rounded-xl border p-3 text-[13px]",
                    report.preventedAfter >= report.preventedBefore && report.falsePositivesAfter <= report.falsePositivesBefore ? "border-emerald-400/30 bg-emerald-400/10 text-emerald-300" : "border-red-500/30 bg-red-500/10 text-red-300",
                  )}
                >
                  {report.preventedAfter >= report.preventedBefore && report.falsePositivesAfter <= report.falsePositivesBefore
                    ? "Safe to publish: no regression in prevented attacks or false positives."
                    : report.preventedAfter < report.preventedBefore
                      ? `Regression: ${report.preventedBefore - report.preventedAfter} historical attack(s) would slip through.`
                      : `Regression: ${report.falsePositivesAfter - report.falsePositivesBefore} legitimate call(s) would now be escalated or blocked.`}
                </div>
                <div>
                  <p className="mb-2 text-[12px] font-semibold uppercase tracking-[0.08em] text-subtle">Changed decisions · {report.diffs.length}</p>
                  <ul className="scrollbar-thin max-h-72 space-y-1.5 overflow-y-auto">
                    {report.diffs.map((d) => (
                      <li key={d.receiptId} className="grid grid-cols-[minmax(0,1fr)_auto_auto_auto] items-center gap-2 rounded-lg border border-line bg-surface px-3 py-2 font-mono text-[12px]">
                        <span className="truncate text-fg">{d.tool}</span>
                        <span className={d.groundTruth === "attack" ? "text-red-300" : "text-emerald-300"}>{d.groundTruth}</span>
                        <VerdictBadge verdict={d.before} />
                        <span className="flex items-center gap-1.5">
                          → <VerdictBadge verdict={d.after} />
                        </span>
                      </li>
                    ))}
                    {!report.diffs.length && <li className="text-[13px] text-subtle">No historical decision changes under this bundle.</li>}
                  </ul>
                </div>
              </div>
            ) : (
              <p className="text-[13.5px] leading-relaxed text-muted">
                Replays all {gw.ledger.length} recorded calls — session by session, with the same tool outputs — once under the active bundle and once under your draft, then diffs the verdicts against ground truth.
              </p>
            )}
          </Panel>

          <Panel className="p-5 sm:p-6">
            <SectionTitle right={<DemoTag />}>Demo engine control plane</SectionTitle>
            <p className="-mt-1 mb-4 text-[12.5px] leading-snug text-subtle">
              These settings belong to the in-browser demo engine. Changing them does not affect the FastAPI backend used by the Live Gateway.
            </p>
            <ul className="space-y-3 text-[13.5px]">
              <li className="flex items-center justify-between gap-3">
                <span className="text-muted">Demo engine mode<DemoTag className="ml-2" /></span>
                <span className={cx("font-mono font-semibold", gw.mode === "FAIL_CLOSED" ? "text-red-400" : "text-emerald-400")}>{gw.mode}</span>
              </li>
              <li className="flex items-center justify-between gap-3">
                <span className="text-muted">Demo behavioral ML (M6/M7)<DemoTag className="ml-2" /></span>
                <button
                  type="button"
                  role="switch"
                  aria-checked={gw.mlEnabled}
                  onClick={() => {
                    getGateway().setMlEnabled(!gw.mlEnabled);
                    toast({ tone: "info", title: `Demo engine ML layer ${gw.mlEnabled ? "disabled" : "enabled"}`, detail: `${gw.mlEnabled ? "Deterministic rules still veto" : "Monotonic fusion active"} · simulation only, the SATG backend is not affected` });
                  }}
                  className={cx("relative h-6 w-11 rounded-full transition-colors", gw.mlEnabled ? "bg-accent" : "bg-fg/20")}
                >
                  <motion.span layout className={cx("absolute top-0.5 h-5 w-5 rounded-full bg-white shadow", gw.mlEnabled ? "right-0.5" : "left-0.5")} />
                </button>
              </li>
              <li className="flex items-center justify-between gap-3">
                <span className="text-muted">Active demo bundle</span>
                <span className="font-mono text-code">
                  {gw.bundle.version} · {gw.bundle.rules.filter((r) => r.enabled).length}/{gw.bundle.rules.length} rules
                </span>
              </li>
              <li className="flex items-center justify-between gap-3">
                <span className="text-muted">Demo signing key</span>
                <span className="font-mono text-code">{gw.key.keyId}</span>
              </li>
              <li className="flex items-center justify-between gap-3">
                <span className="text-muted">Demo engine ingress limits</span>
                <span className="font-mono text-code">depth ≤ 16 · 256KB · 20 burst / 2 rps</span>
              </li>
              <li className="flex items-center justify-between gap-3 border-t border-line pt-3">
                <span className="text-muted">Backend ingress limits (Live Gateway, for comparison)</span>
                <span className="font-mono text-code">depth ≤ 8 · 64 KiB · no rate limiting</span>
              </li>
            </ul>
          </Panel>
        </div>
      </div>
    </div>
  );
}
