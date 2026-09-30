"use client";

import { AnimatePresence, motion } from "framer-motion";
import { Hash, Panel, SectionTitle, Stat } from "@/components/ui/primitives";
import { categorize, type OutcomeCategory } from "@/lib/satg/client";
import { useSatgLog } from "@/lib/satg/log";
import { percentile } from "@/lib/gateway/util";
import { SatgVerdictBadge } from "./PipelineRun";

const ERROR_LABEL: Partial<Record<OutcomeCategory, string>> = { BACKEND_ERROR: "BACKEND ERROR", NETWORK_ERROR: "NETWORK ERROR" };

/** Stats and stream of the real backend responses received in this browser tab. */
export default function LiveTelemetry() {
  const entries = useSatgLog((s) => s.entries);
  const categories = entries.map((e) => categorize(e.outcome));
  const count = (c: OutcomeCategory) => categories.filter((x) => x === c).length;
  const verdicts = entries.length - count("BACKEND_ERROR") - count("NETWORK_ERROR");
  const blocked = count("BLOCKED") + count("ESCALATED");
  const recent = entries.slice(-8).reverse();

  return (
    <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_minmax(0,1.25fr)]">
      <div className="grid grid-cols-2 gap-4">
        <Stat label="Backend verdicts" value={verdicts} hint="received in this tab (resets on reload)" />
        <Stat label="Blocked" value={`${((blocked / Math.max(1, verdicts)) * 100).toFixed(1)}%`} hint={`${blocked} of ${verdicts} verdicts`} tone="text-red-400" />
        <Stat label="Allowed" value={count("ALLOWED")} hint="verdict only — nothing executed" tone="text-emerald-400" />
        <Stat
          label="p95 round trip"
          value={`${percentile(entries.map((e) => e.outcome.roundTripMs), 95).toFixed(1)}ms`}
          hint={`browser → proxy → backend · ${count("BACKEND_ERROR") + count("NETWORK_ERROR")} error(s)`}
          tone="text-accent"
        />
      </div>

      <Panel className="p-5">
        <SectionTitle right={<span className="font-mono text-[11.5px] text-subtle">server audit log is not exposed by the API</span>}>Live decision stream</SectionTitle>
        {recent.length === 0 ? (
          <p className="py-6 text-center text-[13.5px] text-muted">No requests sent yet. Every response from the SATG backend will appear here.</p>
        ) : (
          <ul className="space-y-1.5">
            <AnimatePresence initial={false}>
              {recent.map((e) => {
                const o = e.outcome;
                return (
                  <motion.li
                    key={e.seq}
                    layout
                    initial={{ opacity: 0, x: -12 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0 }}
                    className="grid grid-cols-[auto_minmax(0,1fr)_auto] items-center gap-3 rounded-lg px-2 py-1.5 hover:bg-surface sm:grid-cols-[48px_minmax(0,1fr)_150px_auto]"
                  >
                    <span className="font-mono text-[11.5px] text-subtle">#{e.seq}</span>
                    <span className="truncate font-mono text-[12.5px] text-fg">
                      {o.kind === "verdict" ? (o.verdict.tool ?? "(unreadable tool)") : e.presetTitle}
                      <span className="text-subtle"> · {o.kind === "verdict" ? `${o.verdict.agent_id ?? "?"} · ${o.verdict.rule_id}` : o.message}</span>
                    </span>
                    <span className="hidden sm:block">{o.kind === "verdict" ? <Hash value={o.verdict.request_id} n={8} className="text-subtle" /> : null}</span>
                    {o.kind === "verdict" ? (
                      <SatgVerdictBadge verdict={o.verdict.verdict} />
                    ) : (
                      <span className="rounded-md bg-amber-400/10 px-2 py-0.5 font-mono text-[11px] font-semibold text-amber-300 ring-1 ring-amber-400/30">
                        {ERROR_LABEL[categorize(o)]}
                      </span>
                    )}
                  </motion.li>
                );
              })}
            </AnimatePresence>
          </ul>
        )}
      </Panel>
    </div>
  );
}
