"use client";

import { AnimatePresence, motion } from "framer-motion";
import Link from "next/link";
import { Hash, Panel, SectionTitle, Stat, VerdictBadge } from "@/components/ui/primitives";
import { isEscalated } from "@/lib/gateway/runner";
import { percentile } from "@/lib/gateway/util";
import { useGateway } from "@/lib/store";

export default function LiveTelemetry() {
  const gw = useGateway();
  const ledger = gw.ledger;
  const blocked = ledger.filter((e) => isEscalated(e.receipt.body.verdict)).length;
  const ran = ledger.filter((e) => e.receipt.body.stageLatenciesMs.ml);
  const trifecta = [...gw.sessions.values()].filter((s) => s.flags.privateData && s.flags.untrustedContent && s.flags.outboundChannel).length;
  const recent = ledger.slice(-8).reverse();

  return (
    <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_minmax(0,1.25fr)]">
      <div className="grid grid-cols-2 gap-4">
        <Stat label="Decisions signed" value={ledger.length} hint="100% of calls receive a receipt" />
        <Stat label="Escalated / blocked" value={`${((blocked / Math.max(1, ledger.length)) * 100).toFixed(1)}%`} hint={`${blocked} of ${ledger.length} calls`} tone="text-red-400" />
        <Stat label="p95 deterministic" value={`${percentile(ledger.map((e) => e.receipt.body.deterministicLatencyMs), 95).toFixed(1)}ms`} hint="budget < 15ms" tone="text-emerald-400" />
        <Stat label="p95 ML-augmented" value={`${percentile(ran.map((e) => e.receipt.body.totalLatencyMs), 95).toFixed(1)}ms`} hint={`budget < 40ms · ${trifecta} trifecta session(s)`} tone="text-accent" />
      </div>

      <Panel className="p-5">
        <SectionTitle right={<Link href="/audit" className="text-[12.5px] font-semibold text-accent hover:underline">Full ledger →</Link>}>
          Live decision stream
        </SectionTitle>
        <ul className="space-y-1.5">
          <AnimatePresence initial={false}>
            {recent.map((e) => {
              const b = e.receipt.body;
              return (
                <motion.li
                  key={b.receiptId}
                  layout
                  initial={{ opacity: 0, x: -12 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0 }}
                  className="grid grid-cols-[auto_minmax(0,1fr)_auto] items-center gap-3 rounded-lg px-2 py-1.5 hover:bg-surface sm:grid-cols-[48px_minmax(0,1fr)_120px_auto]"
                >
                  <span className="font-mono text-[11.5px] text-subtle">#{b.seq}</span>
                  <span className="truncate font-mono text-[12.5px] text-fg">
                    {b.tool}
                    <span className="text-subtle"> · {b.principal.agentId.replace("agent:", "")}</span>
                  </span>
                  <span className="hidden sm:block">
                    <Hash value={e.receipt.hash} n={6} className="text-subtle" />
                  </span>
                  <VerdictBadge verdict={b.verdict} />
                </motion.li>
              );
            })}
          </AnimatePresence>
        </ul>
      </Panel>
    </div>
  );
}
