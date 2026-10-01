"use client";

import { ScrollText, ShieldAlert, ShieldCheck, Search } from "lucide-react";
import { useState } from "react";
import { Button, cx, Hash, Modal, PageHeader, Panel, Tabs, VerdictBadge } from "@/components/ui/primitives";
import { verifyReceipt } from "@/lib/gateway/receipts";
import type { Verdict } from "@/lib/gateway/types";
import { useAnomalyLedger, useGateway, useUi } from "@/lib/store";
import AnomalyInspector from "./AnomalyInspector";
import ReceiptInspector from "./ReceiptInspector";

const TABS: { id: string; label: string; match: (v: Verdict) => boolean }[] = [
  { id: "ALL", label: "All", match: () => true },
  { id: "ALLOWED", label: "Allowed", match: (v) => v === "ALLOW" || v === "MONITOR" },
  { id: "BLOCKED", label: "Blocked", match: (v) => v === "BLOCK" || v === "QUARANTINE" },
  { id: "ESCALATED", label: "Escalated", match: (v) => v === "STEP_UP" || v === "HUMAN_APPROVAL" },
];

export default function AuditView() {
  const gw = useGateway();
  const toast = useUi((s) => s.toast);
  const [tab, setTab] = useState("ALL");
  const [q, setQ] = useState("");
  const [selected, setSelected] = useState<string | null>(() => new URLSearchParams(window.location.search).get("receipt"));
  const [chain, setChain] = useState<{ ok: number; total: number; firstBad?: number } | null>(null);
  const [view, setView] = useState<"receipts" | "anomalies">(() => (new URLSearchParams(window.location.search).get("view") === "anomalies" ? "anomalies" : "receipts"));
  const anomalyCount = useAnomalyLedger().length;

  const ledger = gw.ledger;
  const t = TABS.find((x) => x.id === tab)!;
  const needle = q.trim().toLowerCase();
  const rows = ledger
    .filter((e) => t.match(e.receipt.body.verdict))
    .filter((e) => !needle || [e.receipt.body.tool, e.receipt.body.sessionId, e.receipt.body.principal.agentId, e.receipt.hash].some((s) => s.toLowerCase().includes(needle)))
    .slice()
    .reverse();

  const idx = ledger.findIndex((e) => e.receipt.body.receiptId === selected);
  const entry = idx >= 0 ? ledger[idx] : null;

  const verifyAll = () => {
    let ok = 0;
    let firstBad: number | undefined;
    ledger.forEach((e, i) => {
      if (verifyReceipt(e.receipt, i ? ledger[i - 1].receipt : null).ok) ok++;
      else firstBad ??= e.receipt.body.seq;
    });
    setChain({ ok, total: ledger.length, firstBad });
    toast({ tone: ok === ledger.length ? "success" : "danger", title: `Demo hash chain ${ok === ledger.length ? "intact" : "BROKEN"}`, detail: `${ok}/${ledger.length} demo receipts verified (Ed25519 + SHA-256 + links, in the browser)` });
  };

  return (
    <div>
      <PageHeader
        eyebrow="M10 — Cryptographic audit receipts · demo engine"
        title={
          <>
            Audit <span className="text-accent">ledger</span>
          </>
        }
        description="A simulated ledger kept by the in-browser demo engine: each demo-engine decision, including every BLOCK, is canonicalized, Ed25519-signed and hash-chained to the previous receipt, and any row can be verified in your browser. Live Gateway requests do not appear here; the SATG backend keeps its own in-memory audit log, which the API does not expose, and has no signed receipts or hash chain yet."
        actions={
          <Button variant="primary" onClick={verifyAll}>
            <ShieldCheck className="h-4 w-4" /> Verify entire chain
          </Button>
        }
      />

      {chain && (
        <Panel className={cx("mb-5 flex flex-wrap items-center gap-3 px-5 py-3 font-mono text-[12.5px]", chain.ok === chain.total ? "text-emerald-300" : "text-red-300")}>
          <ShieldCheck className="h-4 w-4" />
          {chain.ok}/{chain.total} demo receipts verified · genesis → #{chain.total}
          {chain.firstBad && ` · first failure at #${chain.firstBad}`}
          <span className="text-subtle">· demo signing key {ledger[0]?.receipt.publicKey.slice(0, 16)}…</span>
        </Panel>
      )}

      <Tabs
        className="mb-5"
        label="Audit view"
        value={view}
        onChange={setView}
        items={[
          { id: "receipts", label: <><ScrollText className="h-4 w-4" />Receipt ledger</>, count: ledger.length },
          { id: "anomalies", label: <><ShieldAlert className="h-4 w-4" />Anomaly Inspector</>, count: anomalyCount },
        ]}
      />

      {view === "anomalies" ? (
        <AnomalyInspector onOpenReceipt={setSelected} />
      ) : (
        <Panel className="overflow-hidden">
          <div className="flex flex-col gap-3 border-b border-line p-4 sm:flex-row sm:items-center sm:justify-between">
            <Tabs
              size="sm"
              label="Filter receipts by verdict"
              value={tab}
              onChange={setTab}
              items={TABS.map((x) => ({ id: x.id, label: x.label, count: ledger.filter((e) => x.match(e.receipt.body.verdict)).length }))}
            />
            <label className="flex h-10 items-center gap-2 rounded-xl border border-line bg-black/20 px-3 sm:w-80">
              <Search className="h-4 w-4 text-subtle" />
              <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Filter by tool, session, agent, hash…" className="w-full bg-transparent text-[13.5px] text-fg outline-none placeholder:text-subtle" />
            </label>
          </div>

          <div className="scrollbar-thin overflow-x-auto">
            <table className="w-full min-w-[980px] text-left">
              <thead>
                <tr className="border-b border-line font-mono text-[11px] uppercase tracking-[0.08em] text-subtle">
                  <th className="px-4 py-3 font-medium">#</th>
                  <th className="px-4 py-3 font-medium">Timestamp</th>
                  <th className="px-4 py-3 font-medium">Session</th>
                  <th className="px-4 py-3 font-medium">Agent principal</th>
                  <th className="px-4 py-3 font-medium">Tool</th>
                  <th className="px-4 py-3 font-medium">Verdict</th>
                  <th className="px-4 py-3 font-medium">Latency (det / total)</th>
                  <th className="px-4 py-3 font-medium">Receipt hash</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((e) => {
                  const b = e.receipt.body;
                  return (
                    <tr key={b.receiptId} onClick={() => setSelected(b.receiptId)} className="cursor-pointer border-b border-line/60 transition-colors last:border-0 hover:bg-surface">
                      <td className="px-4 py-3 font-mono text-[12px] text-subtle">{b.seq}</td>
                      <td className="whitespace-nowrap px-4 py-3 font-mono text-[12px] text-code">{new Date(b.timestamp).toLocaleTimeString([], { hour12: false })}</td>
                      <td className="px-4 py-3 font-mono text-[12px] text-muted">{b.sessionId.slice(0, 13)}</td>
                      <td className="px-4 py-3 font-mono text-[12px] text-fg/85">{b.principal.agentId.replace("agent:", "")}</td>
                      <td className="px-4 py-3 font-mono text-[12.5px] font-semibold text-fg">{b.tool}</td>
                      <td className="px-4 py-3">
                        <VerdictBadge verdict={b.verdict} />
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2 font-mono text-[11.5px] text-code">
                          <span className="relative h-1.5 w-20 overflow-hidden rounded bg-surface">
                            <span className="absolute inset-y-0 left-0 bg-sky-400/70" style={{ width: `${Math.min(100, (b.deterministicLatencyMs / 45) * 100)}%` }} />
                            <span className="absolute inset-y-0 bg-accent/80" style={{ left: `${Math.min(100, (b.deterministicLatencyMs / 45) * 100)}%`, width: `${Math.min(100, ((b.totalLatencyMs - b.deterministicLatencyMs) / 45) * 100)}%` }} />
                          </span>
                          {b.deterministicLatencyMs.toFixed(1)} / {b.totalLatencyMs.toFixed(1)}ms
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <Hash value={e.receipt.hash} n={8} />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            {!rows.length && <p className="p-8 text-center text-[14px] text-subtle">No receipts match.</p>}
          </div>
        </Panel>
      )}

      <Modal
        open={!!entry}
        onClose={() => setSelected(null)}
        title={
          entry && (
            <span className="flex flex-wrap items-center gap-2">
              Receipt #{entry.receipt.body.seq}
              <span className="font-mono text-[12.5px] font-normal text-subtle">
                {entry.receipt.body.tool} · {entry.receipt.body.receiptId}
              </span>
            </span>
          )
        }
      >
        {entry && <ReceiptInspector key={entry.receipt.body.receiptId} entry={entry} prev={idx > 0 ? ledger[idx - 1].receipt : null} next={ledger[idx + 1]?.receipt ?? null} />}
      </Modal>
    </div>
  );
}
