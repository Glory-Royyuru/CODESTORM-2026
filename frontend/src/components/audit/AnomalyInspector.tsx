"use client";

import { FileWarning, Fingerprint, ShieldAlert } from "lucide-react";
import { useState } from "react";
import HexView from "@/components/ui/HexView";
import { cx, Drawer, Hash, Panel, SectionTitle, VerdictBadge } from "@/components/ui/primitives";
import type { CryptArithmeticAnomalyRecord } from "@/lib/gateway/anomaly/ledger";
import { useAnomalyLedger, useGateway } from "@/lib/store";

const SEVERITY_CLS: Record<CryptArithmeticAnomalyRecord["risk_severity"], string> = {
  CRITICAL: "bg-red-500/15 text-red-300 ring-red-500/40",
  HIGH: "bg-orange-500/15 text-orange-300 ring-orange-500/40",
  ELEVATED: "bg-amber-400/10 text-amber-300 ring-amber-400/30",
};

const MITIGATION_TEXT: Record<CryptArithmeticAnomalyRecord["mitigation_action"], string> = {
  QUARANTINE_AND_HARD_DENY: "Payload quarantined; call hard-denied before parsing.",
  STRIP_AND_RETRY_SANDBOX: "Call denied; the agent may retry with the value as a decimal string.",
  ISOLATE_SESSION: "Session isolated: every later call in it is quarantined.",
};

function Severity({ s }: { s: CryptArithmeticAnomalyRecord["risk_severity"] }) {
  return <span className={cx("rounded-md px-2 py-0.5 font-mono text-[11px] font-semibold ring-1", SEVERITY_CLS[s])}>{s}</span>;
}

/** Quarantined crypt-arithmetic tampering incidents from the engine's append-only AnomalyLedger. */
export default function AnomalyInspector({ onOpenReceipt }: { onOpenReceipt: (receiptId: string) => void }) {
  const gw = useGateway();
  const records = useAnomalyLedger();
  const [openId, setOpenId] = useState<string | null>(null);
  const rows = [...records].reverse();
  const open = records.find((r) => r.anomaly_id === openId) ?? null;
  const receipt = open ? gw.ledger.find((e) => e.receipt.body.receiptId === open.ed25519_receipt_id)?.receipt : undefined;
  const bySeverity = (s: CryptArithmeticAnomalyRecord["risk_severity"]) => records.filter((r) => r.risk_severity === s).length;

  return (
    <div className="space-y-5">
      <div className="grid gap-3 sm:grid-cols-4">
        {[
          { label: "Quarantined", value: records.length, cls: "text-fg" },
          { label: "Critical", value: bySeverity("CRITICAL"), cls: "text-red-300" },
          { label: "High", value: bySeverity("HIGH"), cls: "text-orange-300" },
          { label: "Sessions isolated", value: new Set(records.filter((r) => r.mitigation_action === "ISOLATE_SESSION").map((r) => r.session_id)).size, cls: "text-accent" },
        ].map((s) => (
          <Panel key={s.label} className="p-4">
            <p className="text-[11.5px] font-medium uppercase tracking-[0.1em] text-subtle">{s.label}</p>
            <p className={cx("mt-1 font-mono text-[26px] font-semibold", s.cls)}>{s.value}</p>
          </Panel>
        ))}
      </div>

      <Panel className="overflow-hidden">
        <div className="scrollbar-thin overflow-x-auto">
          <table className="w-full min-w-[980px] text-left">
            <thead>
              <tr className="border-b border-line font-mono text-[11px] uppercase tracking-[0.08em] text-subtle">
                <th className="px-4 py-3 font-medium">Time</th>
                <th className="px-4 py-3 font-medium">Anomaly</th>
                <th className="px-4 py-3 font-medium">Severity</th>
                <th className="px-4 py-3 font-medium">Location</th>
                <th className="px-4 py-3 font-medium">Agent</th>
                <th className="px-4 py-3 font-medium">Fingerprint</th>
                <th className="px-4 py-3 font-medium">Mitigation</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.anomaly_id} onClick={() => setOpenId(r.anomaly_id)} className="cursor-pointer border-b border-line/60 transition-colors last:border-0 hover:bg-surface">
                  <td className="whitespace-nowrap px-4 py-3 font-mono text-[12px] text-code">{new Date(r.timestamp).toLocaleTimeString([], { hour12: false })}</td>
                  <td className="px-4 py-3 font-mono text-[12px] font-semibold text-fg">{r.anomaly_type}</td>
                  <td className="px-4 py-3">
                    <Severity s={r.risk_severity} />
                  </td>
                  <td className="px-4 py-3 font-mono text-[11.5px] text-muted">{r.location}</td>
                  <td className="px-4 py-3 font-mono text-[12px] text-fg/85">{r.agent_id.replace("agent:", "")}</td>
                  <td className="px-4 py-3">
                    <Hash value={r.raw_payload_sha256} n={12} />
                  </td>
                  <td className="px-4 py-3 font-mono text-[11px] text-red-300">{r.mitigation_action}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {!rows.length && (
            <div className="flex flex-col items-center gap-2 p-10 text-center">
              <ShieldAlert className="h-6 w-6 text-subtle" />
              <p className="text-[14px] text-subtle">No crypt-arithmetic anomalies quarantined yet.</p>
            </div>
          )}
        </div>
      </Panel>

      <Drawer
        open={!!open}
        onClose={() => setOpenId(null)}
        width="max-w-2xl"
        title={
          open && (
            <span className="flex flex-wrap items-center gap-2">
              <FileWarning className="h-4 w-4 text-red-300" />
              {open.anomaly_type}
            </span>
          )
        }
      >
        {open && (
          <div className="space-y-6">
            <div className="flex flex-wrap items-center gap-2">
              <Severity s={open.risk_severity} />
              <span className="rounded-md border border-line bg-surface px-2 py-0.5 font-mono text-[11px] text-muted">{open.location}</span>
              <span className="rounded-md border border-line bg-surface px-2 py-0.5 font-mono text-[11px] text-muted">{open.tool}</span>
            </div>

            <section>
              <SectionTitle>Detected violation</SectionTitle>
              <p className="rounded-lg border border-red-500/30 bg-red-500/5 p-3 font-mono text-[12.5px] text-red-200">{open.parser_error_detail}</p>
            </section>

            <section>
              <SectionTitle right={<span className="font-mono text-[11px] text-subtle">{open.raw_payload_bytes} B raw · never stored</span>}>Quarantined hex snippet</SectionTitle>
              <HexView hex={open.quarantined_hex_snippet} totalBytes={open.raw_payload_bytes} />
              <p className="mt-2 flex items-center gap-2 font-mono text-[11.5px] text-subtle">
                <Fingerprint className="h-3.5 w-3.5" /> {open.raw_payload_sha256}
              </p>
            </section>

            <section>
              <SectionTitle>Mitigation</SectionTitle>
              <p className="text-[13px] text-muted">
                <span className="font-mono font-semibold text-red-300">{open.mitigation_action}</span> — {MITIGATION_TEXT[open.mitigation_action]}
              </p>
            </section>

            <section className="rounded-xl border border-line bg-black/20 p-4">
              <SectionTitle>Deterministic HARD_DENY receipt</SectionTitle>
              {receipt ? (
                <div className="space-y-2 font-mono text-[12px]">
                  <div className="flex flex-wrap items-center gap-2">
                    <VerdictBadge verdict={receipt.body.verdict} />
                    <span className="text-subtle">
                      #{receipt.body.seq} · {receipt.body.tool} · session {open.session_id.slice(0, 13)}
                    </span>
                  </div>
                  <p className="text-subtle">
                    Ed25519 receipt <Hash value={open.ed25519_receipt_id} n={8} /> · hash <Hash value={receipt.hash} n={8} />
                  </p>
                  <p className="break-words text-[12px] text-muted">{receipt.body.counterfactual}</p>
                  <button
                    type="button"
                    onClick={() => {
                      setOpenId(null);
                      onOpenReceipt(open.ed25519_receipt_id);
                    }}
                    className="text-[12.5px] font-semibold text-accent hover:underline"
                  >
                    Open and verify receipt →
                  </button>
                </div>
              ) : (
                <p className="text-[12.5px] text-subtle">Receipt {open.ed25519_receipt_id} is not in this ledger.</p>
              )}
            </section>
          </div>
        )}
      </Drawer>
    </div>
  );
}
