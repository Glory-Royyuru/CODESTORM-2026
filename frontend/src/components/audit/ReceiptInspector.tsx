"use client";

import { AnimatePresence, motion } from "framer-motion";
import { ArrowDown, CheckCircle2, FlaskConical, KeyRound, Link2, XCircle } from "lucide-react";
import { useState } from "react";
import { Button, CopyButton, cx, Hash, JsonBlock, SectionTitle, VerdictBadge } from "@/components/ui/primitives";
import { verifyReceipt, type ReceiptVerification } from "@/lib/gateway/receipts";
import type { DecisionReceipt, LedgerEntry, StageId } from "@/lib/gateway/types";

function Check({ ok, label }: { ok: boolean; label: string }) {
  return (
    <li className={cx("flex items-center gap-2 rounded-lg px-2.5 py-1.5 font-mono text-[12px]", ok ? "bg-emerald-400/10 text-emerald-300" : "bg-red-500/10 text-red-300")}>
      {ok ? <CheckCircle2 className="h-3.5 w-3.5" /> : <XCircle className="h-3.5 w-3.5" />}
      {label}: {ok ? "PASS" : "FAIL"}
    </li>
  );
}

const STAGE_ORDER: StageId[] = ["ingress", "canonicalize", "registry", "policy", "ml", "fusion", "dlp", "receipt"];

export default function ReceiptInspector({ entry, prev, next }: { entry: LedgerEntry; prev: DecisionReceipt | null; next: DecisionReceipt | null }) {
  const r = entry.receipt;
  const b = r.body;
  const [result, setResult] = useState<(ReceiptVerification & { tampered: boolean }) | null>(null);

  const verify = (tamper: boolean) => {
    // Tamper test operates on a deep copy — the stored receipt is never modified.
    const candidate: DecisionReceipt = tamper ? { ...r, body: { ...structuredClone(b), verdict: b.verdict === "ALLOW" ? "BLOCK" : "ALLOW" } } : r;
    setResult({ ...verifyReceipt(candidate, prev), tampered: tamper });
  };

  const maxAbs = Math.max(0.01, ...b.contributions.map((c) => Math.abs(c.contribution)));
  const maxLat = Math.max(1, ...STAGE_ORDER.map((s) => b.stageLatenciesMs[s] ?? 0));

  return (
    <div className="grid gap-6 lg:grid-cols-[minmax(0,1.1fr)_minmax(0,1fr)]">
      {/* left column */}
      <div className="min-w-0 space-y-6">
        <div className="flex flex-wrap items-center gap-3">
          <VerdictBadge verdict={b.verdict} size="lg" />
          <span className="font-mono text-[12px] text-subtle">
            rules {b.deterministicVerdict} · ML {b.mlVerdict}
            {b.mlAbstained ? " (conformal abstain)" : ""} · risk {b.riskScore.toFixed(3)}
          </span>
        </div>

        <section>
          <SectionTitle right={<CopyButton text={r.canonical} label="Copy canonical JSON" />}>Canonical receipt</SectionTitle>
          <JsonBlock value={b} className="max-h-[420px]" />
        </section>

        {b.findings.length > 0 && (
          <section>
            <SectionTitle>Rule findings</SectionTitle>
            <ul className="space-y-1.5">
              {b.findings.map((f) => (
                <li key={f.ruleId} className="rounded-lg border border-line bg-surface p-2.5">
                  <div className="flex items-center justify-between gap-2 font-mono text-[12px]">
                    <span className="text-fg">
                      <span className="text-subtle">{f.module} · </span>
                      {f.ruleId}@{f.ruleVersion}
                    </span>
                    <VerdictBadge verdict={f.outcome} />
                  </div>
                  <p className="mt-1 text-[12.5px] text-muted">{f.reason}</p>
                </li>
              ))}
            </ul>
          </section>
        )}
      </div>

      {/* right column */}
      <div className="min-w-0 space-y-6">
        <section className="rounded-xl border border-line bg-black/20 p-4">
          <SectionTitle>
            <span className="flex items-center gap-2">
              <KeyRound className="h-4 w-4" /> Ed25519 signature
            </span>
          </SectionTitle>
          <dl className="space-y-2 font-mono text-[11.5px]">
            <div>
              <dt className="text-subtle">public key</dt>
              <dd className="break-all text-code">{r.publicKey}</dd>
            </div>
            <div>
              <dt className="text-subtle">signature</dt>
              <dd className="break-all text-code">{r.signature}</dd>
            </div>
            <div>
              <dt className="text-subtle">sha256(canonical)</dt>
              <dd className="break-all text-code">{r.hash}</dd>
            </div>
          </dl>
          <div className="mt-4 flex flex-wrap gap-2">
            <Button variant="primary" className="h-9 text-[13px]" onClick={() => verify(false)}>
              <CheckCircle2 className="h-4 w-4" /> Verify receipt
            </Button>
            <Button variant="danger" className="h-9 text-[13px]" onClick={() => verify(true)}>
              <FlaskConical className="h-4 w-4" /> Tamper test
            </Button>
          </div>
          <AnimatePresence mode="wait">
            {result && (
              <motion.div key={`${result.tampered}-${result.ok}`} initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} className="mt-4">
                <div className={cx("mb-2 flex items-center gap-2 text-[13.5px] font-semibold", result.ok ? "text-emerald-400" : "text-red-400")}>
                  {result.ok ? <CheckCircle2 className="h-4 w-4" /> : <XCircle className="h-4 w-4" />}
                  {result.ok ? "Receipt authentic and chained" : result.tampered ? `Tampered copy rejected (verdict flipped to ${b.verdict === "ALLOW" ? "BLOCK" : "ALLOW"})` : "Verification failed"}
                </div>
                <ul className="grid grid-cols-2 gap-1.5">
                  <Check ok={result.canonicalMatches} label="canonical" />
                  <Check ok={result.hashValid} label="sha256" />
                  <Check ok={result.signatureValid} label="ed25519" />
                  <Check ok={result.chainValid} label="chain link" />
                </ul>
              </motion.div>
            )}
          </AnimatePresence>
        </section>

        <section>
          <SectionTitle>
            <span className="flex items-center gap-2">
              <Link2 className="h-4 w-4" /> SHA-256 hash chain
            </span>
          </SectionTitle>
          <div className="space-y-1.5 font-mono text-[11.5px]">
            <div className="rounded-lg border border-line bg-surface px-3 py-2">
              <span className="text-subtle">#{b.seq - 1} hash </span>
              <Hash value={prev?.hash ?? "0".repeat(64)} n={14} />
            </div>
            <div className="flex items-center gap-2 pl-4 text-subtle">
              <ArrowDown className="h-3.5 w-3.5" /> prevHash {(prev?.hash ?? "0".repeat(64)) === b.prevHash ? <span className="text-emerald-400">✓ linked</span> : <span className="text-red-400">✗ broken</span>}
            </div>
            <div className="rounded-lg border border-accent/40 bg-accent/5 px-3 py-2">
              <span className="text-subtle">#{b.seq} hash </span>
              <Hash value={r.hash} n={14} />
            </div>
            {next && (
              <>
                <div className="flex items-center gap-2 pl-4 text-subtle">
                  <ArrowDown className="h-3.5 w-3.5" /> next.prevHash {next.body.prevHash === r.hash ? <span className="text-emerald-400">✓ linked</span> : <span className="text-red-400">✗ broken</span>}
                </div>
                <div className="rounded-lg border border-line bg-surface px-3 py-2">
                  <span className="text-subtle">#{next.body.seq} hash </span>
                  <Hash value={next.hash} n={14} />
                </div>
              </>
            )}
          </div>
        </section>

        <section>
          <SectionTitle>ML feature contributions (SHAP-style)</SectionTitle>
          <ul className="space-y-2">
            {b.contributions.map((c) => {
              const w = (Math.abs(c.contribution) / maxAbs) * 50;
              const pos = c.contribution >= 0;
              return (
                <li key={c.feature} className="grid grid-cols-[150px_minmax(0,1fr)_56px] items-center gap-3 font-mono text-[11.5px]">
                  <span className="truncate text-muted">{c.feature}</span>
                  <span className="relative h-4 rounded bg-surface">
                    <span className="absolute left-1/2 top-0 h-full w-px bg-line" />
                    <motion.span
                      initial={{ width: 0 }}
                      animate={{ width: `${w}%` }}
                      transition={{ duration: 0.6 }}
                      className={cx("absolute top-0 h-full rounded", pos ? "left-1/2 bg-gradient-to-r from-orange-500/70 to-red-500/80" : "right-1/2 bg-gradient-to-l from-emerald-400/70 to-emerald-600/60")}
                    />
                  </span>
                  <span className={cx("text-right", pos ? "text-orange-300" : "text-emerald-300")}>
                    {pos ? "+" : ""}
                    {c.contribution.toFixed(2)}
                  </span>
                </li>
              );
            })}
          </ul>
          <p className="mt-2 text-[11.5px] text-subtle">Log-odds contribution vs. benign baseline. Positive bars push risk up; ML may only escalate, never loosen a rule veto.</p>
        </section>

        <section className="rounded-xl border border-accent/25 bg-accent/5 p-4">
          <SectionTitle>Counterfactual explanation</SectionTitle>
          <p className="text-[13.5px] leading-relaxed text-fg/90">{b.counterfactual}</p>
        </section>

        <section>
          <SectionTitle right={<span className="font-mono text-[11.5px] text-subtle">det {b.deterministicLatencyMs}ms · total {b.totalLatencyMs}ms</span>}>Stage latencies</SectionTitle>
          <ul className="space-y-1.5">
            {STAGE_ORDER.map((s) => (
              <li key={s} className="grid grid-cols-[96px_minmax(0,1fr)_56px] items-center gap-3 font-mono text-[11.5px]">
                <span className="text-muted">{s}</span>
                <span className="h-2 rounded bg-surface">
                  <motion.span initial={{ width: 0 }} animate={{ width: `${((b.stageLatenciesMs[s] ?? 0) / maxLat) * 100}%` }} className={cx("block h-full rounded", s === "ml" ? "bg-accent" : "bg-sky-400/70")} />
                </span>
                <span className="text-right text-code">{(b.stageLatenciesMs[s] ?? 0).toFixed(2)}</span>
              </li>
            ))}
          </ul>
        </section>
      </div>
    </div>
  );
}
