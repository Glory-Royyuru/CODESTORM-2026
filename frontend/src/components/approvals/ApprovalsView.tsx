"use client";

import { AnimatePresence, motion } from "framer-motion";
import { BadgeCheck, Ban, KeyRound, Play, Repeat, UserCheck, Users } from "lucide-react";
import Link from "next/link";
import { useMemo, useState, type ReactNode } from "react";
import { SatgVerdictBadge } from "@/components/gateway/PipelineRun";
import { LiveChip } from "@/components/provenance/LiveTraceView";
import { Button, cx, DemoTag, Disclosure, Hash, JsonBlock, PageHeader, Panel, SectionTitle, timeAgo, VerdictBadge } from "@/components/ui/primitives";
import type { ApprovalRequest, Verdict } from "@/lib/gateway/types";
import { toLiveTraces, type LiveTrace } from "@/lib/satg/liveTrace";
import { useSatgLog } from "@/lib/satg/log";
import { getGateway, useGateway, useUi } from "@/lib/store";

const OPERATORS = ["secops-lead (Dana K.)", "platform-owner (Leo V.)", "treasury-lead (Alex M.)", "ciso-delegate (Rin T.)"];

function ApprovalCard({ a, operator }: { a: ApprovalRequest; operator: string }) {
  const toast = useUi((s) => s.toast);
  const [lastRun, setLastRun] = useState<{ verdict: Verdict; reason: string } | null>(null);
  const gw = getGateway();
  const tier = gw.registry.get(a.envelope.tool)?.tier;

  const execute = () => {
    const res = gw.executeApproved(a.id);
    if (!res) return;
    const b = res.entry.receipt.body;
    const reason = b.findings.find((f) => f.outcome === b.verdict)?.reason ?? (b.executed ? "executed in sandbox with single-use grant" : "not executed");
    setLastRun({ verdict: b.verdict, reason });
    toast({ tone: b.executed ? "success" : "danger", title: `${a.envelope.tool} → ${b.verdict}`, detail: `${reason} · receipt #${b.seq}` });
  };

  return (
    <motion.div layout initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, scale: 0.97 }} className={cx("panel p-5 sm:p-6", a.status === "PENDING" && tier === 4 && "ring-1 ring-violet-500/30")}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <h3 className="font-mono text-[16px] font-semibold text-fg">{a.envelope.tool}</h3>
            <VerdictBadge verdict={a.kind} />
            {tier === 4 && <span className="rounded-md bg-red-500/10 px-2 py-0.5 font-mono text-[11px] font-semibold text-red-300">Tier 4 · destructive</span>}
          </div>
          <p className="mt-1 font-mono text-[12px] text-subtle">
            {a.envelope.principal.agentId} on behalf of {a.envelope.principal.userId} · {timeAgo(a.createdAt)}
          </p>
        </div>
        <span className={cx("rounded-md px-2.5 py-1 font-mono text-[12px] font-semibold", a.status === "PENDING" ? "bg-amber-400/10 text-amber-300" : a.status === "REJECTED" ? "bg-red-500/10 text-red-300" : "bg-emerald-400/10 text-emerald-300")}>{a.status}</span>
      </div>

      <p className="mt-4 text-[13.5px] leading-snug text-fg/85">
        <span className="font-semibold text-violet-300">Step-up reason · </span>
        {a.reason}
      </p>

      <div className="mt-4 grid gap-4 md:grid-cols-[minmax(0,1fr)_220px]">
        <JsonBlock value={a.envelope.arguments} className="max-h-40" />
        <div className="space-y-3">
          <div>
            <p className="mb-1 flex justify-between font-mono text-[11px] text-subtle">
              <span>ML risk score</span>
              <span>{a.riskScore.toFixed(2)}</span>
            </p>
            <div className="h-2 overflow-hidden rounded-full bg-surface">
              <div className="h-full rounded-full bg-gradient-to-r from-amber-400 to-red-500" style={{ width: `${Math.max(4, a.riskScore * 100)}%` }} />
            </div>
          </div>
          <div>
            <p className="mb-1.5 font-mono text-[11px] text-subtle">
              approvals {a.approvals.length}/{a.requiredApprovals}
            </p>
            <ul className="space-y-1">
              {Array.from({ length: a.requiredApprovals }, (_, i) => a.approvals[i]).map((ap, i) => (
                <li key={i} className={cx("flex items-center gap-2 rounded-lg border px-2.5 py-1.5 text-[12px]", ap ? "border-emerald-400/30 bg-emerald-400/10 text-emerald-300" : "border-dashed border-line text-subtle")}>
                  {ap ? <UserCheck className="h-3.5 w-3.5" /> : <Users className="h-3.5 w-3.5" />}
                  <span className="truncate">{ap ? ap.approver : `approver ${i + 1}`}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>

      {a.status === "PENDING" && (
        <div className="mt-5 flex flex-wrap gap-2">
          <Button
            variant="primary"
            onClick={() => {
              const r = gw.approve(a.id, operator);
              toast({ tone: r.ok ? "success" : "warn", title: r.ok ? `Approved by ${operator}` : "Approval refused", detail: r.message });
            }}
          >
            <BadgeCheck className="h-4 w-4" /> Approve as {operator.split(" ")[0]}
          </Button>
          <Button
            variant="danger"
            onClick={() => {
              gw.reject(a.id, operator);
              toast({ tone: "danger", title: `${a.envelope.tool} rejected`, detail: `by ${operator}` });
            }}
          >
            <Ban className="h-4 w-4" /> Reject
          </Button>
        </div>
      )}

      {a.grant && (
        <div className="mt-5 rounded-xl border border-emerald-400/30 bg-emerald-400/5 p-4">
          <SectionTitle>
            <span className="flex items-center gap-2 text-emerald-300">
              <KeyRound className="h-4 w-4" /> Single-use capability grant
            </span>
          </SectionTitle>
          <dl className="grid gap-x-6 gap-y-1.5 font-mono text-[11.5px] sm:grid-cols-2">
            <div className="flex justify-between gap-2"><dt className="text-subtle">grant</dt><dd className="text-code">{a.grant.grantId}</dd></div>
            <div className="flex justify-between gap-2"><dt className="text-subtle">expires</dt><dd className="text-code">{new Date(a.grant.expiresAt).toLocaleTimeString([], { hour12: false })}</dd></div>
            <div className="flex justify-between gap-2"><dt className="text-subtle">state</dt><dd className={a.grant.used ? "text-amber-300" : "text-emerald-300"}>{a.grant.used ? "CONSUMED" : "UNUSED"}</dd></div>
          </dl>
          <Disclosure className="mt-3" summary="Argument digest and signature">
            <dl className="space-y-1.5 font-mono text-[11.5px]">
              <div className="flex justify-between gap-2"><dt className="text-subtle">args digest</dt><dd><Hash value={a.grant.argsDigest} n={10} /></dd></div>
              <div><dt className="text-subtle">ed25519 signature</dt><dd className="break-all text-code">{a.grant.signature}</dd></div>
            </dl>
          </Disclosure>
          <div className="mt-4 flex flex-wrap items-center gap-2">
            {a.status === "APPROVED" && (
              <Button variant="primary" className="h-9 text-[13px]" onClick={execute}>
                <Play className="h-4 w-4" /> Execute with grant
              </Button>
            )}
            {a.status === "EXECUTED" && (
              <Button variant="secondary" className="h-9 text-[13px]" onClick={execute} title="Re-submit the same grant — it must be rejected">
                <Repeat className="h-4 w-4" /> Replay grant (single-use test)
              </Button>
            )}
            <AnimatePresence>
              {lastRun && (
                <motion.span initial={{ opacity: 0, x: -6 }} animate={{ opacity: 1, x: 0 }} className="flex items-center gap-2 text-[12.5px] text-muted">
                  <VerdictBadge verdict={lastRun.verdict} />
                  {lastRun.reason}
                </motion.span>
              )}
            </AnimatePresence>
          </div>
        </div>
      )}
    </motion.div>
  );
}

function LiveFact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex items-baseline justify-between gap-3 py-1">
      <dt className="text-subtle">{label}</dt>
      <dd className="min-w-0 truncate text-right text-code">{children}</dd>
    </div>
  );
}

/** One real ESCALATE from the SATG backend, read-only: the backend has no approval queue or approve/reject API. */
function LiveEscalationCard({ t }: { t: LiveTrace }) {
  const sandbox = t.stages.find((s) => s.key === "SANDBOX");
  return (
    <div className="panel p-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2">
          {t.verdict && <SatgVerdictBadge verdict={t.verdict} />}
          <span className="font-mono text-[13px] font-semibold text-fg">
            {t.ruleId}
            {t.ml?.riskLevel && <span className="font-normal text-subtle"> · {t.ml.riskLevel}</span>}
          </span>
        </div>
        <span className="font-mono text-[11.5px] text-subtle">
          #{t.seq} · {new Date(t.at).toLocaleTimeString([], { hour12: false })}
        </span>
      </div>
      <h3 className="mt-3 font-mono text-[16px] font-semibold text-fg">{t.request.tool ?? t.title}</h3>
      <p className="mt-0.5 font-mono text-[12px] text-subtle">
        agent {t.request.agentId ?? "—"} · {t.source === "agent" ? "Agent Console" : "Request studio"}
      </p>
      {t.reason && <p className="mt-3 text-[13px] leading-snug text-fg/85">{t.reason}</p>}
      <dl className="mt-3 rounded-xl border border-line bg-black/20 px-3 py-2 font-mono text-[12px]">
        <LiveFact label="Deterministic decision">{t.decision ? `${t.decision.deterministicVerdict} · ${t.decision.deterministicRuleId}` : "— not in response"}</LiveFact>
        <LiveFact label="ML risk">
          {t.ml?.riskScore != null ? `${t.ml.riskScore.toFixed(3)}${t.ml.modelVersion ? ` · ${t.ml.modelVersion}` : ""}` : "— not in response"}
        </LiveFact>
        <LiveFact label="Sandbox">{sandbox ? sandbox.status.replace("_", " ").toUpperCase() : "—"}</LiveFact>
        <LiveFact label="HTTP · round trip">
          {t.httpStatus ?? "—"} · {t.roundTripMs} ms
        </LiveFact>
        <LiveFact label="request_id">{t.requestId ? <Hash value={t.requestId} n={10} /> : "—"}</LiveFact>
      </dl>
      <div className="mt-3 flex flex-wrap items-center justify-between gap-2">
        <LiveChip />
        <Link href={`/provenance/live?seq=${t.seq}`} className="text-[12.5px] font-semibold text-accent hover:underline">
          Open in Live Request Trace →
        </Link>
      </div>
    </div>
  );
}

/** Real ESCALATE decisions this tab received through the Live Gateway (in-memory SATG log). */
function LiveEscalations() {
  const entries = useSatgLog((s) => s.entries);
  const escalations = useMemo(() => toLiveTraces(entries).filter((t) => t.verdict === "ESCALATE"), [entries]);
  return (
    <section>
      <SectionTitle right={<LiveChip />}>Live escalations · {escalations.length}</SectionTitle>
      <p className="-mt-1 mb-4 max-w-3xl text-[13px] leading-relaxed text-muted">
        Real ESCALATE decisions captured from the Live Gateway in this browser tab. Unlike the demo queue below, these come from the SATG backend. They are live
        escalation events, not an approval queue: backend approval actions are not implemented, so nothing here can be approved, rejected or executed.
      </p>
      {escalations.length ? (
        <div className="grid gap-5 xl:grid-cols-2">
          {escalations.map((t) => (
            <LiveEscalationCard key={t.seq} t={t} />
          ))}
        </div>
      ) : (
        <Panel className="p-6 text-center text-[13.5px] text-subtle">
          No live escalations in this tab yet. An ML-001 ESCALATE from the{" "}
          <Link href="/" className="font-semibold text-accent hover:underline">
            Live Gateway
          </Link>{" "}
          will appear here. The list is kept in memory and resets on reload.
        </Panel>
      )}
    </section>
  );
}

export default function ApprovalsView() {
  const gw = useGateway();
  const [operator, setOperator] = useState(OPERATORS[0]);
  const pending = gw.approvals.filter((a) => a.status === "PENDING");
  const active = gw.approvals.filter((a) => a.status === "APPROVED" || a.status === "EXECUTED");
  const closed = gw.approvals.filter((a) => a.status === "REJECTED");

  return (
    <div>
      <PageHeader
        eyebrow="M3 · M11 — Escalations & two-person verification"
        title={
          <>
            Approvals <span className="text-accent">queue</span>
          </>
        }
        description="Live escalations are real ESCALATE decisions this tab received from the SATG backend, shown read-only: the backend holds them and has no approval workflow yet. The demo queue below is seeded by the in-browser engine: its Tier-4 destructive calls and ML step-ups wait there, and two distinct approvers produce a simulated Ed25519-signed capability grant bound to the exact canonical arguments, usable once for five minutes."
        actions={
          <label className="flex items-center gap-2 rounded-xl border border-line bg-surface px-3 py-2 text-[13px] text-muted">
            Acting as (demo operator)
            <select value={operator} onChange={(e) => setOperator(e.target.value)} className="bg-transparent font-mono text-[13px] text-fg outline-none">
              {OPERATORS.map((o) => (
                <option key={o} value={o} className="bg-[#121118]">
                  {o}
                </option>
              ))}
            </select>
          </label>
        }
      />

      <div className="space-y-10">
        <LiveEscalations />

        <div className="space-y-8 border-t border-line pt-8">
        <div>
          <SectionTitle right={<DemoTag label="SIM" />}>Demo approval queue</SectionTitle>
          <p className="-mt-1 text-[13px] text-muted">Simulated by the in-browser demo engine. These records are not backend escalations.</p>
        </div>
        <section>
          <SectionTitle right={<DemoTag />}>Pending · {pending.length}</SectionTitle>
          <div className="grid gap-5 2xl:grid-cols-2">
            <AnimatePresence mode="popLayout">
              {pending.map((a) => (
                <ApprovalCard key={a.id} a={a} operator={operator} />
              ))}
            </AnimatePresence>
          </div>
          {!pending.length && (
            <Panel className="p-8 text-center text-[14px] text-subtle">
              Queue is clear. This demo queue is seeded by the in-browser engine. Live Gateway ESCALATE results are held, not queued; an approval workflow is not implemented in the backend yet.
            </Panel>
          )}
        </section>

        {active.length > 0 && (
          <section>
            <SectionTitle>Granted · {active.length}</SectionTitle>
            <div className="grid gap-5 2xl:grid-cols-2">
              {active.map((a) => (
                <ApprovalCard key={a.id} a={a} operator={operator} />
              ))}
            </div>
          </section>
        )}

        {closed.length > 0 && (
          <section>
            <SectionTitle>Rejected · {closed.length}</SectionTitle>
            <ul className="space-y-1.5">
              {closed.map((a) => (
                <li key={a.id} className="panel flex flex-wrap items-center justify-between gap-2 px-4 py-3 font-mono text-[12.5px]">
                  <span className="text-fg">{a.envelope.tool}</span>
                  <span className="text-subtle">{a.envelope.principal.agentId}</span>
                  <span className="text-red-300">rejected by {a.rejectedBy}</span>
                </li>
              ))}
            </ul>
          </section>
        )}
        </div>
      </div>
    </div>
  );
}
