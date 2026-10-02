"use client";

import { ChevronLeft, ChevronRight, RefreshCw, RotateCcw, Search } from "lucide-react";
import Link from "next/link";
import { useEffect, useMemo, useRef, useState, type FormEvent, type ReactNode } from "react";
import { SatgVerdictBadge } from "@/components/gateway/PipelineRun";
import { LiveChip } from "@/components/provenance/LiveTraceView";
import { Button, cx, Disclosure, Drawer, Hash, Panel, SectionTitle, Tabs } from "@/components/ui/primitives";
import { fetchAuditEvents, type AuditEvent, type AuditOutcome, type AuditPage, type AuditQuery } from "@/lib/satg/audit";
import type { SatgVerdictType } from "@/lib/satg/client";
import { useSatgLog } from "@/lib/satg/log";

const PAGE_SIZE = 25;
const VERDICT_TABS = [
  { id: "ALL", label: "All" },
  { id: "ALLOW", label: "Allow" },
  { id: "BLOCK", label: "Block" },
  { id: "ESCALATE", label: "Escalate" },
] as const;
type VerdictTab = (typeof VERDICT_TABS)[number]["id"];

const FILTERS = [
  { key: "request_id", label: "request_id", placeholder: "req_…" },
  { key: "rule_id", label: "rule", placeholder: "DEST-001" },
  { key: "tool", label: "tool", placeholder: "send_email" },
  { key: "agent_id", label: "agent", placeholder: "support-bot-3" },
] as const;
type FilterKey = (typeof FILTERS)[number]["key"];
type Filters = Record<FilterKey, string>;
const NO_FILTERS: Filters = { request_id: "", rule_id: "", tool: "", agent_id: "" };

const time = (iso: string) => new Date(iso).toLocaleTimeString([], { hour12: false });
const dateTime = (iso: string) => new Date(iso).toLocaleString([], { hour12: false });

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[140px_minmax(0,1fr)] items-baseline gap-3 py-1">
      <dt className="font-mono text-[11px] uppercase tracking-[0.06em] text-subtle">{label}</dt>
      <dd className="min-w-0 font-mono text-[12.5px] text-code [overflow-wrap:anywhere]">{children}</dd>
    </div>
  );
}

const muted = (text: string) => <span className="text-subtle">{text}</span>;

/** States that are not an audit page. Nothing is shown as backend data in any of them. */
function OutcomeNotice({ outcome }: { outcome: Exclude<AuditOutcome, { kind: "ok" }> }) {
  const text: Record<typeof outcome.kind, string> = {
    auth_error: "The backend refused the console's audit credential. Check that SATG_AUDIT_API_TOKEN is identical on the console server and the backend.",
    not_configured: "Live audit is not configured. Set the same SATG_AUDIT_API_TOKEN (at least 32 characters) for the backend and for the console server.",
    invalid_query: "The backend rejected these filters. Identifiers are letters, digits and . _ : - (at most 128 characters).",
    unreachable: "The SATG backend is not reachable, so no audit history can be shown.",
    malformed: "The backend's answer was not a valid audit page, so nothing from it is shown.",
  };
  return (
    <Panel className="border-amber-400/30 p-6">
      <p className="font-mono text-[12px] font-semibold uppercase tracking-[0.08em] text-amber-300">
        No audit data · {outcome.kind.replace("_", " ")}
        {"httpStatus" in outcome ? ` · HTTP ${outcome.httpStatus}` : ""}
        {"code" in outcome ? ` · ${outcome.code}` : ""}
      </p>
      <p className="mt-2 text-[13.5px] leading-relaxed text-fg/85">{text[outcome.kind]}</p>
      <p className="mt-1 font-mono text-[12px] text-subtle">{outcome.message}</p>
    </Panel>
  );
}

function HistoryMeta({ page, fetchedAt }: { page: AuditPage; fetchedAt: number }) {
  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-1 border-b border-line px-4 py-2.5 font-mono text-[11.5px] text-subtle">
      <span className="text-fg/85">In-memory history since backend start · {dateTime(page.process_started_at)}</span>
      <span>
        {page.retained.toLocaleString()} of {page.capacity.toLocaleString()} retained
      </span>
      <span>{page.total_recorded.toLocaleString()} recorded</span>
      {page.oldest_seq !== null && (
        <span>
          seq {page.oldest_seq}–{page.newest_seq}
        </span>
      )}
      {page.evicted > 0 && <span className="text-amber-300">{page.evicted.toLocaleString()} oldest evicted</span>}
      <span className="ml-auto">fetched {time(new Date(fetchedAt).toISOString())}</span>
    </div>
  );
}

function EventDetail({ e, traceSeq }: { e: AuditEvent; traceSeq: number | undefined }) {
  const x = e.execution;
  const ml = e.ml;
  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-2">
        <SatgVerdictBadge verdict={e.verdict} size="lg" />
        <span className="font-mono text-[14px] font-semibold text-fg">{e.rule_id}</span>
        <span className="font-mono text-[12px] text-subtle">
          seq {e.seq} · {e.severity} · stage {e.stage}
        </span>
      </div>
      <p className="text-[13.5px] leading-snug text-fg/85">{e.reason}</p>

      <dl>
        <Field label="request_id">{e.request_id}</Field>
        <Field label="audit record">
          {dateTime(e.timestamp)} {muted("· written by the backend after the decision")}
        </Field>
        <Field label="agent">
          {e.agent_id ?? muted("— not readable")} {muted(`· ${e.auth_method ?? "no identity resolved"}`)}
        </Field>
        <Field label="tool">{e.tool ?? muted("— not readable")}</Field>
      </dl>

      <div className="rounded-xl border border-line bg-surface p-3 text-[13px]">
        {traceSeq !== undefined ? (
          <Link href={`/provenance/live?seq=${traceSeq}`} className="font-semibold text-accent hover:underline">
            Open in Live Request Trace →
          </Link>
        ) : (
          <span className="text-muted">
            No browser trace for this request in this session: it was sent by another client or tab, or before this page was loaded. This audit record is the
            backend&apos;s evidence for it.
          </span>
        )}
      </div>

      <section>
        <SectionTitle>Decision</SectionTitle>
        {e.decision ? (
          <dl>
            <Field label="deterministic">
              {e.decision.deterministic_verdict} · {e.decision.deterministic_rule_id}
            </Field>
            <Field label="final">
              {e.decision.final_verdict} · {e.decision.final_rule_id}
            </Field>
            <Field label="ML thresholds">
              escalate ≥ {e.decision.ml_high_risk_threshold} · block ≥ {e.decision.ml_critical_risk_threshold} · ML_MODE={e.decision.ml_mode}
            </Field>
          </dl>
        ) : (
          <p className="text-[13px] text-muted">No decision trace: the request was refused before the policy pipeline ({e.stage}).</p>
        )}
      </section>

      <div className="space-y-2.5">
        <Disclosure summary="ML summary">
          {!ml ? (
            <p className="text-[13px] text-muted">No ML assessment recorded: the request never reached the ML layer.</p>
          ) : ml.status === "not_consulted" ? (
            <p className="text-[13px] text-muted">Not evaluated — deterministic BLOCK is terminal.</p>
          ) : (
            <dl>
              <Field label="status">
                {ml.status} {muted(`· ML_MODE=${ml.mode}`)}
              </Field>
              <Field label="risk">{ml.risk_score !== null ? ml.risk_score.toFixed(3) : muted("—")}</Field>
              <Field label="level">{ml.risk_level ?? muted("—")}</Field>
              <Field label="model">{ml.model_version ?? muted("—")}</Field>
              <Field label="prediction">{ml.prediction ?? muted("—")}</Field>
              <Field label="latency">{ml.latency_ms !== null ? `${ml.latency_ms} ms` : muted("—")}</Field>
              <Field label="context seen">{ml.context_used.length ? ml.context_used.join(", ") : muted("none")}</Field>
            </dl>
          )}
          <p className="mt-1.5 text-[11.5px] text-subtle">Model features, signals and top factors are withheld by the audit API.</p>
        </Disclosure>

        <Disclosure summary={`Checks · ${e.checks.length} run${e.checks_not_evaluated.length ? ` · ${e.checks_not_evaluated.length} not evaluated` : ""}`}>
          <ul className="space-y-1 font-mono text-[12px]">
            {e.checks.map((c) => (
              <li key={c.check} className="flex gap-2">
                <span className={c.status === "PASSED" ? "text-emerald-300" : "text-red-300"}>{c.status}</span>
                <span className="text-fg">{c.check}</span>
              </li>
            ))}
            {e.checks_not_evaluated.map((c) => (
              <li key={c} className="flex gap-2 text-subtle">
                <span>NOT EVALUATED</span>
                <span>{c}</span>
              </li>
            ))}
          </ul>
        </Disclosure>

        <Disclosure summary="Sandbox">
          {!x ? (
            <p className="text-[13px] text-muted">
              {e.verdict === "ALLOW" ? "No execution result recorded." : `Not executed — ${e.verdict} never reaches the sandbox.`}
            </p>
          ) : (
            <dl>
              <Field label="status">{x.status}</Field>
              {x.error_summary && <Field label="summary">{x.error_summary}</Field>}
              {x.error_code && <Field label="runner code">{x.error_code}</Field>}
              <Field label="exit · duration">
                {x.exit_code ?? "—"} · {x.duration_ms !== null ? `${x.duration_ms} ms` : "—"}
              </Field>
              <Field label="sandbox_id">{x.sandbox_id ?? muted("—")}</Field>
              <Field label="container removed">{x.container_removed === null ? muted("—") : String(x.container_removed)}</Field>
              <Field label="stdout">{x.stdout_sha256 ? <>{x.stdout_bytes} B · sha256 <Hash value={x.stdout_sha256} n={10} /></> : muted("—")}</Field>
              <Field label="stderr">{x.stderr_sha256 ? <>{x.stderr_bytes} B · sha256 <Hash value={x.stderr_sha256} n={10} /></> : muted("—")}</Field>
            </dl>
          )}
          <p className="mt-1.5 text-[11.5px] text-subtle">Tool output is never stored; the backend keeps only its hash and size.</p>
        </Disclosure>

        <Disclosure summary="Hashes and versions">
          <dl>
            <Field label="policy">{e.policy_version}</Field>
            <Field label="tool_version">{e.tool_version ?? muted("—")}</Field>
            <Field label="manifest">{e.tool_manifest_hash ?? muted("—")}</Field>
            <Field label="request_hash">{e.request_hash ?? muted("— not computed (refused before canonicalization)")}</Field>
            <Field label="integrity tag">
              {e.request_integrity ? (
                <>
                  {e.request_integrity.algorithm} · key {e.request_integrity.key_id} {muted("· signature withheld")}
                </>
              ) : (
                muted("none (only an ALLOW is signed)")
              )}
            </Field>
          </dl>
        </Disclosure>

        {e.network.length > 0 && (
          <Disclosure summary={`Network · ${e.network.length}`}>
            <div className="space-y-3">
              {e.network.map((n, i) => (
                <div key={i} className="rounded-xl border border-line bg-surface p-3">
                  <dl>
                    <Field label="parameter">{n.parameter}</Field>
                    <Field label="url">
                      {n.url} {n.url_query_removed && muted("· query/fragment/userinfo removed")}
                    </Field>
                    <Field label="host · domain">
                      {n.requested_host ?? "—"} · {n.registrable_domain ?? "—"}
                    </Field>
                    <Field label="resolved · pinned">
                      {n.resolved_ips.join(", ") || "—"} · {n.pinned_ip ?? "—"}
                    </Field>
                  </dl>
                  <ul className="mt-2 space-y-1 font-mono text-[11.5px]">
                    {n.checks.map((c) => (
                      <li key={c.check} className="flex flex-wrap gap-2">
                        <span className={c.status === "PASSED" ? "text-emerald-300" : c.status === "BLOCKED" ? "text-red-300" : "text-subtle"}>{c.status}</span>
                        <span className="text-fg">{c.check}</span>
                        {c.detail && <span className="text-subtle">{c.detail}</span>}
                      </li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          </Disclosure>
        )}

        {e.anomalies.length > 0 && (
          <Disclosure summary={`Quarantined anomalies · ${e.anomalies.length}`}>
            <ul className="space-y-2">
              {e.anomalies.map((a) => (
                <li key={a.anomaly_id} className="rounded-xl border border-line bg-surface p-3">
                  <dl>
                    <Field label="type">
                      {a.anomaly_type} · {a.risk_severity} · {a.rule_id}
                    </Field>
                    <Field label="location">{a.location}</Field>
                    <Field label="payload">
                      {a.raw_payload_bytes} B · <Hash value={a.raw_payload_sha256} n={14} />
                    </Field>
                    <Field label="mitigation">{a.mitigation_action}</Field>
                  </dl>
                </li>
              ))}
            </ul>
            <p className="mt-1.5 text-[11.5px] text-subtle">The quarantined bytes are withheld; only their fingerprint and size are shown.</p>
          </Disclosure>
        )}
      </div>
    </div>
  );
}

/** Real audit events from the SATG backend's read-only audit API (in-memory history of its current process). */
export default function LiveAuditView() {
  const [verdict, setVerdict] = useState<VerdictTab>("ALL");
  const [draft, setDraft] = useState<Filters>(NO_FILTERS);
  const [filters, setFilters] = useState<Filters>(NO_FILTERS);
  const [cursors, setCursors] = useState<number[]>([]);
  const [tick, setTick] = useState(0);
  const [result, setResult] = useState<{ key: string; outcome: AuditOutcome; fetchedAt: number } | null>(null);
  const [restartedAt, setRestartedAt] = useState<string | null>(null);
  const [openSeq, setOpenSeq] = useState<number | null>(null);
  const startedAt = useRef<string | null>(null);

  const query = useMemo<AuditQuery>(() => {
    const q: AuditQuery = { limit: PAGE_SIZE, before_seq: cursors[cursors.length - 1] };
    if (verdict !== "ALL") q.verdict = verdict as SatgVerdictType;
    for (const f of FILTERS) if (filters[f.key].trim()) q[f.key] = filters[f.key].trim();
    return q;
  }, [verdict, filters, cursors]);
  const key = `${JSON.stringify(query)}#${tick}`;

  useEffect(() => {
    let cancelled = false;
    fetchAuditEvents(query).then((outcome) => {
      if (cancelled) return;
      if (outcome.kind === "ok") {
        const started = outcome.page.process_started_at;
        if (startedAt.current && startedAt.current !== started) setRestartedAt(started);
        startedAt.current = started;
      }
      setResult({ key, outcome, fetchedAt: Date.now() });
    });
    return () => {
      cancelled = true;
    };
  }, [query, key]);

  // request_id -> this tab's trace sequence, only for requests this browser actually sent.
  const entries = useSatgLog((s) => s.entries);
  const traceSeqs = useMemo(() => {
    const m = new Map<string, number>();
    for (const e of entries) if (e.outcome.kind === "verdict") m.set(e.outcome.verdict.request_id, e.seq);
    return m;
  }, [entries]);

  const loading = result?.key !== key;
  const outcome = result?.outcome;
  const page = outcome?.kind === "ok" ? outcome.page : null;
  const filtered = verdict !== "ALL" || FILTERS.some((f) => filters[f.key].trim());
  const open = page?.events.find((e) => e.seq === openSeq) ?? null;

  const apply = (ev: FormEvent) => {
    ev.preventDefault();
    setFilters(draft);
    setCursors([]);
  };
  const clear = () => {
    setDraft(NO_FILTERS);
    setFilters(NO_FILTERS);
    setVerdict("ALL");
    setCursors([]);
  };
  const field = "h-9 w-full rounded-lg border border-line bg-black/20 px-2.5 font-mono text-[12.5px] text-fg outline-none placeholder:text-subtle focus:ring-2 focus:ring-accent/50";

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="max-w-3xl text-[13px] leading-relaxed text-muted">
          Audit records written by the SATG backend for every decision since its process started, read through its operator-authenticated, read-only audit API.
          In memory only: not persistent, signed or shared between workers, and a backend restart starts empty. Sensitive fields are withheld by the backend.
        </p>
        <div className="flex items-center gap-2">
          <LiveChip />
          <Button className="h-9 text-[13px]" onClick={() => setTick((t) => t + 1)} disabled={loading}>
            <RefreshCw className={cx("h-4 w-4", loading && "animate-spin")} /> Refresh
          </Button>
        </div>
      </div>

      {restartedAt && (
        <Panel className="flex flex-wrap items-center gap-3 border-amber-400/30 px-4 py-2.5 text-[13px] text-fg/85">
          <span className="font-semibold text-amber-300">Backend restarted.</span> Its audit history began again at {dateTime(restartedAt)}; earlier events are gone.
          <button type="button" onClick={() => setRestartedAt(null)} className="ml-auto text-[12.5px] font-semibold text-accent hover:underline">
            Dismiss
          </button>
        </Panel>
      )}

      <Panel className="overflow-hidden">
        <form onSubmit={apply} className="flex flex-col gap-3 border-b border-line p-4 xl:flex-row xl:items-end">
          <Tabs size="sm" label="Filter by verdict" value={verdict} onChange={(v) => { setVerdict(v); setCursors([]); }} items={VERDICT_TABS} />
          <div className="grid flex-1 grid-cols-2 gap-2 md:grid-cols-4">
            {FILTERS.map((f) => (
              <label key={f.key} className="block">
                <span className="mb-1 block font-mono text-[10.5px] uppercase tracking-[0.08em] text-subtle">{f.label}</span>
                <input className={field} value={draft[f.key]} placeholder={f.placeholder} spellCheck={false} onChange={(e) => setDraft({ ...draft, [f.key]: e.target.value })} />
              </label>
            ))}
          </div>
          <div className="flex gap-2">
            <Button type="submit" className="h-9 text-[13px]">
              <Search className="h-4 w-4" /> Apply
            </Button>
            <Button variant="ghost" className="h-9 text-[13px]" onClick={clear}>
              <RotateCcw className="h-4 w-4" /> Clear
            </Button>
          </div>
        </form>

        {page && result && <HistoryMeta page={page} fetchedAt={result.fetchedAt} />}

        {!outcome ? (
          <p className="p-8 text-center text-[13.5px] text-subtle">Loading the backend&apos;s audit history…</p>
        ) : outcome.kind !== "ok" ? (
          <div className="p-4">
            <OutcomeNotice outcome={outcome} />
          </div>
        ) : !page?.events.length ? (
          <p className="p-8 text-center text-[13.5px] text-subtle">
            {filtered
              ? "No audit events match these filters in the history this backend process still holds."
              : `No audit events since this backend process started (${dateTime(outcome.page.process_started_at)}). Run a request from the Live Gateway, then Refresh.`}
          </p>
        ) : (
          <div className={cx("scrollbar-thin overflow-x-auto transition-opacity", loading && "opacity-60")}>
            <table className="w-full min-w-[1080px] text-left">
              <thead>
                <tr className="border-b border-line font-mono text-[11px] uppercase tracking-[0.08em] text-subtle">
                  <th className="px-4 py-3 font-medium">seq</th>
                  <th className="px-4 py-3 font-medium" title="When the backend wrote the audit record">Audit time</th>
                  <th className="px-4 py-3 font-medium">Verdict</th>
                  <th className="px-4 py-3 font-medium">Rule</th>
                  <th className="px-4 py-3 font-medium">Tool</th>
                  <th className="px-4 py-3 font-medium">Agent</th>
                  <th className="px-4 py-3 font-medium">Severity · stage</th>
                  <th className="px-4 py-3 font-medium">request_id</th>
                  <th className="px-4 py-3 font-medium">Trace</th>
                </tr>
              </thead>
              <tbody>
                {page.events.map((e) => {
                  const traceSeq = traceSeqs.get(e.request_id);
                  return (
                    <tr key={e.seq} onClick={() => setOpenSeq(e.seq)} className="cursor-pointer border-b border-line/60 transition-colors last:border-0 hover:bg-surface">
                      <td className="px-4 py-3 font-mono text-[12px] text-subtle">{e.seq}</td>
                      <td className="whitespace-nowrap px-4 py-3 font-mono text-[12px] text-code" title={e.timestamp}>
                        {time(e.timestamp)}
                      </td>
                      <td className="px-4 py-3">
                        <SatgVerdictBadge verdict={e.verdict} />
                      </td>
                      <td className="px-4 py-3 font-mono text-[12.5px] font-semibold text-fg">{e.rule_id}</td>
                      <td className="px-4 py-3 font-mono text-[12.5px] text-fg">{e.tool ?? muted("—")}</td>
                      <td className="px-4 py-3 font-mono text-[12px] text-fg/85">{e.agent_id ?? muted("—")}</td>
                      <td className="px-4 py-3 font-mono text-[12px] text-muted">
                        {e.severity} · {e.stage}
                      </td>
                      <td className="px-4 py-3">
                        <Hash value={e.request_id} n={10} />
                      </td>
                      <td className="px-4 py-3 font-mono text-[11.5px]">{traceSeq !== undefined ? <span className="text-accent">#{traceSeq}</span> : muted("—")}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {page && (page.events.length > 0 || cursors.length > 0) && (
          <div className="flex items-center justify-between gap-3 border-t border-line px-4 py-2.5">
            <span className="font-mono text-[11.5px] text-subtle">
              page {cursors.length + 1} · newest first · {page.events.length} shown
            </span>
            <div className="flex gap-2">
              <Button variant="ghost" className="h-8 text-[12.5px]" disabled={!cursors.length || loading} onClick={() => setCursors(cursors.slice(0, -1))}>
                <ChevronLeft className="h-4 w-4" /> Newer
              </Button>
              <Button
                variant="ghost"
                className="h-8 text-[12.5px]"
                disabled={page.next_before_seq === null || loading}
                onClick={() => page.next_before_seq !== null && setCursors([...cursors, page.next_before_seq])}
              >
                Older <ChevronRight className="h-4 w-4" />
              </Button>
            </div>
          </div>
        )}
      </Panel>

      <Drawer
        open={!!open}
        onClose={() => setOpenSeq(null)}
        width="max-w-2xl"
        title={
          open && (
            <span className="flex flex-wrap items-center gap-2">
              Audit event #{open.seq}
              <span className="font-mono text-[12.5px] font-normal text-subtle">{open.tool ?? "unreadable tool"}</span>
            </span>
          )
        }
      >
        {open && <EventDetail e={open} traceSeq={traceSeqs.get(open.request_id)} />}
      </Drawer>
    </div>
  );
}
