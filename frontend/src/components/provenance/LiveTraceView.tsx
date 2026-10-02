"use client";

import { CircleCheck, CircleDashed, CircleHelp, CircleSlash, CircleX, PauseCircle, type LucideIcon } from "lucide-react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { Suspense, useMemo, useState, type ReactNode } from "react";
import { SatgVerdictBadge } from "@/components/gateway/PipelineRun";
import { cx, Disclosure, Hash, JsonBlock, PageHeader, Panel, SectionTitle } from "@/components/ui/primitives";
import { useSatgLog } from "@/lib/satg/log";
import { toLiveTraces, type LiveTrace, type TraceStage, type TraceStageStatus } from "@/lib/satg/liveTrace";
import ProvenanceModeTabs from "./ProvenanceModeTabs";

/** Stage status styling. Escalated reuses the violet the Live Gateway uses for ESCALATE. */
const STATUS: Record<TraceStageStatus, { text: string; cls: string; icon: LucideIcon }> = {
  passed: { text: "PASSED", cls: "bg-emerald-400/10 text-emerald-300 ring-emerald-400/30", icon: CircleCheck },
  failed: { text: "FAILED", cls: "bg-red-500/15 text-red-300 ring-red-500/40", icon: CircleX },
  escalated: { text: "ESCALATED", cls: "bg-violet-400/10 text-violet-300 ring-violet-400/30", icon: PauseCircle },
  not_evaluated: { text: "NOT EVALUATED", cls: "bg-surface text-muted ring-line", icon: CircleSlash },
  not_executed: { text: "NOT EXECUTED", cls: "bg-surface text-muted ring-line", icon: CircleSlash },
  unavailable: { text: "UNAVAILABLE", cls: "bg-amber-400/10 text-amber-300 ring-amber-400/30", icon: CircleDashed },
  unknown: { text: "UNKNOWN", cls: "bg-surface text-subtle ring-line", icon: CircleHelp },
};

const time = (iso: string) => new Date(iso).toLocaleTimeString([], { hour12: false });

export function LiveChip() {
  return (
    <span className="inline-flex items-center gap-2 rounded-md bg-emerald-400/10 px-2.5 py-1 font-mono text-[11.5px] font-semibold tracking-[0.06em] text-emerald-300 ring-1 ring-emerald-400/30">
      <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
      LIVE · SATG BACKEND
    </span>
  );
}

/** The backend's verdict, or NO VERDICT when the round trip produced none. Never derived from the stages. */
function TraceVerdict({ t, size = "sm" }: { t: LiveTrace; size?: "sm" | "lg" }) {
  if (t.verdict) return <SatgVerdictBadge verdict={t.verdict} size={size} />;
  return (
    <span
      className={cx(
        "inline-flex items-center whitespace-nowrap rounded-md bg-amber-400/10 font-mono font-semibold text-amber-300 ring-1 ring-amber-400/30",
        size === "lg" ? "px-3 py-1.5 text-sm" : "px-2 py-0.5 text-[11px]",
      )}
    >
      NO VERDICT
    </span>
  );
}

function Meta({ t }: { t: LiveTrace }) {
  const items = [`#${t.seq}`, t.source === "agent" ? "agent console" : "request studio", time(t.at), t.httpStatus !== undefined ? `HTTP ${t.httpStatus}` : "no HTTP response", `${t.roundTripMs} ms`];
  return <span className="font-mono text-[11.5px] text-subtle">{items.join(" · ")}</span>;
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[132px_minmax(0,1fr)] items-baseline gap-3 py-1">
      <dt className="font-mono text-[11px] uppercase tracking-[0.06em] text-subtle">{label}</dt>
      <dd className="min-w-0 break-all font-mono text-[12.5px] text-code">{children}</dd>
    </div>
  );
}

function StageRow({ s, last, verdict }: { s: TraceStage; last: boolean; verdict?: LiveTrace["verdict"] }) {
  const st = STATUS[s.status];
  // The final-verdict stage names the backend verdict itself (ALLOW / BLOCK / ESCALATE); its colour still follows the stage status.
  const text = s.key === "FINAL_VERDICT" && verdict ? verdict : st.text;
  const quiet = s.status === "not_evaluated" || s.status === "not_executed" || s.status === "unknown";
  return (
    <li className="relative grid grid-cols-[28px_minmax(0,1fr)] gap-3">
      {!last && <span aria-hidden="true" className="absolute left-[13px] top-7 bottom-0 w-px bg-line" />}
      <span className={cx("relative z-10 mt-0.5 grid h-7 w-7 place-items-center rounded-full ring-1", st.cls)}>
        <st.icon className="h-4 w-4" />
      </span>
      <div className={cx("min-w-0 pb-4", quiet && "opacity-90")}>
        <div className="flex flex-wrap items-center gap-2">
          <span className={cx("text-[14px] font-semibold", quiet ? "text-muted" : "text-fg")}>{s.label}</span>
          <span className={cx("rounded-md px-2 py-0.5 font-mono text-[11px] font-semibold ring-1", st.cls)}>
            {text}
            {s.ruleId && ` · ${s.ruleId}`}
          </span>
          <span
            className="ml-auto font-mono text-[10.5px] text-subtle"
            title={s.source === "backend" ? "Restates a field of the backend response" : "The backend response left this field empty"}
          >
            {s.source === "backend" ? "backend" : "empty in response"}
          </span>
        </div>
        {s.detail && <p className={cx("mt-1 break-words text-[12.5px] leading-snug", quiet ? "text-fg/80" : "text-muted")}>{s.detail}</p>}
      </div>
    </li>
  );
}

function TraceDetail({ t }: { t: LiveTrace }) {
  const r = t.request;
  const ids: [string, string | undefined][] = [
    ["request_id", t.requestId],
    ["request_hash", t.requestHash],
    ["policy", t.policyVersion],
    ["tool_version", t.toolVersion],
    ["manifest", t.toolManifestHash],
  ];
  const presentIds = ids.filter((x): x is [string, string] => x[1] !== undefined);

  return (
    <div className="min-w-0 space-y-5">
      <Panel className="p-5 sm:p-6">
        <div className="flex flex-wrap items-center gap-3">
          <TraceVerdict t={t} size="lg" />
          {t.ruleId && <span className="font-mono text-[14px] font-semibold text-fg">{t.ruleId}</span>}
          <span className="ml-auto">
            <Meta t={t} />
          </span>
        </div>
        {t.requestId && (
          <p className="mt-2 font-mono text-[11.5px] text-subtle">
            request_id <Hash value={t.requestId} n={14} />
          </p>
        )}
        {t.verdict ? (
          t.reason && <p className="mt-3 text-[14px] leading-snug text-fg/85">{t.reason}</p>
        ) : (
          <p className="mt-3 text-[14px] leading-snug text-fg/85">
            This request did not produce a valid SATG verdict{t.error ? `: ${t.error.message}` : "."}
            {t.error?.code && <span className="font-mono text-[12.5px] text-subtle"> ({t.error.code})</span>}
            <span className="mt-1 block text-[13px] text-muted">No security check, decision or sandbox run is shown, because the backend reported none.</span>
          </p>
        )}
      </Panel>

      <Panel className="p-5 sm:p-6">
        <SectionTitle right={<span className="font-mono text-[11.5px] text-subtle">as sent by this browser · self-asserted</span>}>Parsed request</SectionTitle>
        {r.parsed ? (
          <dl>
            <Field label="agent_id">{r.agentId ?? <span className="text-subtle">— not a string in the body</span>}</Field>
            <Field label="tool">{r.tool ?? <span className="text-subtle">— not a string in the body</span>}</Field>
          </dl>
        ) : (
          <p className="text-[13px] text-muted">The body is not a JSON object, so no request fields can be read from it. See the exact body below.</p>
        )}
        <div className="mt-3 space-y-2.5">
          {r.parameters !== undefined && (
            <Disclosure summary="Parameters">
              <JsonBlock value={r.parameters} className="max-h-64" />
            </Disclosure>
          )}
          {r.context !== undefined && (
            <Disclosure summary="Context (untrusted; never used for a security decision)">
              <JsonBlock value={r.context} className="max-h-64" />
            </Disclosure>
          )}
          <Disclosure summary="View exact request body">
            <p className="mb-1.5 text-[12px] text-subtle">Exact request body, byte-for-byte as submitted.</p>
            <JsonBlock value={r.body} className="max-h-72 whitespace-pre-wrap break-all" />
          </Disclosure>
        </div>
      </Panel>

      {t.stages.length > 0 && (
        <Panel className="p-5 sm:p-6">
          <SectionTitle right={<span className="font-mono text-[11.5px] text-subtle">from the backend response · nothing inferred</span>}>SATG decision trace</SectionTitle>
          <ol>
            {t.stages.map((s, i) => (
              <StageRow key={s.key} s={s} last={i === t.stages.length - 1} verdict={t.verdict} />
            ))}
          </ol>
        </Panel>
      )}

      {(presentIds.length > 0 || t.network.length > 0 || t.anomalies.length > 0) && (
        <Panel className="space-y-2.5 p-5 sm:p-6">
          <SectionTitle>Backend evidence</SectionTitle>
          {presentIds.length > 0 && (
            <Disclosure summary="Identifiers and versions">
              <dl>
                {presentIds.map(([k, v]) => (
                  <Field key={k} label={k}>
                    {v}
                  </Field>
                ))}
              </dl>
            </Disclosure>
          )}
          {t.network.length > 0 && (
            <Disclosure summary={`Network inspection · ${t.network.length}`}>
              <div className="space-y-3">
                {t.network.map((n, i) => (
                  <div key={i} className="rounded-xl border border-line bg-surface p-3">
                    <dl>
                      <Field label="parameter">{n.parameter}</Field>
                      <Field label="requested_url">{n.requested_url}</Field>
                      {n.requested_host && <Field label="host">{n.requested_host}</Field>}
                      <Field label="resolved_ips">{n.resolved_ips.length ? n.resolved_ips.join(", ") : "—"}</Field>
                      <Field label="pinned_ip">{n.pinned_ip ?? "—"}</Field>
                    </dl>
                    <ul className="mt-2 space-y-1">
                      {n.checks.map((c) => (
                        <li key={c.check} className="flex flex-wrap items-baseline gap-2 font-mono text-[11.5px]">
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
          {t.anomalies.length > 0 && (
            <Disclosure summary={`Quarantined anomalies · ${t.anomalies.length}`}>
              <JsonBlock value={t.anomalies} className="max-h-72" />
            </Disclosure>
          )}
        </Panel>
      )}
    </div>
  );
}

/** Real Live Gateway round trips from this tab, traced from the backend's own responses. */
export default function LiveTraceView() {
  // useSearchParams() needs a Suspense boundary on a statically built route.
  return (
    <Suspense>
      <LiveTraceBody />
    </Suspense>
  );
}

function LiveTraceBody() {
  const params = useSearchParams();
  const entries = useSatgLog((s) => s.entries);
  const traces = useMemo(() => toLiveTraces(entries), [entries]);
  // ?seq=N (e.g. from a live escalation on the Approvals page) selects that trace; otherwise the newest.
  const [selected, setSelected] = useState<number | null>(() => Number(params.get("seq")) || null);
  const t = traces.find((x) => x.seq === selected) ?? traces[0];

  return (
    <div>
      <ProvenanceModeTabs current="live" className="mb-5" />
      <PageHeader
        eyebrow="Live Gateway · request trace"
        title={
          <>
            Live Request <span className="text-accent">Trace</span>
          </>
        }
        description="Each request this browser tab sent through the Live Gateway, traced from the SATG backend's own response: the checks it ran, its deterministic decision, the ML assessment and the sandbox result. Nothing is inferred, and this is not data provenance. Traces are kept in memory only and disappear on reload."
        actions={<LiveChip />}
      />

      {!t ? (
        <Panel className="p-8 text-center">
          <p className="text-[14px] text-muted">No live traces yet. Run a request from Live Gateway to populate this view.</p>
          <Link href="/" className="mt-3 inline-block text-[13.5px] font-semibold text-accent hover:underline">
            Open Live Gateway →
          </Link>
        </Panel>
      ) : (
        <div className="grid gap-5 xl:grid-cols-[320px_minmax(0,1fr)]">
          <Panel className="scrollbar-thin max-h-[780px] self-start overflow-y-auto p-3">
            <p className="px-2 pb-2 pt-1 text-[12px] font-semibold uppercase tracking-[0.1em] text-subtle">Requests · {traces.length}</p>
            <ul className="space-y-1">
              {traces.map((x) => (
                <li key={x.seq}>
                  <button
                    type="button"
                    onClick={() => setSelected(x.seq)}
                    aria-current={x.seq === t.seq}
                    className={cx("w-full rounded-xl px-3 py-2.5 text-left transition-colors", x.seq === t.seq ? "bg-surface-hover ring-1 ring-line" : "hover:bg-surface")}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="truncate font-mono text-[13px] font-semibold text-fg">{x.request.tool ?? x.title}</span>
                      <TraceVerdict t={x} />
                    </div>
                    <div className="mt-1 flex items-center justify-between gap-2 font-mono text-[11px] text-subtle">
                      <span className="truncate">
                        #{x.seq} · {x.source} · {time(x.at)}
                      </span>
                      <span className="shrink-0">
                        {x.httpStatus !== undefined ? `${x.httpStatus} · ` : ""}
                        {x.roundTripMs} ms
                      </span>
                    </div>
                  </button>
                </li>
              ))}
            </ul>
            <p className="px-2 pt-3 text-[11.5px] leading-snug text-subtle">This tab only. The backend&apos;s own audit log is not exposed by its API.</p>
          </Panel>

          <TraceDetail key={t.seq} t={t} />
        </div>
      )}
    </div>
  );
}
