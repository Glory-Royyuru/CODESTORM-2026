"use client";

import { AnimatePresence, motion } from "framer-motion";
import {
  BrainCircuit,
  CircleOff,
  Container,
  KeyRound,
  ListChecks,
  LogIn,
  Power,
  Scale,
  Send,
  ServerCrash,
  ShieldCheck,
  Unplug,
  type LucideIcon,
} from "lucide-react";
import { useEffect, useState } from "react";
import { cx, JsonBlock, Panel, SectionTitle } from "@/components/ui/primitives";
import { VERDICT_STYLE } from "@/components/ui/tokens";
import { categorize, type SatgOutcome, type SatgVerdict, type SatgVerdictType } from "@/lib/satg/client";
import type { StudioRun } from "./AttackStudio";

type TileStatus = "pass" | "warn" | "fail" | "skip";

interface Tile {
  key: string;
  label: string;
  icon: LucideIcon;
  status: TileStatus;
  /** Overrides the generic status word on the tile. */
  text?: string;
  detail: string;
}

/** Display names for the backend's check identifiers (backend/app/gateway/pipeline.py). Unknown names are shown raw. */
const CHECKS: Record<string, { label: string; icon: LucideIcon }> = {
  REQUEST_STRUCTURE: { label: "Ingress & canonicalize", icon: LogIn },
  TOOL_REGISTRY: { label: "Registry & manifest", icon: ShieldCheck },
  TOOL_ENABLED: { label: "Tool enabled", icon: Power },
  AGENT_PERMISSION: { label: "Agent permission", icon: KeyRound },
  PARAMETER_VALIDATION: { label: "Parameters", icon: ListChecks },
  DESTINATION_VALIDATION: { label: "Destination", icon: Send },
  GATEWAY_INTERNAL: { label: "Gateway internal", icon: ServerCrash },
};

/** SATG modules that the current backend does not implement. Shown so nothing implies they ran. */
const NOT_IN_BACKEND = ["Response DLP", "Signed receipt"];

const STATUS_CLS: Record<TileStatus, string> = {
  pass: "border-emerald-400/50 bg-emerald-400/10 text-emerald-300",
  warn: "border-amber-400/50 bg-amber-400/10 text-amber-300",
  fail: "border-red-500/60 bg-red-500/15 text-red-300",
  skip: "border-line bg-surface text-subtle",
};

const STATUS_TEXT: Record<TileStatus, string> = { pass: "passed", warn: "warning", fail: "failed", skip: "not evaluated" };

const STEP_MS = 220;

export function SatgVerdictBadge({ verdict, size = "sm" }: { verdict: SatgVerdictType; size?: "sm" | "lg" }) {
  // ESCALATE (ML-001: held for review, never executed) reuses the violet "hold" colour.
  const s = VERDICT_STYLE[verdict === "ESCALATE" ? "HUMAN_APPROVAL" : verdict];
  return (
    <span
      className={cx(
        "inline-flex items-center gap-1.5 whitespace-nowrap rounded-md font-mono font-semibold ring-1",
        s.fg,
        s.bg,
        s.ring,
        size === "lg" ? "px-3 py-1.5 text-sm" : "px-2 py-0.5 text-[11px]",
      )}
    >
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: s.hex }} />
      {verdict}
    </span>
  );
}

/** The ML tile shows what the backend did with the assessment; it never derives a verdict itself. */
function mlTile(v: SatgVerdict): Tile {
  const ml = v.ml;
  const base = { key: "__ml", label: "ML risk", icon: BrainCircuit };
  if (!ml || ml.status === "not_consulted") {
    return { ...base, status: "skip", detail: "Not consulted — the deterministic policy already refused the call." };
  }
  if (ml.status === "disabled") return { ...base, status: "skip", text: "disabled", detail: "ML_MODE=off — the ML layer is not consulted." };
  if (ml.status !== "ok") {
    // ML-003: ML_MODE=required and no usable assessment (unavailable, error or timeout): blocked, fail closed.
    const blocked = v.rule_id === "ML-003";
    return {
      ...base,
      status: blocked ? "fail" : "warn",
      text: blocked ? "unavailable · blocked" : "unavailable",
      detail: `ML ${ml.status}${ml.detail ? `: ${ml.detail}` : ""} · ML_MODE=${ml.mode}${blocked ? " — blocked (ML-003, fail closed)" : " — deterministic decision kept"}`,
    };
  }
  const detail = `risk ${ml.risk_score?.toFixed(3)} · level ${ml.risk_level} · ${ml.model_version}`;
  if (v.rule_id === "ML-002") return { ...base, status: "fail", text: "blocked", detail };
  if (v.rule_id === "ML-001") return { ...base, status: "warn", text: "escalate", detail };
  return { ...base, status: "pass", detail };
}

function tilesFor(v: SatgVerdict): Tile[] {
  const tiles: Tile[] = v.checks.map((c) => {
    const meta = CHECKS[c.check] ?? { label: c.check, icon: ShieldCheck };
    const failed = c.status === "FAILED";
    return {
      key: c.check,
      label: meta.label,
      icon: meta.icon,
      status: failed ? "fail" : "pass",
      // The backend stops at the first failure, and that failure is the one the verdict reports.
      detail: failed ? `${v.rule_id} · ${v.reason} (stage: ${v.stage})` : `${c.check} passed`,
    };
  });
  for (const c of v.checks_not_evaluated) {
    const meta = CHECKS[c] ?? { label: c, icon: ShieldCheck };
    tiles.push({ key: c, label: meta.label, icon: meta.icon, status: "skip", detail: `${c} was not evaluated — the backend stops at the first failed check.` });
  }
  tiles.push(mlTile(v));
  tiles.push({
    key: "__policy",
    label: "Policy decision",
    icon: Scale,
    status: v.verdict === "ALLOW" ? "pass" : v.verdict === "ESCALATE" ? "warn" : "fail",
    detail: `${v.verdict} · ${v.rule_id} · ${v.reason} · policy ${v.policy_version}`,
  });
  const e = v.execution;
  tiles.push({
    key: "__sandbox",
    label: "Docker sandbox",
    icon: Container,
    status: !e || e.status === "not_executed" ? "skip" : e.status === "success" ? "pass" : e.status === "tool_error" || e.status === "rejected" ? "warn" : "fail",
    text: e && e.status !== "success" && e.status !== "not_executed" ? e.status.replace("_", " ") : undefined,
    detail: e
      ? `${e.status}${e.exit_code !== null ? ` · exit ${e.exit_code}` : ""}${e.duration_ms !== null ? ` · ${e.duration_ms} ms` : ""}${e.error ? ` · ${e.error}` : ""}`
      : `Not started — ${v.verdict} never reaches the sandbox.`,
  });
  return tiles;
}

function Field({ label, value, missing }: { label: string; value: string | null; missing?: string }) {
  return (
    <div className="grid grid-cols-[120px_minmax(0,1fr)] items-baseline gap-3 py-1">
      <dt className="font-mono text-[11.5px] uppercase tracking-[0.06em] text-subtle">{label}</dt>
      <dd className="min-w-0 break-all font-mono text-[12px] text-code">{value ?? <span className="text-subtle">{missing ?? "— not available"}</span>}</dd>
    </div>
  );
}

function VerdictDetails({ outcome }: { outcome: Extract<SatgOutcome, { kind: "verdict" }> }) {
  const v = outcome.verdict;
  const internal = v.rule_id === "GATEWAY-001";
  const summary =
    v.verdict === "ALLOW"
      ? v.execution?.status === "success"
        ? "Allowed by the SATG backend and executed in a disposable Docker sandbox."
        : `Allowed by the SATG backend. Sandbox: ${v.execution?.status ?? "not reported"}${v.execution?.error ? ` — ${v.execution.error}` : ""}.`
      : v.verdict === "ESCALATE"
        ? "Escalated by the ML risk layer: held for review and not executed."
        : internal
          ? "Internal gateway error — the backend failed closed and blocked the request."
          : `Blocked by security policy at the ${v.stage} stage. Nothing was executed.`;
  const beforeCanon = v.request_hash === null ? "not computed — rejected before canonicalization" : undefined;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2.5">
        <SatgVerdictBadge verdict={v.verdict} size="lg" />
        <span className="rounded-md border border-line bg-surface px-2 py-1 font-mono text-[11.5px] text-muted">severity {v.severity}</span>
        <span className="rounded-md border border-line bg-surface px-2 py-1 font-mono text-[11.5px] text-muted">HTTP {outcome.httpStatus}</span>
      </div>

      <div className="rounded-lg border border-line bg-surface p-3">
        <p className="font-mono text-[12.5px] font-semibold text-fg">
          <span className="text-subtle">{v.stage} · </span>
          {v.rule_id}
        </p>
        <p className="mt-1 text-[13px] leading-snug text-muted">{v.reason}</p>
        {outcome.ingressErrors.length > 0 && (
          <ul className="mt-2 space-y-1 border-t border-line pt-2">
            {outcome.ingressErrors.map((e, i) => (
              <li key={i} className="font-mono text-[11.5px] text-muted">
                <span className="text-code-ident">{e.loc.join(".") || "body"}</span> — {e.msg}
              </li>
            ))}
          </ul>
        )}
      </div>

      <div className="rounded-lg border border-accent/25 bg-accent/5 p-3 text-[12.5px] leading-snug text-fg/85">{summary}</div>

      <dl className="divide-y divide-line/60">
        <Field label="request_id" value={v.request_id} />
        <Field label="agent_id" value={v.agent_id} missing="— not readable from the request" />
        <Field label="tool" value={v.tool} missing="— not readable from the request" />
        <Field label="tool_version" value={v.tool_version} missing="— tool not resolved by the registry" />
        <Field label="manifest" value={v.tool_manifest_hash} missing="— tool not resolved by the registry" />
        <Field label="request_hash" value={v.request_hash} missing={beforeCanon} />
        <Field label="policy" value={v.policy_version} />
        <Field label="round trip" value={`${outcome.roundTripMs} ms (measured in browser)`} />
      </dl>

      <details className="group">
        <summary className="cursor-pointer text-[12.5px] font-semibold text-accent hover:underline">Raw backend response</summary>
        <JsonBlock value={outcome.raw} className="mt-2 max-h-[280px]" />
      </details>
    </div>
  );
}

function ErrorDetails({ outcome }: { outcome: Exclude<SatgOutcome, { kind: "verdict" }> }) {
  const network = outcome.kind === "network_error";
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2.5">
        <span className="inline-flex items-center gap-1.5 rounded-md bg-amber-400/10 px-3 py-1.5 font-mono text-sm font-semibold text-amber-300 ring-1 ring-amber-400/30">
          {network ? <Unplug className="h-4 w-4" /> : <ServerCrash className="h-4 w-4" />}
          {network ? "NETWORK ERROR" : "BACKEND ERROR"}
        </span>
        <span className="rounded-md border border-line bg-surface px-2 py-1 font-mono text-[11.5px] text-muted">
          {network ? outcome.code : `HTTP ${outcome.httpStatus}`}
        </span>
      </div>
      <p className="rounded-lg border border-line bg-surface p-3 text-[13px] leading-snug text-muted">{outcome.message}</p>
      <div className="rounded-lg border border-amber-400/30 bg-amber-400/5 p-3 text-[12.5px] leading-snug text-fg/85">
        No verdict was produced, so nothing is allowed. The console never substitutes its own decision.
      </div>
      {network ? (
        <p className="text-[12.5px] leading-relaxed text-subtle">
          Start the backend in a second terminal: <code className="font-mono text-code">cd backend && uvicorn app.main:app --reload</code>
          {" "}(expected at <code className="font-mono text-code">SATG_BACKEND_URL</code>, default http://127.0.0.1:8000).
        </p>
      ) : (
        <details>
          <summary className="cursor-pointer text-[12.5px] font-semibold text-accent hover:underline">Raw backend response</summary>
          <JsonBlock value={outcome.raw ?? "(empty)"} className="mt-2 max-h-[240px]" />
        </details>
      )}
    </div>
  );
}

/** Stage-by-stage view of the real backend verdict for the last request. */
export default function PipelineRun({ run, onDone }: { run: StudioRun | null; onDone: () => void }) {
  const [active, setActive] = useState(-1);
  const [selected, setSelected] = useState<number | null>(null);
  const outcome = run?.outcome;
  const tiles = outcome?.kind === "verdict" ? tilesFor(outcome.verdict) : [];

  useEffect(() => {
    if (!run) return;
    if (tiles.length === 0) {
      onDone();
      return;
    }
    let i = -1;
    const id = setInterval(() => {
      i++;
      setActive(i);
      if (i >= tiles.length - 1) {
        clearInterval(id);
        onDone();
      }
    }, STEP_MS);
    return () => clearInterval(id);
    // Remounted per run via `key`, so this replays exactly once.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (!run || !outcome) {
    return (
      <Panel className="flex min-h-[180px] flex-col items-center justify-center gap-3 p-8 text-center">
        <div className="flex items-center gap-2 font-mono text-[12px] uppercase tracking-[0.14em] text-subtle">
          {[...Object.values(CHECKS).slice(0, 6), { icon: Scale }].map(({ icon: Icon }, i) => (
            <span key={i} className="flex items-center gap-2">
              <Icon className="h-4 w-4" />
              {i < 6 && <span className="hidden h-px w-5 bg-line sm:block" />}
            </span>
          ))}
        </div>
        <p className="text-[14px] text-muted">
          Pick a request and press <span className="text-accent">Send Through Gateway</span> to see the real backend&apos;s checks and verdict.
        </p>
      </Panel>
    );
  }

  const category = categorize(outcome);
  const done = tiles.length === 0 || active >= tiles.length - 1;
  const shown = selected ?? Math.max(0, Math.min(active, tiles.length - 1));
  const glow =
    category === "ALLOWED" ? VERDICT_STYLE.ALLOW.hex : category === "BLOCKED" ? VERDICT_STYLE.BLOCK.hex : category === "ESCALATED" ? VERDICT_STYLE.HUMAN_APPROVAL.hex : "#fbbf24";

  return (
    <div className="grid items-start gap-5 xl:grid-cols-[minmax(0,1fr)_460px]">
      <Panel className="p-5 sm:p-6">
        <SectionTitle right={<span className="font-mono text-[12px] text-subtle">round trip {outcome.roundTripMs}ms</span>}>Backend checks · {run.preset.title}</SectionTitle>

        {tiles.length > 0 ? (
          <>
            <ol className="grid grid-cols-[repeat(auto-fit,minmax(112px,1fr))] gap-3">
              {tiles.map((t, i) => {
                const reached = i <= active;
                return (
                  <li key={t.key}>
                    <button
                      type="button"
                      onClick={() => setSelected(i)}
                      className={cx(
                        "relative flex w-full flex-col items-center gap-2 rounded-xl border p-3 text-center transition-all duration-300",
                        reached ? STATUS_CLS[t.status] : "border-line bg-surface/50 text-subtle/60",
                        shown === i && "ring-2 ring-accent/60",
                      )}
                    >
                      {i === active && !done && <motion.span layoutId="stage-glow" className="absolute inset-0 rounded-xl bg-accent/10" />}
                      <t.icon className="h-5 w-5" />
                      <span className="text-[11.5px] font-semibold leading-tight">{t.label}</span>
                      <span className="font-mono text-[10.5px] opacity-80">{reached ? (t.text ?? STATUS_TEXT[t.status]) : "…"}</span>
                    </button>
                  </li>
                );
              })}
            </ol>

            <AnimatePresence mode="wait">
              <motion.div
                key={shown}
                initial={{ opacity: 0, y: 6 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.18 }}
                className="mt-4 rounded-xl border border-line bg-black/25 p-4 font-mono text-[12.5px] leading-relaxed"
              >
                <span className="text-accent">{tiles[shown]?.label}</span>
                <span className="text-subtle"> · {tiles[shown] && (tiles[shown].text ?? STATUS_TEXT[tiles[shown].status])}</span>
                <p className="mt-1 break-words text-code">{tiles[shown]?.detail}</p>
              </motion.div>
            </AnimatePresence>
          </>
        ) : (
          <div className="flex min-h-[120px] items-center justify-center rounded-xl border border-dashed border-amber-400/40 bg-amber-400/5 p-6 text-center text-[13.5px] text-amber-200/90">
            No backend verdict — no checks to show.
          </div>
        )}

        <div className="mt-5 border-t border-line pt-4">
          <p className="mb-2 font-mono text-[11px] uppercase tracking-[0.12em] text-subtle">Not part of the current backend</p>
          <ul className="flex flex-wrap gap-2">
            {NOT_IN_BACKEND.map((m) => (
              <li key={m} className="flex items-center gap-1.5 rounded-lg border border-dashed border-line px-2.5 py-1 font-mono text-[11.5px] text-subtle">
                <CircleOff className="h-3.5 w-3.5" />
                {m}
              </li>
            ))}
          </ul>
        </div>
      </Panel>

      {/* verdict panel */}
      <Panel className="relative overflow-hidden p-5 sm:p-6">
        <motion.div
          aria-hidden="true"
          className="pointer-events-none absolute -right-20 -top-20 h-56 w-56 rounded-full blur-3xl"
          style={{ background: glow }}
          initial={{ opacity: 0 }}
          animate={{ opacity: done ? 0.18 : 0 }}
        />
        <SectionTitle>{outcome.kind === "verdict" ? "Backend verdict" : "No verdict"}</SectionTitle>
        <AnimatePresence mode="wait">
          {done ? (
            <motion.div key="v" initial={{ opacity: 0, scale: 0.96 }} animate={{ opacity: 1, scale: 1 }}>
              {outcome.kind === "verdict" ? <VerdictDetails outcome={outcome} /> : <ErrorDetails outcome={outcome} />}
            </motion.div>
          ) : (
            <motion.p key="p" className="font-mono text-[13px] text-subtle" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
              replaying backend checks {Math.max(1, active + 1)}/{tiles.length}…
            </motion.p>
          )}
        </AnimatePresence>
      </Panel>
    </div>
  );
}
