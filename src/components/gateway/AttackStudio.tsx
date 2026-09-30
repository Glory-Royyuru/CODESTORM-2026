"use client";

import { AnimatePresence, motion } from "framer-motion";
import { Check, ChevronDown, Loader2, Play, RotateCcw } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { cx, VerdictBadge } from "@/components/ui/primitives";
import { toWire } from "@/lib/gateway/ingress";
import { runScript, scenarioScript } from "@/lib/gateway/runner";
import { SCENARIOS, type Scenario } from "@/lib/gateway/scenarios";
import type { PipelineResult, Protocol, SessionState, Verdict } from "@/lib/gateway/types";
import { getGateway } from "@/lib/store";

export interface StudioRun {
  scenario: Scenario;
  session: SessionState;
  results: PipelineResult[];
  runId: number;
}

const PROTOCOLS: Protocol[] = ["MCP", "OPENAI", "REST"];

const finalWire = (s: Scenario, protocol: Protocol) => {
  const last = s.steps[s.steps.length - 1];
  return toWire(protocol, last.tool, last.args);
};

/** Tiny JSON highlighter for the payload preview underlay. */
function highlight(json: string) {
  return json.split(/("(?:\\.|[^"\\])*"\s*:?|\b-?\d+(?:\.\d+)?\b|true|false|null)/g).map((tok, i) => {
    if (!tok) return null;
    if (/^"/.test(tok)) return <span key={i} className={tok.trimEnd().endsWith(":") ? "text-code-ident" : "text-chip-fg"}>{tok}</span>;
    if (/^(-?\d|true|false|null)/.test(tok)) return <span key={i} className="text-amber-300">{tok}</span>;
    return <span key={i} className="text-code-punct">{tok}</span>;
  });
}

export default function AttackStudio({ busy, onRun }: { busy: boolean; onRun: (run: StudioRun) => void }) {
  const [scenario, setScenario] = useState<Scenario>(SCENARIOS[0]);
  const [protocol, setProtocol] = useState<Protocol>(SCENARIOS[0].protocol);
  const [payload, setPayload] = useState(() => finalWire(SCENARIOS[0], SCENARIOS[0].protocol));
  const [menu, setMenu] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);
  const runSeq = useRef(0);
  const preRef = useRef<HTMLPreElement>(null);

  useEffect(() => {
    if (!menu) return;
    const close = (e: PointerEvent) => !menuRef.current?.contains(e.target as Node) && setMenu(false);
    document.addEventListener("pointerdown", close);
    return () => document.removeEventListener("pointerdown", close);
  }, [menu]);

  const choose = (s: Scenario) => {
    setScenario(s);
    setProtocol(s.protocol);
    setPayload(finalWire(s, s.protocol));
    setMenu(false);
  };

  const execute = () => {
    const gw = getGateway();
    const res = runScript(gw, scenarioScript({ ...scenario, protocol }), { finalRaw: payload, gapMs: 900 });
    onRun({ scenario, ...res, runId: ++runSeq.current });
  };

  const edited = payload !== finalWire(scenario, protocol);

  return (
    <motion.div
      initial={{ opacity: 0, y: 24, scale: 0.98 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      transition={{ duration: 0.8, delay: 0.25, ease: [0.22, 1, 0.36, 1] }}
      className="w-full overflow-visible rounded-2xl border border-line bg-window shadow-[0_30px_80px_-30px_rgba(0,0,0,0.7)] backdrop-blur-xl"
    >
      {/* window chrome */}
      <div className="flex h-[60px] items-center justify-between gap-3 border-b border-line px-4 sm:px-5">
        <div className="hidden gap-2 sm:flex" aria-hidden="true">
          {[0, 1, 2].map((i) => (
            <span key={i} className="h-[13px] w-[13px] rounded-full bg-fg/15" />
          ))}
        </div>
        <div className="flex min-w-0 items-center gap-2">
          <button
            type="button"
            aria-label="Reset payload"
            title="Reset payload"
            onClick={() => setPayload(finalWire(scenario, protocol))}
            className="group grid h-9 w-10 place-items-center rounded-lg border border-line bg-surface text-fg/70 hover:bg-surface-hover hover:text-fg"
          >
            <RotateCcw className="h-4 w-4 transition-transform duration-500 group-active:-rotate-180" />
          </button>
          <div ref={menuRef} className="relative min-w-0">
            <button
              type="button"
              aria-haspopup="menu"
              aria-expanded={menu}
              onClick={() => setMenu((m) => !m)}
              className="flex h-9 max-w-[220px] items-center gap-2 rounded-lg border border-line bg-surface px-3 font-mono text-[13px] text-fg/80 hover:bg-surface-hover sm:max-w-none"
            >
              <span className="rounded bg-accent/20 px-1.5 text-[11px] font-bold text-accent">{scenario.id}</span>
              <span className="truncate">{scenario.short}</span>
              <ChevronDown className={cx("h-4 w-4 shrink-0 transition-transform", menu && "rotate-180")} />
            </button>
            <AnimatePresence>
              {menu && (
                <motion.ul
                  role="menu"
                  initial={{ opacity: 0, y: -6, scale: 0.97 }}
                  animate={{ opacity: 1, y: 0, scale: 1 }}
                  exit={{ opacity: 0, y: -6, scale: 0.97 }}
                  transition={{ duration: 0.15 }}
                  className="absolute right-0 top-11 z-30 w-[min(430px,85vw)] origin-top-right rounded-xl border border-line bg-panel-strong p-1.5 shadow-2xl backdrop-blur-xl"
                >
                  <li className="px-2.5 pb-1.5 pt-1 text-[11px] font-semibold uppercase tracking-wider text-subtle">Attack scenarios</li>
                  {SCENARIOS.map((s) => (
                    <li key={s.id}>
                      <button
                        type="button"
                        role="menuitem"
                        onClick={() => choose(s)}
                        className="flex w-full items-start gap-2.5 rounded-lg px-2.5 py-2 text-left hover:bg-surface-hover"
                      >
                        <span className="mt-0.5 rounded bg-accent/15 px-1.5 font-mono text-[11px] font-bold text-accent">{s.id}</span>
                        <span className="min-w-0 flex-1">
                          <span className="block text-[13.5px] font-medium text-fg">{s.title.replace(/^Scenario .: /, "")}</span>
                          <span className="block text-[12px] text-subtle">{s.expected}</span>
                        </span>
                        {s.id === scenario.id && <Check className="mt-0.5 h-4 w-4 text-accent" />}
                      </button>
                    </li>
                  ))}
                </motion.ul>
              )}
            </AnimatePresence>
          </div>
        </div>
      </div>

      <div className="space-y-4 p-5">
        <p className="text-[13.5px] leading-relaxed text-muted">{scenario.description}</p>

        {/* context steps */}
        <div>
          <p className="mb-2 font-mono text-[11px] uppercase tracking-[0.12em] text-subtle">Session · {scenario.principal.agentId} → {scenario.principal.userId}</p>
          <ol className="space-y-1.5">
            <li className="flex items-center gap-2 font-mono text-[12.5px]">
              <span className="w-5 text-subtle">0</span>
              <span className="text-subtle">goal</span>
              <span className="truncate text-fg/80">“{scenario.goal}”</span>
            </li>
            {scenario.steps.map((s, i) => (
              <li key={i} className="flex items-center gap-2 font-mono text-[12.5px]">
                <span className="w-5 text-subtle">{i + 1}</span>
                <span className={cx(i === scenario.steps.length - 1 ? "text-accent" : "text-code-ident")}>{s.tool}</span>
                <span className="truncate text-subtle">{i === scenario.steps.length - 1 ? "← payload below (editable)" : s.note}</span>
              </li>
            ))}
          </ol>
        </div>

        {/* protocol + payload editor */}
        <div>
          <div className="mb-2 flex items-center justify-between gap-2">
            <div className="flex rounded-lg border border-line bg-surface p-0.5">
              {PROTOCOLS.map((p) => (
                <button
                  key={p}
                  type="button"
                  onClick={() => {
                    setProtocol(p);
                    setPayload(finalWire(scenario, p));
                  }}
                  className={cx("rounded-md px-2.5 py-1 font-mono text-[11.5px] font-semibold transition-colors", protocol === p ? "bg-accent text-[#1a0d03]" : "text-muted hover:text-fg")}
                >
                  {p === "OPENAI" ? "OpenAI fn" : p}
                </button>
              ))}
            </div>
            <span className="font-mono text-[11px] text-subtle">{edited ? "● edited" : `${new TextEncoder().encode(payload).length} B`}</span>
          </div>
          <div className="relative h-[210px] overflow-hidden rounded-xl border border-line bg-black/30 focus-within:ring-2 focus-within:ring-accent/50">
            <pre ref={preRef} aria-hidden="true" className="pointer-events-none absolute inset-0 overflow-hidden whitespace-pre-wrap break-all p-4 font-mono text-[12.5px] leading-[1.65]">
              {highlight(payload)}
              {"\n"}
            </pre>
            <textarea
              value={payload}
              onChange={(e) => setPayload(e.target.value)}
              onScroll={(e) => preRef.current && (preRef.current.scrollTop = e.currentTarget.scrollTop)}
              spellCheck={false}
              aria-label="Raw tool-call payload"
              className="scrollbar-thin absolute inset-0 h-full w-full resize-none whitespace-pre-wrap break-all bg-transparent p-4 font-mono text-[12.5px] leading-[1.65] text-transparent caret-accent outline-none selection:bg-accent/30"
            />
          </div>
          <p className="mt-2 text-[12px] text-subtle">Tip: try a duplicate JSON key, nesting deeper than 16, or an SSRF URL — ingress and policy react to your edits.</p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <button
            type="button"
            onClick={execute}
            disabled={busy}
            className="group inline-flex h-12 flex-1 items-center justify-center gap-2.5 rounded-xl bg-accent px-6 text-[15.5px] font-semibold text-[#1a0d03] shadow-[0_10px_40px_-10px_rgba(249,115,22,0.7),inset_0_1px_0_rgba(255,255,255,0.25)] transition-[filter,transform] hover:brightness-110 active:scale-[0.98] disabled:opacity-60"
          >
            {busy ? <Loader2 className="h-5 w-5 animate-spin" /> : <Play className="h-5 w-5" />}
            {busy ? "Executing through gateway…" : "Execute Through Gateway"}
          </button>
          <span className="flex items-center gap-2 text-[12px] text-subtle">
            expected <VerdictBadge verdict={scenario.expected.split(" ")[0] as Verdict} />
          </span>
        </div>
      </div>
    </motion.div>
  );
}
