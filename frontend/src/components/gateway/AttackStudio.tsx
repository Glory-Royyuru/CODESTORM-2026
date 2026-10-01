"use client";

import { AnimatePresence, motion } from "framer-motion";
import { Check, ChevronDown, Loader2, Play, RotateCcw } from "lucide-react";
import { Fragment, useEffect, useRef, useState } from "react";
import { cx, VerdictBadge } from "@/components/ui/primitives";
import { BACKEND_ENDPOINT, type SatgOutcome } from "@/lib/satg/client";
import { PRESETS, type RequestPreset } from "@/lib/satg/presets";

/** One real backend exchange shown by the Live Gateway panels (from this editor or the agent console). */
export interface StudioRun {
  /** What was sent: the preset's title, or the agent instruction. */
  title: string;
  requestBody: string;
  outcome: SatgOutcome;
  runId: number;
}

const INGRESS_LIMIT_BYTES = 64 * 1024;

/** Tiny JSON highlighter for the payload preview underlay. */
function highlight(json: string) {
  return json.split(/("(?:\\.|[^"\\])*"\s*:?|\b-?\d+(?:\.\d+)?\b|true|false|null)/g).map((tok, i) => {
    if (!tok) return null;
    if (/^"/.test(tok)) return <span key={i} className={tok.trimEnd().endsWith(":") ? "text-code-ident" : "text-chip-fg"}>{tok}</span>;
    if (/^(-?\d|true|false|null)/.test(tok)) return <span key={i} className="text-amber-300">{tok}</span>;
    return <span key={i} className="text-code-punct">{tok}</span>;
  });
}

/** Request editor: pick an example, edit the raw body, send it to the real SATG backend. */
export default function AttackStudio({ busy, onRun }: { busy: boolean; onRun: (preset: RequestPreset, body: string) => void }) {
  const [preset, setPreset] = useState<RequestPreset>(PRESETS[0]);
  const [payload, setPayload] = useState(PRESETS[0].body);
  const [menu, setMenu] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);
  const preRef = useRef<HTMLPreElement>(null);

  useEffect(() => {
    if (!menu) return;
    const close = (e: PointerEvent) => !menuRef.current?.contains(e.target as Node) && setMenu(false);
    document.addEventListener("pointerdown", close);
    return () => document.removeEventListener("pointerdown", close);
  }, [menu]);

  const choose = (p: RequestPreset) => {
    setPreset(p);
    setPayload(p.body);
    setMenu(false);
  };

  const edited = payload !== preset.body;
  const bytes = new TextEncoder().encode(payload).length;
  const [expectedVerdict, ...expectedRule] = preset.expected.split(" · ");

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
            onClick={() => setPayload(preset.body)}
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
              className="flex h-9 max-w-[240px] items-center gap-2 rounded-lg border border-line bg-surface px-3 font-mono text-[13px] text-fg/80 hover:bg-surface-hover sm:max-w-none"
            >
              <span className="rounded bg-accent/20 px-1.5 text-[11px] font-bold text-accent">{preset.group}</span>
              <span className="truncate">{preset.title}</span>
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
                  className="scrollbar-thin absolute right-0 top-11 z-30 max-h-[min(560px,70vh)] w-[min(460px,85vw)] origin-top-right overflow-y-auto rounded-xl border border-line bg-panel-strong p-1.5 shadow-2xl backdrop-blur-xl"
                >
                  {PRESETS.map((p, i) => (
                    <Fragment key={p.id}>
                      {(i === 0 || PRESETS[i - 1].group !== p.group) && (
                        <li className="px-2.5 pb-1.5 pt-2 text-[11px] font-semibold uppercase tracking-wider text-subtle">{p.group}</li>
                      )}
                      <li>
                        <button
                          type="button"
                          role="menuitem"
                          onClick={() => choose(p)}
                          className="flex w-full items-start gap-2.5 rounded-lg px-2.5 py-2 text-left hover:bg-surface-hover"
                        >
                          <span className="min-w-0 flex-1">
                            <span className="block text-[13.5px] font-medium text-fg">{p.title}</span>
                            <span className="block font-mono text-[11.5px] text-subtle">designed to trigger {p.expected}</span>
                          </span>
                          {p.id === preset.id && <Check className="mt-0.5 h-4 w-4 text-accent" />}
                        </button>
                      </li>
                    </Fragment>
                  ))}
                </motion.ul>
              )}
            </AnimatePresence>
          </div>
        </div>
      </div>

      <div className="space-y-4 p-5">
        <p className="text-[13.5px] leading-relaxed text-muted">{preset.description}</p>

        {/* request line */}
        <div className="space-y-1.5 font-mono text-[12.5px]">
          <p className="flex flex-wrap items-center gap-2">
            <span className="rounded bg-emerald-400/10 px-1.5 font-semibold text-emerald-300 ring-1 ring-emerald-400/30">LIVE</span>
            <span className="text-fg/85">{BACKEND_ENDPOINT}</span>
            <span className="text-subtle">· FastAPI SATG backend via /api/satg</span>
          </p>
          <p className="text-[11.5px] text-subtle">agent_id is self-asserted (no authentication yet) · allowed calls run in a disposable, network-less Docker sandbox</p>
        </div>

        {/* payload editor */}
        <div>
          <div className="mb-2 flex items-center justify-between gap-2">
            <span className="rounded-lg border border-line bg-surface px-2.5 py-1 font-mono text-[11.5px] font-semibold text-muted">application/json · raw body</span>
            <span className={cx("font-mono text-[11px]", bytes > INGRESS_LIMIT_BYTES ? "text-red-300" : "text-subtle")}>
              {edited ? "● edited · " : ""}
              {bytes} B{bytes > INGRESS_LIMIT_BYTES ? " (over the 64 KiB ingress limit)" : ""}
            </span>
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
              aria-label="Raw tool-call request body"
              className="scrollbar-thin absolute inset-0 h-full w-full resize-none whitespace-pre-wrap break-all bg-transparent p-4 font-mono text-[12.5px] leading-[1.65] text-transparent caret-accent outline-none selection:bg-accent/30"
            />
          </div>
          <p className="mt-2 text-[12px] text-subtle">
            The body is sent byte-for-byte. Try a duplicate key, nesting deeper than 8, NaN, an unknown field, or a recipient outside company.com — the backend decides.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <button
            type="button"
            onClick={() => onRun(preset, payload)}
            disabled={busy}
            className="group inline-flex h-12 flex-1 items-center justify-center gap-2.5 rounded-xl bg-accent px-6 text-[15.5px] font-semibold text-[#1a0d03] shadow-[0_10px_40px_-10px_rgba(249,115,22,0.7),inset_0_1px_0_rgba(255,255,255,0.25)] transition-[filter,transform] hover:brightness-110 active:scale-[0.98] disabled:opacity-60"
          >
            {busy ? <Loader2 className="h-5 w-5 animate-spin" /> : <Play className="h-5 w-5" />}
            {busy ? "Waiting for SATG backend…" : "Send Through Gateway"}
          </button>
          <span className="flex items-center gap-2 text-[12px] text-subtle" title="What this example is designed to trigger — not a result">
            designed for <VerdictBadge verdict={expectedVerdict === "ALLOW" ? "ALLOW" : expectedVerdict === "ESCALATE" ? "HUMAN_APPROVAL" : "BLOCK"} />
            <span className="font-mono">{expectedRule.join(" · ")}</span>
          </span>
        </div>
      </div>
    </motion.div>
  );
}
