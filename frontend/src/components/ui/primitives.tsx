"use client";

import { AnimatePresence, motion } from "framer-motion";
import { Check, Copy, X } from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";
import type { TaintLattice, ToolStatus, Verdict } from "@/lib/gateway/types";
import { STATUS_STYLE, TAINT_HEX, VERDICT_DISPLAY, VERDICT_FAMILY_STYLE } from "./tokens";

export function cx(...c: (string | false | null | undefined)[]) {
  return c.filter(Boolean).join(" ");
}

export function Panel({ className, children }: { className?: string; children: ReactNode }) {
  return <div className={cx("panel", className)}>{children}</div>;
}

/** A demo-engine verdict shown in the backend's vocabulary: ALLOW / ESCALATE / BLOCK, plus a qualifier such as "· quarantine". */
export function VerdictBadge({ verdict, size = "sm" }: { verdict: Verdict; size?: "sm" | "lg" }) {
  const d = VERDICT_DISPLAY[verdict];
  const s = VERDICT_FAMILY_STYLE[d.family];
  return (
    <span
      title={`Demo-engine verdict: ${verdict}`}
      className={cx(
        "inline-flex items-center gap-1.5 whitespace-nowrap rounded-md font-mono font-semibold ring-1",
        s.fg,
        s.bg,
        s.ring,
        size === "lg" ? "px-3 py-1.5 text-sm" : "px-2 py-0.5 text-[11px]",
      )}
    >
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: s.hex }} />
      {d.family}
      {d.qualifier && <span className="font-normal opacity-75">· {d.qualifier}</span>}
    </span>
  );
}

export function TaintBadge({ label }: { label: TaintLattice }) {
  return (
    <span
      className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 font-mono text-[10px] font-semibold ring-1"
      style={{ color: TAINT_HEX[label], background: `${TAINT_HEX[label]}14`, boxShadow: `inset 0 0 0 1px ${TAINT_HEX[label]}40` }}
    >
      {label}
    </span>
  );
}

export function StatusBadge({ status }: { status: ToolStatus }) {
  const s = STATUS_STYLE[status];
  return <span className={cx("rounded-md px-2 py-0.5 font-mono text-[11px] font-semibold ring-1", s.fg, s.bg, s.ring)}>{status}</span>;
}

export function PageHeader({ eyebrow, title, description, actions }: { eyebrow: string; title: ReactNode; description?: ReactNode; actions?: ReactNode }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, ease: [0.22, 1, 0.36, 1] }}
      className="mb-6 flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between"
    >
      <div className="max-w-3xl">
        <p className="mb-2 font-mono text-[11.5px] font-medium uppercase tracking-[0.14em] text-accent">{eyebrow}</p>
        <h1 className="text-[clamp(1.6rem,2.2vw,2.125rem)] font-medium leading-[1.15] tracking-[-0.025em] text-fg">{title}</h1>
        {description && <p className="mt-2.5 text-[14.5px] leading-relaxed text-muted">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-3">{actions}</div>}
    </motion.div>
  );
}

/** The standard marker for anything run by the in-browser demo engine rather than the SATG backend. */
export function DemoTag({ label = "SIM", title = "Simulated by the in-browser demo engine, not the SATG backend", className }: { label?: string; title?: string; className?: string }) {
  return (
    <span title={title} className={cx("rounded bg-fg/10 px-1 font-mono text-[10px] text-subtle", className)}>
      {label}
    </span>
  );
}

/** Segmented tabs in the console's outlined style (active = orange outline, as in the Live Gateway's detail toggles). */
export function Tabs<T extends string>({
  items,
  value,
  onChange,
  size = "md",
  label,
  className,
}: {
  items: readonly { id: T; label: ReactNode; count?: number }[];
  value: T;
  onChange: (id: T) => void;
  size?: "sm" | "md";
  label?: string;
  className?: string;
}) {
  return (
    <div role="tablist" aria-label={label} className={cx("flex w-fit rounded-xl border border-line bg-surface p-1", className)}>
      {items.map((t) => {
        const active = t.id === value;
        return (
          <button
            key={t.id}
            type="button"
            role="tab"
            aria-selected={active}
            onClick={() => onChange(t.id)}
            className={cx(
              "flex items-center gap-2 rounded-lg border font-semibold transition-colors",
              size === "md" ? "px-3.5 py-2 text-[13.5px]" : "px-3 py-1.5 text-[13px]",
              active ? "border-accent/50 bg-accent/10 text-fg" : "border-transparent text-muted hover:text-fg",
            )}
          >
            {t.label}
            {t.count !== undefined && <span className="font-mono text-[11px] opacity-70">{t.count}</span>}
          </button>
        );
      })}
    </div>
  );
}

export function Button({
  children,
  onClick,
  variant = "secondary",
  disabled,
  className,
  type = "button",
  title,
}: {
  children: ReactNode;
  onClick?: () => void;
  variant?: "primary" | "secondary" | "danger" | "ghost";
  disabled?: boolean;
  className?: string;
  type?: "button" | "submit";
  title?: string;
}) {
  const styles = {
    primary:
      "bg-accent text-[#1a0d03] shadow-[0_10px_30px_-12px_rgba(249,115,22,0.8),inset_0_1px_0_rgba(255,255,255,0.25)] hover:brightness-110",
    secondary: "border border-line bg-surface text-fg hover:bg-surface-hover",
    danger: "border border-red-500/40 bg-red-500/15 text-red-300 hover:bg-red-500/25",
    ghost: "text-muted hover:bg-surface hover:text-fg",
  }[variant];
  return (
    <button
      type={type}
      title={title}
      onClick={onClick}
      disabled={disabled}
      className={cx(
        "inline-flex h-10 items-center justify-center gap-2 rounded-xl px-4 text-[14px] font-semibold transition-[filter,background-color,transform] active:scale-[0.98] disabled:pointer-events-none disabled:opacity-45",
        styles,
        className,
      )}
    >
      {children}
    </button>
  );
}

export function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      onClick={() => {
        void navigator.clipboard?.writeText(text);
        setDone(true);
        setTimeout(() => setDone(false), 1400);
      }}
      className="inline-flex items-center gap-1.5 rounded-lg border border-line bg-surface px-2.5 py-1 text-[12px] font-medium text-muted transition-colors hover:bg-surface-hover hover:text-fg"
    >
      {done ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
      {done ? "Copied" : label}
    </button>
  );
}

export function Hash({ value, n = 10, className }: { value: string; n?: number; className?: string }) {
  return (
    <span title={value} className={cx("font-mono text-[12px] text-code", className)}>
      {value.length > n * 2 + 1 ? `${value.slice(0, n)}…${value.slice(-4)}` : value}
    </span>
  );
}

export function Stat({ label, value, hint, tone }: { label: string; value: ReactNode; hint?: ReactNode; tone?: string }) {
  return (
    <div className="panel p-5">
      <p className="text-[12px] font-medium uppercase tracking-[0.1em] text-subtle">{label}</p>
      <p className={cx("mt-2 font-mono text-[28px] font-semibold tracking-tight", tone ?? "text-fg")}>{value}</p>
      {hint && <p className="mt-1 text-[12.5px] text-muted">{hint}</p>}
    </div>
  );
}

function useEscape(open: boolean, onClose: () => void) {
  useEffect(() => {
    if (!open) return;
    const h = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [open, onClose]);
}

export function Drawer({ open, onClose, title, children, width = "max-w-xl" }: { open: boolean; onClose: () => void; title: ReactNode; children: ReactNode; width?: string }) {
  useEscape(open, onClose);
  return (
    <AnimatePresence>
      {open && (
        <>
          <motion.div className="fixed inset-0 z-40 bg-black/50 backdrop-blur-[2px]" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={onClose} />
          <motion.aside
            role="dialog"
            aria-modal="true"
            initial={{ x: "100%" }}
            animate={{ x: 0 }}
            exit={{ x: "100%" }}
            transition={{ type: "spring", damping: 32, stiffness: 320 }}
            className={cx("fixed inset-y-0 right-0 z-50 flex w-full flex-col border-l border-line bg-panel-strong backdrop-blur-xl", width)}
          >
            <div className="flex items-center justify-between border-b border-line px-6 py-4">
              <div className="min-w-0 text-[16px] font-semibold text-fg">{title}</div>
              <button type="button" onClick={onClose} aria-label="Close" className="rounded-lg p-2 text-muted hover:bg-surface hover:text-fg">
                <X className="h-4 w-4" />
              </button>
            </div>
            <div className="scrollbar-thin flex-1 overflow-y-auto px-6 py-5">{children}</div>
          </motion.aside>
        </>
      )}
    </AnimatePresence>
  );
}

export function Modal({ open, onClose, title, children }: { open: boolean; onClose: () => void; title: ReactNode; children: ReactNode }) {
  useEscape(open, onClose);
  return (
    <AnimatePresence>
      {open && (
        <motion.div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/60 p-4 backdrop-blur-[3px] sm:p-8" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={onClose}>
          <motion.div
            role="dialog"
            aria-modal="true"
            initial={{ opacity: 0, y: 20, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 12, scale: 0.98 }}
            transition={{ duration: 0.25, ease: [0.22, 1, 0.36, 1] }}
            onClick={(e) => e.stopPropagation()}
            className="w-full max-w-5xl rounded-2xl border border-line bg-panel-strong shadow-2xl backdrop-blur-xl"
          >
            <div className="flex items-center justify-between border-b border-line px-6 py-4">
              <div className="min-w-0 text-[16px] font-semibold text-fg">{title}</div>
              <button type="button" onClick={onClose} aria-label="Close" className="rounded-lg p-2 text-muted hover:bg-surface hover:text-fg">
                <X className="h-4 w-4" />
              </button>
            </div>
            <div className="p-6">{children}</div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}

export function SectionTitle({ children, right }: { children: ReactNode; right?: ReactNode }) {
  return (
    <div className="mb-3 flex items-center justify-between gap-3">
      <h3 className="text-[13px] font-semibold uppercase tracking-[0.1em] text-subtle">{children}</h3>
      {right}
    </div>
  );
}

export function JsonBlock({ value, className }: { value: unknown; className?: string }) {
  return (
    <pre className={cx("scrollbar-thin overflow-auto rounded-xl border border-line bg-black/30 p-4 font-mono text-[12px] leading-relaxed text-code", className)}>
      {typeof value === "string" ? value : JSON.stringify(value, null, 2)}
    </pre>
  );
}

export const timeAgo = (t: number) => {
  const s = Math.max(0, Math.round((Date.now() - t) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  return `${Math.round(s / 3600)}h ago`;
};
