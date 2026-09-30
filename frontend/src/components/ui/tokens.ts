import type { TaintLattice, ToolStatus, Verdict } from "@/lib/gateway/types";

export const VERDICT_STYLE: Record<Verdict, { fg: string; bg: string; ring: string; hex: string }> = {
  ALLOW: { fg: "text-emerald-400", bg: "bg-emerald-400/10", ring: "ring-emerald-400/30", hex: "#34d399" },
  MONITOR: { fg: "text-sky-400", bg: "bg-sky-400/10", ring: "ring-sky-400/30", hex: "#38bdf8" },
  STEP_UP: { fg: "text-amber-400", bg: "bg-amber-400/10", ring: "ring-amber-400/30", hex: "#fbbf24" },
  HUMAN_APPROVAL: { fg: "text-violet-400", bg: "bg-violet-400/10", ring: "ring-violet-400/30", hex: "#a78bfa" },
  QUARANTINE: { fg: "text-fuchsia-400", bg: "bg-fuchsia-400/10", ring: "ring-fuchsia-400/30", hex: "#e879f9" },
  BLOCK: { fg: "text-red-400", bg: "bg-red-500/10", ring: "ring-red-500/30", hex: "#f87171" },
};

export const TAINT_HEX: Record<TaintLattice, string> = {
  TRUSTED: "#34d399",
  INTERNAL: "#60a5fa",
  UNTRUSTED: "#f472b6",
  SENSITIVE: "#fbbf24",
  SECRET: "#a78bfa",
  TAINTED: "#ef4444",
};

export const STATUS_STYLE: Record<ToolStatus, { fg: string; bg: string; ring: string }> = {
  VERIFIED: { fg: "text-emerald-400", bg: "bg-emerald-400/10", ring: "ring-emerald-400/30" },
  POISONED: { fg: "text-red-400", bg: "bg-red-500/10", ring: "ring-red-500/30" },
  QUARANTINED: { fg: "text-fuchsia-400", bg: "bg-fuchsia-400/10", ring: "ring-fuchsia-400/30" },
};

export const TIER_LABEL: Record<number, string> = {
  1: "Tier 1 · Read-only",
  2: "Tier 2 · Sensitive read",
  3: "Tier 3 · Egress / secrets",
  4: "Tier 4 · Destructive",
};
