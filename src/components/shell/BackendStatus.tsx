"use client";

import { useEffect, useState } from "react";
import { cx } from "@/components/ui/primitives";
import { checkHealth, type BackendHealth } from "@/lib/satg/client";

const POLL_MS = 15_000;

const STYLE: Record<BackendHealth | "checking", { dot: string; text: string }> = {
  online: { dot: "bg-emerald-400", text: "Backend online" },
  degraded: { dot: "bg-amber-400", text: "Backend degraded" },
  offline: { dot: "bg-red-500", text: "Backend offline" },
  checking: { dot: "bg-fg/30 animate-pulse", text: "Backend…" },
};

/** Health of the real SATG FastAPI backend (GET /health via the proxy). */
export default function BackendStatus() {
  const [health, setHealth] = useState<BackendHealth | "checking">("checking");

  useEffect(() => {
    let alive = true;
    const probe = () => void checkHealth().then((h) => alive && setHealth(h));
    probe();
    const id = setInterval(probe, POLL_MS);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, []);

  const s = STYLE[health];
  return (
    <span
      title="SATG FastAPI backend health (GET /health)"
      className="hidden h-10 items-center gap-2 rounded-xl border border-line bg-surface px-3 font-mono text-[12px] font-semibold text-fg/80 lg:flex"
    >
      <span className={cx("h-2 w-2 rounded-full", s.dot)} />
      {s.text}
    </span>
  );
}
