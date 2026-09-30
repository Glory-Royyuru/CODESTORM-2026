"use client";

import { FlaskConical } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";

/** Routes backed by the real SATG backend. Every other screen runs on the in-browser demo engine. */
const LIVE_ROUTES = new Set(["/", "/gateway"]);

export default function SimulationNotice() {
  const pathname = usePathname();
  if (LIVE_ROUTES.has(pathname)) return null;
  return (
    <div className="mb-6 flex flex-wrap items-center gap-x-3 gap-y-1 rounded-xl border border-amber-400/30 bg-amber-400/5 px-4 py-2.5 text-[13px] text-fg/85">
      <FlaskConical className="h-4 w-4 shrink-0 text-amber-300" />
      <span>
        <span className="font-semibold text-amber-300">Simulation.</span> This screen runs on the in-browser demo engine, not the SATG backend. Its decisions,
        receipts, ML scores and sandbox runs are illustrative and not authoritative.
      </span>
      <Link href="/" className="font-semibold text-accent hover:underline">
        Live Gateway uses the real backend →
      </Link>
    </div>
  );
}
