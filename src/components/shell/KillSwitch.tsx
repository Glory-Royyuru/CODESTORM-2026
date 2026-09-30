"use client";

import { Power } from "lucide-react";
import { cx } from "@/components/ui/primitives";
import { getGateway, useGateway, useUi } from "@/lib/store";
import { toWire } from "@/lib/gateway/ingress";

/** Global emergency kill switch (M1/M11): flips the gateway into FAIL_CLOSED. */
export default function KillSwitch() {
  const gw = useGateway();
  const toast = useUi((s) => s.toast);
  const engaged = gw.mode === "FAIL_CLOSED";

  const toggle = () => {
    const g = getGateway();
    if (!engaged) {
      g.setMode("FAIL_CLOSED");
      // Prove the acceptance criterion: the very next call is blocked at ingress.
      const probe = g.createSession({ agentId: "agent:kill-switch-probe", userId: "u_secops", tenant: "acme" }, "Kill-switch verification probe", ["calendar:read"]);
      const res = g.process({ raw: toWire("MCP", "calendar_read", { from: "2026-09-30", to: "2026-09-30" }), sessionId: probe.id, groundTruth: "benign", scenario: "kill-switch-probe" });
      const b = res.entry.receipt.body;
      toast({ tone: "danger", title: "Kill switch engaged — gateway FAIL_CLOSED", detail: `Probe call ${b.verdict} in ${b.totalLatencyMs}ms · receipt #${b.seq} signed` });
    } else {
      g.setMode("ENFORCING");
      toast({ tone: "success", title: "Gateway restored to ENFORCING", detail: "Deterministic policy + ML fusion active" });
    }
  };

  return (
    <button
      type="button"
      onClick={toggle}
      aria-pressed={engaged}
      title={engaged ? "Disengage kill switch" : "Engage global emergency kill switch"}
      className={cx(
        "flex h-10 items-center gap-2 rounded-xl border px-3 text-[13px] font-semibold transition-colors",
        engaged ? "pulse-ring border-red-500/60 bg-red-500/20 text-red-200" : "border-line bg-surface text-fg/80 hover:border-red-500/40 hover:text-red-300",
      )}
    >
      <Power className="h-4 w-4" />
      <span className="hidden sm:inline">{engaged ? "FAIL_CLOSED" : "Kill Switch"}</span>
      <span className={cx("h-2 w-2 rounded-full", engaged ? "bg-red-500" : "bg-emerald-400")} />
    </button>
  );
}
