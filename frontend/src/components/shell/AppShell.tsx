"use client";

import { useEffect, type ReactNode } from "react";
import { ShieldCheck } from "lucide-react";
import InteractiveBackground from "@/components/hero/InteractiveBackground";
import { DEFAULT_BENDS } from "@/components/hero/colorBends";
import { useGateway, useIsClient, useUi } from "@/lib/store";
import SimulationNotice from "./SimulationNotice";
import TopNav from "./TopNav";
import Toasts from "./Toasts";

const FAIL_CLOSED_BENDS = { ...DEFAULT_BENDS, color: "#EF4444", speed: 0.9, intensity: 1.6 };

function EngineBackground() {
  const gw = useGateway();
  const theme = useUi((s) => s.theme);
  return <InteractiveBackground bends={gw.mode === "FAIL_CLOSED" ? FAIL_CLOSED_BENDS : DEFAULT_BENDS} theme={theme} />;
}

export default function AppShell({ children }: { children: ReactNode }) {
  const isClient = useIsClient();
  const theme = useUi((s) => s.theme);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
  }, [theme]);

  if (!isClient) {
    // The in-browser demo engine seeds itself with live timestamps + a fresh key, so the console renders client-side only.
    return (
      <div className="flex min-h-screen items-center justify-center">
        <div className="flex items-center gap-3 font-mono text-[13px] text-subtle">
          <ShieldCheck className="h-4 w-4 animate-pulse text-accent" />
          Loading console…
        </div>
      </div>
    );
  }

  return (
    <div className="relative min-h-screen">
      <EngineBackground />
      <TopNav />
      <main className="relative mx-auto w-[min(1596px,calc(100%-2rem))] pb-24 pt-6 sm:w-[min(1596px,calc(100%-4rem))] lg:pt-10">
        <SimulationNotice />
        {children}
      </main>
      <Toasts />
    </div>
  );
}
