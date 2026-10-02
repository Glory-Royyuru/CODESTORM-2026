"use client";

import { useRouter } from "next/navigation";
import { DemoTag, Tabs } from "@/components/ui/primitives";

type Mode = "live" | "demo";

const HREF: Record<Mode, string> = { live: "/provenance/live", demo: "/provenance" };

/** Switch between the real Live Request Trace and the simulated demo Provenance DAG. */
export default function ProvenanceModeTabs({ current, className }: { current: Mode; className?: string }) {
  const router = useRouter();
  return (
    <Tabs
      size="sm"
      className={className}
      label="Trace source"
      value={current}
      onChange={(mode) => mode !== current && router.push(HREF[mode])}
      items={[
        { id: "live", label: <>Live Request Trace</> },
        {
          id: "demo",
          label: (
            <>
              Demo Provenance <DemoTag />
            </>
          ),
        },
      ]}
    />
  );
}
