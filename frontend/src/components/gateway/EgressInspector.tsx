"use client";

import { motion } from "framer-motion";
import { ArrowRight, CheckCircle2, CircleDashed, Fingerprint, Globe, Network, ShieldAlert, XCircle } from "lucide-react";
import Link from "next/link";
import HexView from "@/components/ui/HexView";
import { cx, Hash, Panel, SectionTitle } from "@/components/ui/primitives";
import type { SatgAnomaly, SatgNetworkCheck, SatgNetworkInspection, SatgVerdict } from "@/lib/satg/client";
import type { StudioRun } from "./AttackStudio";

/** Display names for backend/app/gateway/network.py check ids. Unknown ids are shown raw. */
const CHECK_LABELS: Record<string, { label: string; ranges?: string }> = {
  URL_PARSE: { label: "Strict URL parse" },
  SCHEME_HTTPS: { label: "HTTPS only" },
  LOCAL_HOSTNAME: { label: "Local hostname", ranges: "localhost · *.internal · *.local" },
  LOOPBACK: { label: "Loopback", ranges: "127.0.0.0/8 · ::1" },
  ZERO_ADDRESS: { label: "Zero address", ranges: "0.0.0.0/8 · ::" },
  RFC1918_PRIVATE: { label: "RFC1918 Check", ranges: "10/8 · 172.16/12 · 192.168/16" },
  LINK_LOCAL_METADATA: { label: "Cloud Metadata", ranges: "169.254.0.0/16 · fe80::/10" },
  UNIQUE_LOCAL_V6: { label: "Unique local v6", ranges: "fc00::/7" },
  MULTICAST_BROADCAST: { label: "Multicast / broadcast", ranges: "224/4 · ff00::/8 · 255.255.255.255" },
  DOMAIN_ALLOWLIST: { label: "eTLD+1 allowlist" },
  DNS_RESOLUTION_PINNED: { label: "DNS pinned" },
};

const STATUS: Record<SatgNetworkCheck["status"], { text: string; cls: string; icon: typeof CheckCircle2 }> = {
  PASSED: { text: "CLEAR", cls: "border-emerald-400/40 bg-emerald-400/10 text-emerald-300", icon: CheckCircle2 },
  BLOCKED: { text: "BLOCKED", cls: "border-red-500/60 bg-red-500/15 text-red-300", icon: XCircle },
  NOT_EVALUATED: { text: "NOT EVALUATED", cls: "border-line bg-surface text-subtle", icon: CircleDashed },
};

const SEVERITY_CLS: Record<SatgAnomaly["risk_severity"], string> = {
  CRITICAL: "bg-red-500/15 text-red-300 ring-red-500/40",
  HIGH: "bg-orange-500/15 text-orange-300 ring-orange-500/40",
  ELEVATED: "bg-amber-400/10 text-amber-300 ring-amber-400/30",
};

function Destination({ n }: { n: SatgNetworkInspection }) {
  const blocked = n.checks.find((c) => c.status === "BLOCKED");
  return (
    <div className="space-y-4">
      <div className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_auto_minmax(0,1fr)] sm:items-center">
        <div className="min-w-0 rounded-xl border border-line bg-surface p-3">
          <p className="font-mono text-[10.5px] uppercase tracking-[0.1em] text-subtle">Requested hostname</p>
          <p className="mt-1 break-all font-mono text-[13px] text-fg">{n.requested_host ?? "— unparseable"}</p>
          <p className="mt-1 break-all font-mono text-[11px] text-subtle">{n.requested_url}</p>
        </div>
        <ArrowRight className="mx-auto hidden h-5 w-5 text-subtle sm:block" />
        <div className={cx("min-w-0 rounded-xl border p-3", n.pinned_ip ? "border-emerald-400/40 bg-emerald-400/5" : "border-red-500/40 bg-red-500/5")}>
          <p className="font-mono text-[10.5px] uppercase tracking-[0.1em] text-subtle">Resolved → pinned IP</p>
          <p className={cx("mt-1 break-all font-mono text-[13px]", n.pinned_ip ? "text-emerald-300" : "text-red-300")}>
            {n.pinned_ip ?? (blocked ? "refused — no connection target" : "not resolved")}
          </p>
          <p className="mt-1 break-all font-mono text-[11px] text-subtle">
            {n.resolved_ips.length ? `DNS: ${n.resolved_ips.join(", ")}` : n.requested_host && /^[\d.:a-f]+$/.test(n.requested_host) ? "IP literal — no DNS lookup" : "no DNS answer used"}
          </p>
        </div>
      </div>

      <ul className="grid grid-cols-[repeat(auto-fill,minmax(190px,1fr))] gap-2">
        {n.checks.map((c) => {
          const meta = CHECK_LABELS[c.check] ?? { label: c.check };
          const s = STATUS[c.status];
          return (
            <li key={c.check} title={c.detail ?? undefined} className={cx("rounded-lg border px-3 py-2", s.cls)}>
              <div className="flex items-center justify-between gap-2">
                <span className="text-[12px] font-semibold">{meta.label}</span>
                <s.icon className="h-3.5 w-3.5 shrink-0" />
              </div>
              <p className="font-mono text-[10.5px] font-semibold">{s.text}</p>
              {meta.ranges && <p className="mt-0.5 font-mono text-[10px] opacity-70">{meta.ranges}</p>}
            </li>
          );
        })}
      </ul>
      {n.pinned_ip && (
        <p className="text-[12px] leading-relaxed text-subtle">
          Anti-rebinding: the execution layer must connect to <span className="font-mono text-code">{n.pinned_ip}</span> with SNI/Host{" "}
          <span className="font-mono text-code">{n.requested_host}</span> and never resolve the name again.
        </p>
      )}
    </div>
  );
}

function Integrity({ v }: { v: SatgVerdict }) {
  const tag = v.request_integrity;
  if (!tag)
    return (
      <p className="rounded-lg border border-dashed border-line p-3 text-[12.5px] text-subtle">
        No HMAC tag — only ALLOW verdicts are signed, so a downstream tool has nothing to accept and fails closed.
      </p>
    );
  return (
    <div className="space-y-2 rounded-xl border border-emerald-400/30 bg-emerald-400/5 p-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="inline-flex items-center gap-1.5 rounded-md bg-emerald-400/10 px-2 py-0.5 font-mono text-[11px] font-semibold text-emerald-300 ring-1 ring-emerald-400/30">
          <Fingerprint className="h-3.5 w-3.5" /> {tag.algorithm} · ISSUED
        </span>
        <span className="font-mono text-[11px] text-subtle">key {tag.key_id}</span>
      </div>
      <p className="break-all font-mono text-[12px] text-code">{tag.signature}</p>
      <p className="font-mono text-[11px] text-subtle">binds: {tag.signed_fields.join(" · ")}</p>
      <p className="text-[11.5px] leading-snug text-subtle">
        The console does not hold the gateway secret; the execution layer recomputes the tag and refuses the call if it is missing or differs.
      </p>
    </div>
  );
}

function Anomalies({ anomalies }: { anomalies: SatgAnomaly[] }) {
  return (
    <ul className="space-y-3">
      {anomalies.map((a) => (
        <li key={a.anomaly_id} className="rounded-xl border border-red-500/30 bg-red-500/5 p-3">
          <div className="flex flex-wrap items-center gap-2">
            <span className={cx("rounded-md px-2 py-0.5 font-mono text-[11px] font-semibold ring-1", SEVERITY_CLS[a.risk_severity])}>{a.risk_severity}</span>
            <span className="font-mono text-[12px] font-semibold text-fg">{a.anomaly_type}</span>
            <span className="font-mono text-[11px] text-subtle">
              {a.rule_id} · {a.location}
            </span>
          </div>
          <p className="mt-1.5 text-[12.5px] text-muted">{a.parser_error_detail}</p>
          <HexView hex={a.quarantined_hex_snippet} totalBytes={a.raw_payload_bytes} className="mt-2" />
          <div className="mt-2 flex flex-wrap items-center justify-between gap-2 font-mono text-[11px] text-subtle">
            <span>
              fingerprint <Hash value={a.raw_payload_sha256} n={14} />
            </span>
            <span className="text-red-300">{a.mitigation_action}</span>
          </div>
        </li>
      ))}
    </ul>
  );
}

/** Network boundary, request-integrity and quarantine facts from the last live backend verdict. */
export default function EgressInspector({ run }: { run: StudioRun | null }) {
  const v = run?.outcome.kind === "verdict" ? run.outcome.verdict : null;
  const hasFacts = !!v && (v.network.length > 0 || v.anomalies.length > 0 || !!v.request_integrity);

  return (
    <Panel className="p-5 sm:p-6">
      <SectionTitle
        right={
          <Link href="/provenance" className="font-mono text-[11.5px] text-accent hover:underline">
            eBPF egress model (simulated) →
          </Link>
        }
      >
        <span className="flex items-center gap-2">
          <Network className="h-4 w-4" /> Network & Egress Inspector
        </span>
      </SectionTitle>

      {!hasFacts || !v ? (
        <div className="flex flex-col items-center gap-2 rounded-xl border border-dashed border-line p-6 text-center">
          <Globe className="h-6 w-6 text-subtle" />
          <p className="max-w-xl text-[13.5px] text-muted">
            {v
              ? "This verdict carries no network, integrity or quarantine facts (the tool has no URL destination and the request was not allowed)."
              : "Send a request from the Network or Quarantine group to see resolved IPs, CIDR deny-range checks, the HMAC integrity tag and quarantined anomalies from the backend."}
          </p>
        </div>
      ) : (
        <motion.div key={run?.runId} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="grid gap-6 xl:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)]">
          <div className="min-w-0 space-y-5">
            {v.network.length > 0 ? (
              v.network.map((n) => (
                <section key={n.parameter}>
                  <p className="mb-2 font-mono text-[11px] uppercase tracking-[0.12em] text-subtle">Destination · parameter “{n.parameter}”</p>
                  <Destination n={n} />
                </section>
              ))
            ) : v.anomalies.length > 0 ? (
              <section>
                <p className="mb-2 flex items-center gap-2 font-mono text-[11px] uppercase tracking-[0.12em] text-subtle">
                  <ShieldAlert className="h-3.5 w-3.5" /> Quarantined crypt-arithmetic anomalies · {v.anomalies.length}
                </p>
                <Anomalies anomalies={v.anomalies} />
              </section>
            ) : (
              <p className="rounded-xl border border-dashed border-line p-4 text-[12.5px] text-subtle">This tool has no URL destination, so there is no network inspection.</p>
            )}
          </div>
          <div className="min-w-0 space-y-3">
            <p className="font-mono text-[11px] uppercase tracking-[0.12em] text-subtle">Application request integrity</p>
            <Integrity v={v} />
            <p className="pt-2 font-mono text-[11px] uppercase tracking-[0.12em] text-subtle">Transport / workload identity</p>
            <p className="rounded-lg border border-dashed border-line p-3 text-[12.5px] leading-snug text-subtle">
              Not implemented in the backend yet: <span className="font-mono">agent_id</span> is self-asserted. mTLS 1.3, SPIFFE ID attestation and DPoP
              proof-of-possession are modeled in the simulation (Provenance → session → Identity).
            </p>
          </div>
        </motion.div>
      )}
    </Panel>
  );
}
