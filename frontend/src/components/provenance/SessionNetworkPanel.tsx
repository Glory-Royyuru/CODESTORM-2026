"use client";

import { ArrowRight, CheckCircle2, CircleDashed, Cpu, Fingerprint, IdCard, Network, XCircle } from "lucide-react";
import type { ReactNode } from "react";
import { cx, Hash, Panel, SectionTitle } from "@/components/ui/primitives";
import { EBPF_PROGRAM, EGRESS_PROXY } from "@/lib/gateway/network/ebpf";
import type { NetCheckStatus } from "@/lib/gateway/network/firewall";
import type { SessionState } from "@/lib/gateway/types";
import { useGateway } from "@/lib/store";

const STATUS: Record<NetCheckStatus, { text: string; cls: string; icon: typeof CheckCircle2 }> = {
  PASSED: { text: "CLEAR", cls: "border-emerald-400/40 bg-emerald-400/10 text-emerald-300", icon: CheckCircle2 },
  BLOCKED: { text: "BLOCKED", cls: "border-red-500/60 bg-red-500/15 text-red-300", icon: XCircle },
  NOT_EVALUATED: { text: "NOT EVALUATED", cls: "border-line bg-surface text-subtle", icon: CircleDashed },
};

function Row({ k, v }: { k: string; v: ReactNode }) {
  return (
    <div className="grid grid-cols-[92px_minmax(0,1fr)] gap-2 py-0.5">
      <dt className="font-mono text-[10.5px] uppercase tracking-[0.08em] text-subtle">{k}</dt>
      <dd className="min-w-0 break-all font-mono text-[11.5px] text-code">{v}</dd>
    </div>
  );
}

/** Simulated network boundary for one session: workload identity, destination firewall, HMAC integrity and eBPF egress. */
export default function SessionNetworkPanel({ s }: { s: SessionState }) {
  const gw = useGateway();
  const entries = gw.ledger.filter((e) => e.envelope.sessionId === s.id);
  const lastNet = [...entries].reverse().find((e) => e.sandbox?.network);
  const lastSigned = [...entries].reverse().find((e) => e.receipt.body.requestIntegrity);
  const net = lastNet?.sandbox?.network;
  const e = s.ebpf;
  const used = Math.min(100, (e.bytesOut / e.maxBytes) * 100);

  return (
    <Panel className="p-5">
      <SectionTitle right={<span className="rounded-md bg-accent/15 px-2 py-0.5 font-mono text-[10.5px] font-semibold text-accent">SIMULATED</span>}>
        <span className="flex items-center gap-2">
          <Network className="h-4 w-4" /> Network & egress boundary
        </span>
      </SectionTitle>

      <div className="grid gap-4 lg:grid-cols-2">
        {/* transport / workload identity */}
        <section className="rounded-xl border border-line bg-surface p-3.5">
          <p className="mb-2 flex items-center gap-2 text-[12.5px] font-semibold text-fg">
            <IdCard className="h-4 w-4 text-accent" /> Transport / workload identity
          </p>
          <dl>
            <Row k="SPIFFE ID" v={s.identity.spiffeId} />
            <Row k="mTLS" v={`${s.identity.mtls.version} · ${s.identity.mtls.cipher}`} />
            <Row k="X.509-SVID" v={<Hash value={s.identity.mtls.peerCertSha256} n={12} />} />
            <Row k="DPoP" v={`${s.identity.dpop.alg} · jkt ${s.identity.dpop.jkt.slice(0, 16)}… · bound to ${s.identity.dpop.boundTo}`} />
          </dl>
        </section>

        {/* application request integrity */}
        <section className="rounded-xl border border-line bg-surface p-3.5">
          <p className="mb-2 flex items-center gap-2 text-[12.5px] font-semibold text-fg">
            <Fingerprint className="h-4 w-4 text-accent" /> Application request integrity
          </p>
          {lastSigned?.receipt.body.requestIntegrity ? (
            <div className="space-y-1.5">
              <div className="flex flex-wrap items-center gap-2">
                <span
                  className={cx(
                    "rounded-md px-2 py-0.5 font-mono text-[11px] font-semibold ring-1",
                    lastSigned.sandbox?.integrityVerified ? "bg-emerald-400/10 text-emerald-300 ring-emerald-400/30" : "bg-red-500/15 text-red-300 ring-red-500/40",
                  )}
                >
                  HMAC-SHA256 · {lastSigned.sandbox?.integrityVerified ? "VERIFIED BY TOOL" : "REJECTED BY TOOL"}
                </span>
                <span className="font-mono text-[11px] text-subtle">{lastSigned.receipt.body.requestIntegrity.keyId}</span>
              </div>
              <p className="break-all font-mono text-[11.5px] text-code">{lastSigned.receipt.body.requestIntegrity.tag}</p>
              <p className="text-[11.5px] text-subtle">
                Over (decision, session, {lastSigned.envelope.tool}, args digest, manifest hash, pinned IP). A missing or altered tag makes the tool fail closed.
              </p>
            </div>
          ) : (
            <p className="text-[12.5px] text-subtle">No call in this session was approved for execution, so no HMAC tag was issued.</p>
          )}
        </section>
      </div>

      {/* destination firewall */}
      {net && (
        <section className="mt-4">
          <p className="mb-2 font-mono text-[11px] uppercase tracking-[0.12em] text-subtle">Destination firewall · last URL call ({lastNet!.envelope.tool})</p>
          <div className="mb-3 flex flex-wrap items-center gap-2 font-mono text-[12px]">
            <span className="rounded-lg border border-line bg-surface px-2.5 py-1 text-fg">{net.host ?? net.url}</span>
            <ArrowRight className="h-4 w-4 text-subtle" />
            <span className="text-subtle">DNS {net.resolvedIps.join(", ") || "—"}</span>
            <ArrowRight className="h-4 w-4 text-subtle" />
            <span className={cx("rounded-lg px-2.5 py-1", net.pinnedIp ? "bg-emerald-400/10 text-emerald-300" : "bg-red-500/15 text-red-300")}>
              {net.pinnedIp ? `pinned ${net.pinnedIp}` : net.decision}
            </span>
          </div>
          <ul className="grid grid-cols-[repeat(auto-fill,minmax(150px,1fr))] gap-1.5">
            {net.checks.map((c) => {
              const st = STATUS[c.status];
              return (
                <li key={c.check} title={c.detail} className={cx("flex items-center justify-between gap-2 rounded-lg border px-2.5 py-1.5", st.cls)}>
                  <span className="text-[11.5px] font-semibold">{c.label}</span>
                  <st.icon className="h-3.5 w-3.5 shrink-0" />
                </li>
              );
            })}
          </ul>
        </section>
      )}

      {/* eBPF egress */}
      <section className="mt-4">
        <p className="mb-2 flex flex-wrap items-center gap-2 font-mono text-[11px] uppercase tracking-[0.12em] text-subtle">
          <Cpu className="h-3.5 w-3.5" /> eBPF egress policy · ENFORCED
          <span className="normal-case tracking-normal">
            {EBPF_PROGRAM} · proxy {EGRESS_PROXY.ip}:{EGRESS_PROXY.port}
          </span>
        </p>
        <div className="mb-3 grid gap-3 font-mono text-[11.5px] text-muted sm:grid-cols-3">
          <div>
            <div className="mb-1 flex justify-between">
              <span>bytes {e.bytesOut}/{e.maxBytes}</span>
              <span>{used.toFixed(0)}%</span>
            </div>
            <div className="h-1.5 overflow-hidden rounded bg-surface">
              <div className={cx("h-full", used > 80 ? "bg-red-400" : "bg-accent/80")} style={{ width: `${used}%` }} />
            </div>
          </div>
          <span>EWMA {Math.round(e.ewmaBytes)} B/conn</span>
          <span className={e.drops ? "text-red-300" : undefined}>{e.drops} drop(s) · {e.sockets.length} socket(s)</span>
        </div>
        {e.sockets.length ? (
          <ul className="space-y-1">
            {e.sockets.map((k, i) => (
              <li key={i} className="grid grid-cols-[52px_minmax(0,1fr)] items-start gap-2 rounded-lg border border-line bg-black/20 px-2.5 py-1.5 font-mono text-[11.5px]">
                <span className={cx("rounded px-1.5 text-center font-semibold", k.action === "PASS" ? "bg-emerald-400/10 text-emerald-300" : "bg-red-500/15 text-red-300")}>{k.action}</span>
                <span className="min-w-0 break-words text-muted">
                  <span className="text-fg">{k.tool}</span> → {k.dst}:{k.port}
                  {k.upstream ? ` ⇒ ${k.upstream}` : ""} · {k.bytes} B · <span className={k.action === "DROP" ? "text-red-300" : "text-subtle"}>{k.reason}</span>
                </span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-[12.5px] text-subtle">No outbound sockets in this session.</p>
        )}
      </section>
    </Panel>
  );
}
