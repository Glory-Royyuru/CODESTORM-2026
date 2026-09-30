"use client";

import { motion } from "framer-motion";
import { Database, FileText, Globe2, MessageSquareText, Radio, ShieldAlert, Wrench, type LucideIcon } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { cx, Drawer, JsonBlock, PageHeader, Panel, SectionTitle, TaintBadge, timeAgo, VerdictBadge } from "@/components/ui/primitives";
import { TAINT_HEX } from "@/components/ui/tokens";
import { TAINT_ORDER } from "@/lib/gateway/taint";
import type { GraphNode, SessionState } from "@/lib/gateway/types";
import { maxVerdict } from "@/lib/gateway/util";
import { useGateway } from "@/lib/store";
import SessionNetworkPanel from "./SessionNetworkPanel";

const COL_W = 240;
const NODE_W = 188;
const NODE_H = 66;
const ROW_Y = { external: 24, tool: 150, prompt: 150, data: 276 } as const;
const KIND_ICON: Record<GraphNode["kind"], LucideIcon> = { prompt: MessageSquareText, tool: Wrench, data: Database, external: Globe2 };

function layout(s: SessionState) {
  const pos = new Map<string, { x: number; y: number }>();
  for (const n of s.nodes) pos.set(n.id, { x: 24 + n.step * COL_W, y: ROW_Y[n.kind] });
  const width = 24 + (s.step + 1) * COL_W;
  return { pos, width, height: ROW_Y.data + NODE_H + 24 };
}

function edgePath(a: { x: number; y: number }, b: { x: number; y: number }) {
  if (Math.abs(a.x - b.x) < 4) {
    // same column: vertical link
    const down = b.y > a.y;
    const x = a.x + NODE_W / 2;
    const y1 = down ? a.y + NODE_H : a.y;
    const y2 = down ? b.y : b.y + NODE_H;
    return `M ${x} ${y1} L ${x} ${y2}`;
  }
  const x1 = a.x + NODE_W;
  const y1 = a.y + NODE_H / 2;
  const x2 = b.x;
  const y2 = b.y + NODE_H / 2;
  const dx = Math.max(40, (x2 - x1) / 2);
  return `M ${x1} ${y1} C ${x1 + dx} ${y1}, ${x2 - dx} ${y2}, ${x2} ${y2}`;
}

function TrifectaPanel({ s }: { s: SessionState }) {
  const flags = [
    { key: "privateData", label: "Private data acquired", icon: Database, on: s.flags.privateData },
    { key: "untrustedContent", label: "Untrusted content ingested", icon: FileText, on: s.flags.untrustedContent },
    { key: "outboundChannel", label: "Outbound channel available", icon: Radio, on: s.flags.outboundChannel },
  ];
  const count = flags.filter((f) => f.on).length;
  const armed = count === 3;
  return (
    <Panel className={cx("p-5", armed && "ring-1 ring-red-500/40")}>
      <SectionTitle
        right={
          <span className={cx("flex items-center gap-2 font-mono text-[12px] font-semibold", armed ? "text-red-400" : count === 2 ? "text-amber-400" : "text-emerald-400")}>
            {armed && <ShieldAlert className="h-4 w-4" />}
            {armed ? "LETHAL TRIFECTA — egress hard-vetoed" : `${count}/3 conditions`}
          </span>
        }
      >
        Lethal trifecta monitor (M5)
      </SectionTitle>
      <div className="grid gap-3 sm:grid-cols-3">
        {flags.map((f) => (
          <div key={f.key} className={cx("flex items-center gap-3 rounded-xl border p-3 transition-colors", f.on ? "border-red-500/40 bg-red-500/10" : "border-line bg-surface")}>
            <f.icon className={cx("h-5 w-5", f.on ? "text-red-400" : "text-subtle")} />
            <div>
              <p className="text-[13px] font-semibold text-fg">{f.label}</p>
              <p className={cx("font-mono text-[11px]", f.on ? "text-red-300" : "text-subtle")}>{f.on ? "ACTIVE" : "clear"}</p>
            </div>
          </div>
        ))}
      </div>
      <div className="mt-4 grid gap-3 font-mono text-[12px] text-muted sm:grid-cols-3">
        <span>
          egress rows {s.egress.rowsOut}/{s.egress.maxRows}
        </span>
        <span>
          egress bytes {s.egress.bytesOut}/{s.egress.maxBytes}
        </span>
        <span>
          EWMA slow-drip {s.egress.ewmaBytes.toFixed(2)} · CUSUM {s.cusum.toFixed(2)}
        </span>
      </div>
    </Panel>
  );
}

export default function ProvenanceView() {
  const gw = useGateway();
  const sessions = [...gw.sessions.values()].filter((x) => x.step > 0).sort((a, b) => b.startedAt - a.startedAt);
  const [selectedId, setSelectedId] = useState<string | null>(() => sessions.find((s) => s.scenario === "A")?.id ?? sessions[0]?.id ?? null);
  const [nodeId, setNodeId] = useState<string | null>(null);
  const s = sessions.find((x) => x.id === selectedId) ?? sessions[0];

  if (!s) return <PageHeader eyebrow="Session investigator" title="No sessions yet" />;
  const { pos, width, height } = layout(s);
  const node = s.nodes.find((n) => n.id === nodeId);
  const atomsById = new Map(s.atoms.map((a) => [a.id, a]));

  return (
    <div>
      <PageHeader
        eyebrow="M4 · M5 — Session investigator"
        title={
          <>
            Provenance <span className="text-accent">DAG</span>
          </>
        }
        description="Every tool call, retrieved document and external target in a session, with edges colored by the taint lattice. Value-level atom matching links data back to the call that produced it."
      />

      <div className="grid gap-5 xl:grid-cols-[320px_minmax(0,1fr)]">
        <Panel className="scrollbar-thin max-h-[780px] overflow-y-auto p-3">
          <p className="px-2 pb-2 pt-1 text-[12px] font-semibold uppercase tracking-[0.1em] text-subtle">Sessions · {sessions.length}</p>
          <ul className="space-y-1">
            {sessions.map((x) => {
              const worst = maxVerdict(...x.nodes.filter((n) => n.verdict).map((n) => n.verdict!));
              const flags = [x.flags.privateData, x.flags.untrustedContent, x.flags.outboundChannel];
              return (
                <li key={x.id}>
                  <button
                    type="button"
                    onClick={() => setSelectedId(x.id)}
                    className={cx("w-full rounded-xl px-3 py-2.5 text-left transition-colors", x.id === s.id ? "bg-surface-hover ring-1 ring-line" : "hover:bg-surface")}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="truncate text-[13.5px] font-semibold text-fg">{x.title}</span>
                      <VerdictBadge verdict={worst} />
                    </div>
                    <div className="mt-1 flex items-center justify-between gap-2">
                      <span className="truncate font-mono text-[11px] text-subtle">
                        {x.principal.agentId.replace("agent:", "")} · {timeAgo(x.startedAt)}
                      </span>
                      <span className="flex gap-1" title="private · untrusted · outbound">
                        {flags.map((on, i) => (
                          <span key={i} className={cx("h-1.5 w-1.5 rounded-full", on ? "bg-red-400" : "bg-fg/15")} />
                        ))}
                      </span>
                    </div>
                  </button>
                </li>
              );
            })}
          </ul>
        </Panel>

        <div className="min-w-0 space-y-5">
          <TrifectaPanel s={s} />

          <SessionNetworkPanel s={s} />

          <Panel className="p-5">
            <SectionTitle
              right={
                <span className="hidden flex-wrap items-center gap-1.5 md:flex">
                  {TAINT_ORDER.map((t) => (
                    <TaintBadge key={t} label={t} />
                  ))}
                </span>
              }
            >
              {s.principal.agentId} · “{s.goal}”
            </SectionTitle>

            <div className="scrollbar-thin overflow-x-auto pb-2">
              <div className="relative" style={{ width, height }}>
                <svg className="absolute inset-0" width={width} height={height} aria-hidden="true">
                  <defs>
                    {TAINT_ORDER.map((t) => (
                      <marker key={t} id={`arrow-${t}`} viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
                        <path d="M 0 0 L 10 5 L 0 10 z" fill={TAINT_HEX[t]} />
                      </marker>
                    ))}
                  </defs>
                  {s.edges.map((e, i) => {
                    const a = pos.get(e.from);
                    const b = pos.get(e.to);
                    if (!a || !b) return null;
                    const d = edgePath(a, b);
                    return (
                      <g key={`${s.id}-${i}`}>
                        <path d={d} fill="none" stroke={TAINT_HEX[e.taint]} strokeOpacity={0.18} strokeWidth={8} />
                        <motion.path
                          d={d}
                          fill="none"
                          stroke={TAINT_HEX[e.taint]}
                          strokeWidth={1.8}
                          strokeDasharray={e.label === "vetoed" ? "6 5" : undefined}
                          markerEnd={`url(#arrow-${e.taint})`}
                          initial={{ pathLength: 0, opacity: 0 }}
                          animate={{ pathLength: 1, opacity: 1 }}
                          transition={{ duration: 0.7, delay: 0.08 * i }}
                        />
                      </g>
                    );
                  })}
                </svg>

                {s.nodes.map((n, i) => {
                  const p = pos.get(n.id)!;
                  const Icon = KIND_ICON[n.kind];
                  return (
                    <motion.button
                      key={n.id}
                      type="button"
                      onClick={() => setNodeId(n.id)}
                      initial={{ opacity: 0, scale: 0.9 }}
                      animate={{ opacity: 1, scale: 1 }}
                      transition={{ delay: 0.05 * i }}
                      className="absolute flex items-center gap-2.5 rounded-xl border bg-panel-strong px-3 text-left backdrop-blur-md transition-transform hover:-translate-y-0.5"
                      style={{ left: p.x, top: p.y, width: NODE_W, height: NODE_H, borderColor: `${TAINT_HEX[n.taint]}66`, boxShadow: `0 0 24px -12px ${TAINT_HEX[n.taint]}` }}
                    >
                      <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg" style={{ background: `${TAINT_HEX[n.taint]}1f`, color: TAINT_HEX[n.taint] }}>
                        <Icon className="h-4 w-4" />
                      </span>
                      <span className="min-w-0">
                        <span className="block truncate font-mono text-[12.5px] font-semibold text-fg">{n.label}</span>
                        <span className="block truncate text-[11px] text-subtle">{n.sublabel}</span>
                      </span>
                      {n.verdict && n.verdict !== "ALLOW" && (
                        <span className="absolute -right-1.5 -top-2">
                          <VerdictBadge verdict={n.verdict} />
                        </span>
                      )}
                    </motion.button>
                  );
                })}
              </div>
            </div>
            <p className="mt-3 text-[12px] text-subtle">Rows: external targets (top) · tool calls (middle) · returned data (bottom). Dashed edges were vetoed before egress. Click any node for its atoms and taint history.</p>
          </Panel>
        </div>
      </div>

      <Drawer
        open={!!node}
        onClose={() => setNodeId(null)}
        title={
          node && (
            <span className="flex items-center gap-2">
              <span className="font-mono">{node.label}</span>
              <TaintBadge label={node.taint} />
            </span>
          )
        }
      >
        {node && (
          <div className="space-y-6">
            <div className="flex flex-wrap items-center gap-2 text-[13px] text-muted">
              <span className="rounded-md bg-surface px-2 py-0.5 font-mono text-[11px] uppercase">{node.kind}</span>
              step {node.step}
              {node.verdict && <VerdictBadge verdict={node.verdict} />}
              {node.receiptId && (
                <Link href={`/audit?receipt=${node.receiptId}`} className="ml-auto font-semibold text-accent hover:underline">
                  Receipt →
                </Link>
              )}
            </div>
            {node.payload && (
              <section>
                <SectionTitle>{node.kind === "tool" ? "Payload parameters" : "Content"}</SectionTitle>
                <JsonBlock value={node.payload} className="max-h-64" />
              </section>
            )}
            <section>
              <SectionTitle>Data atoms · {node.atoms.length}</SectionTitle>
              {node.atoms.length ? (
                <ul className="space-y-1.5">
                  {node.atoms.map((id) => {
                    const a = atomsById.get(id);
                    if (!a) return null;
                    return (
                      <li key={id} className="flex items-center gap-2 rounded-lg border border-line bg-surface px-3 py-2">
                        <TaintBadge label={a.label} />
                        <span className="rounded bg-fg/5 px-1.5 font-mono text-[10.5px] text-subtle">{a.kind}</span>
                        <span className="min-w-0 flex-1 truncate font-mono text-[12px] text-code" title={a.value}>
                          {a.value}
                        </span>
                        <span className="font-mono text-[10.5px] text-subtle">{a.sourceTool}</span>
                      </li>
                    );
                  })}
                </ul>
              ) : (
                <p className="text-[13px] text-subtle">No tracked atoms {node.kind === "tool" ? "flowed into this call's arguments." : "on this node."}</p>
              )}
            </section>
            <section>
              <SectionTitle>Taint history</SectionTitle>
              <ul className="space-y-1.5 font-mono text-[12px]">
                {s.edges
                  .filter((e) => e.from === node.id || e.to === node.id)
                  .map((e, i) => {
                    const other = s.nodes.find((n) => n.id === (e.from === node.id ? e.to : e.from));
                    return (
                      <li key={i} className="flex items-center gap-2">
                        <span className="text-subtle">{e.from === node.id ? "→ out" : "← in"}</span>
                        <TaintBadge label={e.taint} />
                        <span className="text-code">{other?.label}</span>
                        <span className="text-subtle">({e.label})</span>
                      </li>
                    );
                  })}
              </ul>
            </section>
          </div>
        )}
      </Drawer>
    </div>
  );
}
