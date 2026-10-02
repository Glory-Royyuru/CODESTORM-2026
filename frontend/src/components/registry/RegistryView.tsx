"use client";

import { AnimatePresence, motion } from "framer-motion";
import { AlertTriangle, Bomb, Fingerprint, PackagePlus, RotateCcw, Server, ShieldCheck } from "lucide-react";
import { useMemo, useState } from "react";
import { Button, cx, DemoTag, Drawer, Hash, PageHeader, Panel, SectionTitle, Stat, StatusBadge, timeAgo } from "@/components/ui/primitives";
import { TIER_LABEL } from "@/components/ui/tokens";
import { manifestHash, scanManifest } from "@/lib/gateway/registry";
import type { Capability, RegisteredTool, RiskTier, ToolManifest } from "@/lib/gateway/types";
import { getGateway, useGateway, useUi } from "@/lib/store";

const TIER_CLS: Record<RiskTier, string> = {
  1: "text-emerald-300 bg-emerald-400/10",
  2: "text-sky-300 bg-sky-400/10",
  3: "text-amber-300 bg-amber-400/10",
  4: "text-red-300 bg-red-500/10",
};

function ToolCard({ tool }: { tool: RegisteredTool }) {
  const toast = useUi((s) => s.toast);
  const gw = getGateway();
  const name = tool.manifest.name;
  const drift = tool.currentHash !== tool.pinnedHash;
  const added = Object.keys(tool.manifest.parameters).filter((k) => !(k in tool.pinnedManifest.parameters));

  return (
    <motion.div layout initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} className={cx("panel flex min-w-0 flex-col p-5", tool.status === "QUARANTINED" && "ring-1 ring-fuchsia-500/40", tool.status === "POISONED" && "ring-1 ring-red-500/40")}>
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <h3 className="truncate font-mono text-[15px] font-semibold text-fg">{name}</h3>
          <p className="mt-0.5 flex items-center gap-1.5 truncate font-mono text-[11.5px] text-subtle">
            <Server className="h-3 w-3" />
            {tool.manifest.server.id}
          </p>
        </div>
        <StatusBadge status={tool.status} />
      </div>

      <p className="mt-3 line-clamp-3 text-[13px] leading-snug text-muted">{tool.manifest.description}</p>

      <div className="mt-4 flex flex-wrap gap-1.5">
        <span className={cx("rounded-md px-2 py-0.5 font-mono text-[11px] font-semibold", TIER_CLS[tool.tier])}>{TIER_LABEL[tool.tier]}</span>
        <span className="rounded-md bg-surface px-2 py-0.5 font-mono text-[11px] text-muted">{tool.capability}</span>
        {tool.egress && <span className="rounded-md bg-orange-500/10 px-2 py-0.5 font-mono text-[11px] text-orange-300">egress</span>}
        {tool.untrustedSource && <span className="rounded-md bg-pink-500/10 px-2 py-0.5 font-mono text-[11px] text-pink-300">untrusted src</span>}
      </div>

      <dl className="mt-4 space-y-1.5 rounded-xl border border-line bg-black/20 p-3 font-mono text-[11.5px]">
        <div className="flex items-center justify-between gap-2">
          <dt className="text-subtle">pinned sha256</dt>
          <dd><Hash value={tool.pinnedHash} n={10} /></dd>
        </div>
        <div className="flex items-center justify-between gap-2">
          <dt className="text-subtle">advertised</dt>
          <dd><Hash value={tool.currentHash} n={10} className={drift ? "text-red-400" : "text-emerald-400"} /></dd>
        </div>
        <div className="flex items-center justify-between gap-2">
          <dt className="text-subtle">last audit · calls</dt>
          <dd className="text-code">{timeAgo(tool.lastAudit)} · {tool.calls}</dd>
        </div>
      </dl>

      <AnimatePresence>
        {tool.findings.length > 0 && (
          <motion.ul initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: "auto" }} exit={{ opacity: 0, height: 0 }} className="mt-3 space-y-1 overflow-hidden">
            {tool.findings.map((f, i) => (
              <li key={i} className="flex items-start gap-2 text-[12px] text-red-300">
                <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                <span>
                  <span className="font-mono font-semibold">{f.kind}</span> — {f.detail}
                </span>
              </li>
            ))}
            {drift && added.length > 0 && <li className="font-mono text-[11.5px] text-fuchsia-300">+ params: {added.join(", ")}</li>}
          </motion.ul>
        )}
      </AnimatePresence>

      <div className="mt-auto flex flex-wrap gap-2 pt-4">
        {tool.status === "VERIFIED" && (
          <Button
            variant="danger"
            className="h-9 flex-1 text-[13px]"
            onClick={() => {
              gw.simulateRugPull(name);
              toast({ tone: "danger", title: `Integrity alert: ${name} quarantined`, detail: "Manifest hash drifted from pinned SHA-256 — schema expanded + hidden instructions" });
            }}
          >
            <Bomb className="h-4 w-4" /> Simulate Tool Rug-pull
          </Button>
        )}
        {tool.status === "QUARANTINED" && (
          <>
            <Button
              className="h-9 flex-1 text-[13px]"
              onClick={() => {
                gw.restore(name);
                toast({ tone: "success", title: `${name} restored to pinned manifest` });
              }}
            >
              <RotateCcw className="h-4 w-4" /> Restore pinned
            </Button>
            <Button
              variant="ghost"
              className="h-9 text-[13px]"
              onClick={() => {
                const r = gw.repin(name);
                toast({ tone: r.ok ? "success" : "danger", title: r.ok ? `${name} re-pinned` : "Re-pin refused", detail: r.reason });
              }}
            >
              <Fingerprint className="h-4 w-4" /> Re-pin
            </Button>
          </>
        )}
        {tool.status === "POISONED" && (
          <p className="text-[12px] text-subtle">Calls to this tool are hard-blocked (tool_integrity) until the publisher ships a clean manifest.</p>
        )}
      </div>
    </motion.div>
  );
}

const CAPS: Capability[] = ["db:read", "db:admin", "net:fetch", "email:send", "chat:post", "secrets:read", "fs:read", "orders:read", "payments:transfer", "calendar:read", "weather:read", "docs:read"];

function RegisterDrawer({ open, onClose }: { open: boolean; onClose: () => void }) {
  const toast = useUi((s) => s.toast);
  const [name, setName] = useState("jira_search");
  const [server, setServer] = useState("mcp://atlassian.tools.acme.dev");
  const [description, setDescription] = useState("Search Jira issues visible to the current user using JQL.");
  const [params, setParams] = useState('{\n  "jql": { "type": "string", "description": "JQL query" },\n  "max_results": { "type": "number" }\n}');
  const [tier, setTier] = useState<RiskTier>(1);
  const [capability, setCapability] = useState<Capability>("docs:read");
  const [egress, setEgress] = useState(false);
  const [untrusted, setUntrusted] = useState(true);

  const preview = useMemo(() => {
    let parsed: ToolManifest["parameters"] | null = null;
    let error = "";
    try {
      parsed = JSON.parse(params);
    } catch (e) {
      error = (e as Error).message;
    }
    if (!/^[a-z][a-z0-9_]{2,40}$/.test(name)) error = "name must be snake_case (3-41 chars)";
    if (!parsed) return { error: error || "invalid parameters JSON" };
    const manifest: ToolManifest = { name, description, parameters: parsed, required: Object.keys(parsed).slice(0, 1), server: { id: server, url: server.replace("mcp://", "https://"), transport: "sse" }, version: "1.0.0" };
    return { error, manifest, hash: manifestHash(manifest), findings: scanManifest(manifest, 0) };
  }, [name, server, description, params]);

  const submit = () => {
    if (!preview.manifest || preview.error) return;
    const gw = getGateway();
    if (gw.registry.has(name)) {
      toast({ tone: "warn", title: `${name} already registered` });
      return;
    }
    const t = gw.registerTool({ manifest: preview.manifest, tier, capability, egress, sensitiveSource: false, untrustedSource: untrusted });
    toast({ tone: t.status === "VERIFIED" ? "success" : "danger", title: `${name} registered · ${t.status}`, detail: `pinned sha256:${t.pinnedHash.slice(0, 16)}…` });
    onClose();
  };

  const field = "w-full rounded-xl border border-line bg-black/20 px-3 py-2.5 text-[14px] text-fg outline-none focus:ring-2 focus:ring-accent/50";
  return (
    <Drawer
      open={open}
      onClose={onClose}
      title={
        <span className="flex items-center gap-2">
          Register MCP tool <DemoTag />
        </span>
      }
    >
      <div className="space-y-4">
        <label className="block">
          <span className="mb-1.5 block text-[12.5px] font-semibold text-muted">Tool name</span>
          <input className={cx(field, "font-mono")} value={name} onChange={(e) => setName(e.target.value)} />
        </label>
        <label className="block">
          <span className="mb-1.5 block text-[12.5px] font-semibold text-muted">Server identity</span>
          <input className={cx(field, "font-mono")} value={server} onChange={(e) => setServer(e.target.value)} />
        </label>
        <label className="block">
          <span className="mb-1.5 block text-[12.5px] font-semibold text-muted">Description (scanned for poisoning)</span>
          <textarea className={cx(field, "min-h-[84px]")} value={description} onChange={(e) => setDescription(e.target.value)} />
        </label>
        <label className="block">
          <span className="mb-1.5 block text-[12.5px] font-semibold text-muted">Parameters (JSON schema properties)</span>
          <textarea className={cx(field, "min-h-[120px] font-mono text-[12.5px]")} spellCheck={false} value={params} onChange={(e) => setParams(e.target.value)} />
        </label>
        <div className="grid grid-cols-2 gap-3">
          <label className="block">
            <span className="mb-1.5 block text-[12.5px] font-semibold text-muted">Risk tier</span>
            <select className={field} value={tier} onChange={(e) => setTier(Number(e.target.value) as RiskTier)}>
              {[1, 2, 3, 4].map((t) => (
                <option key={t} value={t}>
                  {TIER_LABEL[t]}
                </option>
              ))}
            </select>
          </label>
          <label className="block">
            <span className="mb-1.5 block text-[12.5px] font-semibold text-muted">Capability scope</span>
            <select className={cx(field, "font-mono")} value={capability} onChange={(e) => setCapability(e.target.value as Capability)}>
              {CAPS.map((c) => (
                <option key={c}>{c}</option>
              ))}
            </select>
          </label>
        </div>
        <div className="flex flex-wrap gap-5 text-[13.5px] text-muted">
          <label className="flex items-center gap-2">
            <input type="checkbox" checked={egress} onChange={(e) => setEgress(e.target.checked)} className="accent-orange-500" /> Egress-capable
          </label>
          <label className="flex items-center gap-2">
            <input type="checkbox" checked={untrusted} onChange={(e) => setUntrusted(e.target.checked)} className="accent-orange-500" /> Returns untrusted content
          </label>
        </div>

        <div className="rounded-xl border border-line bg-black/25 p-4">
          <SectionTitle>Manifest hashing & scan</SectionTitle>
          {preview.error ? (
            <p className="font-mono text-[12px] text-red-400">{preview.error}</p>
          ) : (
            <>
              <p className="break-all font-mono text-[12px] text-code">sha256:{preview.hash}</p>
              {preview.findings?.length ? (
                <ul className="mt-2 space-y-1">
                  {preview.findings.map((f, i) => (
                    <li key={i} className="font-mono text-[12px] text-red-300">
                      ⚠ {f.kind}: {f.detail}
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="mt-2 flex items-center gap-1.5 text-[12.5px] text-emerald-400">
                  <ShieldCheck className="h-4 w-4" /> No poisoning patterns detected
                </p>
              )}
            </>
          )}
        </div>
        <Button variant="primary" className="w-full" onClick={submit} disabled={!!preview.error}>
          <PackagePlus className="h-4 w-4" /> Register & pin manifest
        </Button>
      </div>
    </Drawer>
  );
}

export default function RegistryView() {
  const gw = useGateway();
  const [open, setOpen] = useState(false);
  const tools = [...gw.registry.values()];
  const count = (s: RegisteredTool["status"]) => tools.filter((t) => t.status === s).length;

  return (
    <div>
      <PageHeader
        eyebrow="M2 — Tool registry & integrity engine · demo engine"
        title={
          <>
            Tool registry, <span className="text-accent">hash-pinned</span>
          </>
        }
        description="A demo registry run by the in-browser engine: each tool's name, description, parameter schema and server identity is hashed with SHA-256 and pinned at registration, and drift at call time quarantines the tool. The SATG backend keeps its own registry, which pins manifest hashes and refuses a drifted manifest (TOOL-004); the poisoning scanner, quarantine, re-pin and registration shown here are demo only."
        actions={
          <Button variant="primary" onClick={() => setOpen(true)}>
            <PackagePlus className="h-4 w-4" /> Register tool
          </Button>
        }
      />
      <div className="mb-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Stat label="Registered tools" value={tools.length} />
        <Stat label="Verified" value={count("VERIFIED")} tone="text-emerald-400" />
        <Stat label="Poisoned" value={count("POISONED")} tone="text-red-400" />
        <Stat label="Quarantined" value={count("QUARANTINED")} tone="text-fuchsia-400" />
      </div>
      <Panel className="mb-6 flex flex-wrap items-center gap-x-6 gap-y-2 px-5 py-3 font-mono text-[12px] text-muted">
        <span className="text-subtle">pin =</span> sha256(canonical_json(&#123;name, description, parameters, required, server&#125;))
      </Panel>
      <SectionTitle right={<DemoTag />}>Demo registry · {tools.length} tools</SectionTitle>
      <motion.div layout className="grid gap-5 md:grid-cols-2 2xl:grid-cols-3">
        {tools.map((t) => (
          <ToolCard key={t.manifest.name} tool={t} />
        ))}
      </motion.div>
      <RegisterDrawer open={open} onClose={() => setOpen(false)} />
    </div>
  );
}
