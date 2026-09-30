import { EGRESS_PROXY, enforceConnect, type EbpfSessionState, type SocketEvent } from "./network/ebpf";
import type { NetworkInspection } from "./network/firewall";
import type { CanonicalRequest, RequestIntegrityTag } from "./network/identity";
import type { SimulatedDns } from "./network/resolver";
import type { RegisteredTool, SandboxResult, ToolCallEnvelope } from "./types";
import { hashSeed, mulberry32, shortId } from "./util";

/* M8 — Sandboxed execution harness (simulated container runtime) */

export interface SandboxContext {
  /** Gateway-side destination check for the call's URL; the proxy only ever connects to its pinned IP. */
  network?: NetworkInspection;
  integrity: { request: CanonicalRequest; tag?: RequestIntegrityTag; verify: (req: CanonicalRequest, tag?: RequestIntegrityTag) => boolean };
  ebpf: EbpfSessionState;
  dns: SimulatedDns;
  /** Scripted misbehaviour: the tool opens its own socket. */
  socket?: "direct" | "rebind";
  now: number;
}

/** Default outputs per tool when a scenario doesn't script one. */
function defaultOutput(env: ToolCallEnvelope): string {
  const a = env.arguments;
  switch (env.tool) {
    case "get_order":
      return JSON.stringify({ order_id: a.order_id, status: "shipped", total: 184.2, items: 3, customer: `${env.principal.userId}@acme.com` });
    case "execute_sql":
      return JSON.stringify({ rows: [{ region: "EMEA", revenue: 1204331 }, { region: "NA", revenue: 2210945 }], row_count: 2 });
    case "calendar_read":
      return JSON.stringify([{ title: "Quarterly planning", at: "2026-10-02T15:00Z" }, { title: "1:1 with Priya", at: "2026-10-03T10:30Z" }]);
    case "weather_lookup":
      return JSON.stringify({ city: a.city, forecast: "Partly cloudy", high_c: 21, low_c: 12 });
    case "file_system":
      return `# ${String(a.path)}\n\nProject notes: migrate billing workers to the new queue by Q4.`;
    case "fetch_webpage":
      return `<article>${String(a.url)} — Release notes: performance improvements and bug fixes.</article>`;
    case "send_email":
      return JSON.stringify({ status: "queued", message_id: shortId("msg") });
    case "slack_post":
      return JSON.stringify({ ok: true, ts: "1727712000.000200" });
    case "aws_secrets_manager":
      return JSON.stringify({ secret_id: a.secret_id, value: "db-password-rotated-2026" });
    case "db_admin":
      return JSON.stringify({ status: "ok", statement: a.statement, affected: 0 });
    case "transfer_funds":
      return JSON.stringify({ status: "submitted", reference: shortId("wire") });
    default:
      return JSON.stringify({ ok: true });
  }
}

export function executeInSandbox(env: ToolCallEnvelope, tool: RegisteredTool, scriptedOutput: string | undefined, ctx: SandboxContext): SandboxResult {
  const r = mulberry32(hashSeed(env.id));
  const net = ctx.network;
  const sockets: SocketEvent[] = [];
  let refusal: string | undefined;

  // Application request integrity: the tool side recomputes the HMAC and fails closed.
  const integrityVerified = ctx.integrity.verify(ctx.integrity.request, ctx.integrity.tag);
  if (!integrityVerified) refusal = "request-integrity HMAC missing or invalid — tool refused (fail closed)";
  else if (net?.decision === "HARD_DENY") refusal = `egress firewall: ${net.reason}`;

  const networked = tool.egress || tool.capability === "net:fetch";
  if (!refusal && networked) {
    const bytes = new TextEncoder().encode(JSON.stringify(env.arguments)).length;
    // URL tools go to the pinned IP; other egress tools to their registered endpoint.
    const upstream = net?.pinnedIp ?? `registered:${tool.manifest.server.id}`;
    sockets.push(enforceConnect(ctx.ebpf, { tool: env.tool, dst: EGRESS_PROXY.ip, port: EGRESS_PROXY.port, upstream, pinnedIp: upstream, bytes }, ctx.now));
    if (ctx.socket === "direct") {
      sockets.push(enforceConnect(ctx.ebpf, { tool: env.tool, dst: "169.254.169.254", port: 80, bytes: 180, pinnedIp: upstream }, ctx.now));
    } else if (ctx.socket === "rebind" && net?.host) {
      // A naive HTTP client re-resolves the name at connect time and dials the answer directly.
      const again = ctx.dns.resolve(net.host).ips[0];
      sockets.push(enforceConnect(ctx.ebpf, { tool: env.tool, dst: again, port: 443, bytes, pinnedIp: upstream }, ctx.now));
    }
    const dropped = sockets.find((s) => s.action === "DROP");
    if (dropped) refusal = `eBPF egress enforcement: ${dropped.reason} — runner terminated the tool`;
  }

  return {
    executed: !refusal,
    runtime: "rootless docker + gVisor",
    container: {
      image: `satg/tool-${tool.manifest.name.replace(/_/g, "-")}@sha256:${tool.pinnedHash.slice(0, 16)}`,
      runtime: "runsc (gVisor)",
      rootless: true,
      user: "65532:65532 (nonroot)",
      readOnlyRootFs: true,
      cpu: tool.tier >= 3 ? "0.5 vCPU" : "0.25 vCPU",
      memory: tool.tier >= 3 ? "256Mi" : "128Mi",
      network: networked ? `egress only via proxy ${EGRESS_PROXY.ip}:${EGRESS_PROXY.port} (eBPF-enforced)` : "none",
    },
    vaultLease: tool.needsSecret && !refusal ? { path: tool.needsSecret, leaseId: `${tool.needsSecret}/${shortId("lease")}`, ttlSeconds: 60 } : undefined,
    egressProxy: net?.host ? { host: net.host, pinnedIp: net.pinnedIp ?? "0.0.0.0 (refused)", blocked: net.decision === "HARD_DENY" } : undefined,
    network: net,
    sockets,
    integrityVerified,
    refusal,
    output: refusal ? "" : (scriptedOutput ?? defaultOutput(env)),
    execMs: Math.round((12 + r() * 60) * 10) / 10,
  };
}
