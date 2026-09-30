import { classifyIp, parseIp } from "./cidr";

/*
 * Simulated Cilium / eBPF egress enforcement inside the sandbox runner.
 * Models cgroup/connect4+connect6 hooks: every outbound socket a tool
 * container opens is checked in the kernel before the SYN leaves.
 *   - the only permitted destination is the egress proxy, and only for the
 *     IP the gateway pinned for this call (anything else bypasses the proxy);
 *   - per-session byte budget, with an EWMA of bytes per connection to
 *     catch slow-drip exfiltration that stays under per-call limits.
 */

export const EGRESS_PROXY = { ip: "10.96.0.10", port: 3128 };
export const EBPF_PROGRAM = "cilium bpf_sock: cgroup/connect4 · cgroup/connect6 · tc egress";

export interface SocketEvent {
  at: number;
  tool: string;
  /** Where the container tried to connect. */
  dst: string;
  port: number;
  /** Upstream the proxy was asked to reach (proxy connections only). */
  upstream?: string;
  bytes: number;
  action: "PASS" | "DROP";
  reason: string;
}

export interface EbpfSessionState {
  sockets: SocketEvent[];
  bytesOut: number;
  maxBytes: number;
  /** EWMA of bytes per permitted connection. */
  ewmaBytes: number;
  drops: number;
}

export const newEbpfState = (maxBytes: number): EbpfSessionState => ({ sockets: [], bytesOut: 0, maxBytes, ewmaBytes: 0, drops: 0 });

export interface ConnectAttempt {
  tool: string;
  dst: string;
  port: number;
  upstream?: string;
  bytes: number;
  /** The IP the gateway pinned for this call; undefined if the call has no approved destination. */
  pinnedIp?: string;
}

const EWMA_ALPHA = 0.3;
/** EWMA above this share of the budget per connection = slow drip. */
const SLOW_DRIP_SHARE = 0.2;

/** Decide one connect() in "kernel" and record it on the session. */
export function enforceConnect(state: EbpfSessionState, a: ConnectAttempt, now: number): SocketEvent {
  const drop = (reason: string): SocketEvent => ({ at: now, tool: a.tool, dst: a.dst, port: a.port, upstream: a.upstream, bytes: a.bytes, action: "DROP", reason });
  let ev: SocketEvent;
  const ip = parseIp(a.dst);
  const denied = ip ? classifyIp(ip) : null;
  if (a.dst !== EGRESS_PROXY.ip || a.port !== EGRESS_PROXY.port) {
    ev = drop(`proxy bypass: direct connect to ${a.dst}:${a.port}${denied ? ` (${denied.check} ${denied.cidr})` : ""}`);
  } else if (!a.pinnedIp || a.upstream !== a.pinnedIp) {
    ev = drop(`proxy upstream ${a.upstream ?? "?"} ≠ pinned ${a.pinnedIp ?? "none"} (re-resolution / rebinding)`);
  } else if (state.bytesOut + a.bytes > state.maxBytes) {
    ev = drop(`session byte budget exhausted (${state.bytesOut + a.bytes}/${state.maxBytes} B)`);
  } else {
    const ewma = EWMA_ALPHA * a.bytes + (1 - EWMA_ALPHA) * state.ewmaBytes;
    const permitted = state.sockets.filter((s) => s.action === "PASS").length;
    if (permitted >= 3 && ewma > state.maxBytes * SLOW_DRIP_SHARE) {
      ev = drop(`slow-drip: EWMA ${Math.round(ewma)} B/conn over ${permitted + 1} connections`);
    } else {
      state.ewmaBytes = ewma;
      state.bytesOut += a.bytes;
      ev = { at: now, tool: a.tool, dst: a.dst, port: a.port, upstream: a.upstream, bytes: a.bytes, action: "PASS", reason: `via proxy → pinned ${a.pinnedIp}` };
    }
  }
  if (ev.action === "DROP") state.drops++;
  state.sockets.push(ev);
  return ev;
}
