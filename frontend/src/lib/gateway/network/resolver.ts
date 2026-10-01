import { hashSeed, mulberry32 } from "../util";

/* Simulated DNS. Deterministic so seeded sessions are reproducible. */

/** Fixed answers for names the demo refers to. */
const STATIC: Record<string, string[]> = {
  localhost: ["127.0.0.1", "::1"],
  "metadata.google.internal": ["169.254.169.254"],
};

/**
 * Rebinding names: every lookup returns the next answer, with TTL 0. The
 * first answer is public (passes the gateway's check), later ones point at
 * the metadata service — exactly what a client that re-resolves at connect
 * time would receive.
 */
const REBINDING: Record<string, string[][]> = {
  "assets.partner-portal.com": [["93.184.216.34"], ["169.254.169.254"]],
};

function publicAddress(host: string) {
  const r = mulberry32(hashSeed(host));
  return `${Math.floor(r() * 150) + 23}.${Math.floor(r() * 250)}.${Math.floor(r() * 250)}.${Math.floor(r() * 250) + 1}`;
}

export interface DnsAnswer {
  host: string;
  ips: string[];
  ttl: number;
  rebinding: boolean;
}

export class SimulatedDns {
  private queries = new Map<string, number>();

  resolve(host: string): DnsAnswer {
    const h = host.toLowerCase();
    const n = this.queries.get(h) ?? 0;
    this.queries.set(h, n + 1);
    const rebind = REBINDING[h];
    if (rebind) return { host: h, ips: rebind[Math.min(n, rebind.length - 1)], ttl: 0, rebinding: true };
    return { host: h, ips: STATIC[h] ?? [publicAddress(h)], ttl: 300, rebinding: false };
  }
}
