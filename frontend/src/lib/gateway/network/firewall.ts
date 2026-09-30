import { classifyIp, DENY_RANGES, parseIp, type DenyCheck } from "./cidr";
import type { SimulatedDns } from "./resolver";

/* Multi-stage destination firewall: parse → scheme → local names → deny ranges → eTLD+1 allowlist → resolve once & pin. */

export type NetCheckId = "URL_PARSE" | "SCHEME_HTTPS" | "LOCAL_HOSTNAME" | DenyCheck | "DOMAIN_ALLOWLIST" | "DNS_RESOLUTION_PINNED";
export type NetCheckStatus = "PASSED" | "BLOCKED" | "NOT_EVALUATED";

export interface NetCheck {
  check: NetCheckId;
  label: string;
  status: NetCheckStatus;
  detail?: string;
}

export interface NetworkInspection {
  url: string;
  host: string | null;
  registrableDomain: string | null;
  resolvedIps: string[];
  /** The only address the egress proxy will connect to. Never re-resolved. */
  pinnedIp: string | null;
  checks: NetCheck[];
  decision: "ALLOW" | "HARD_DENY";
  reason: string;
}

export const CHECK_LABELS: Record<NetCheckId, string> = {
  URL_PARSE: "Strict URL parse",
  SCHEME_HTTPS: "HTTPS only",
  LOCAL_HOSTNAME: "Local hostname",
  ...(Object.fromEntries(DENY_RANGES.map((r) => [r.check, r.label])) as Record<DenyCheck, string>),
  DOMAIN_ALLOWLIST: "eTLD+1 allowlist",
  DNS_RESOLUTION_PINNED: "DNS resolved & pinned",
};
const ORDER = Object.keys(CHECK_LABELS) as NetCheckId[];

const LOCAL_NAMES = new Set(["localhost", "metadata", "metadata.google.internal"]);
const LOCAL_SUFFIXES = [".localhost", ".local", ".internal", ".home.arpa"];
/** Deliberately small public-suffix table; an unknown suffix has no registrable domain (fail closed). */
const PUBLIC_SUFFIXES = new Set(["com", "net", "org", "io", "dev", "app", "ai", "co", "de", "fr", "in", "co.uk", "org.uk", "com.au", "co.jp"]);
const LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

export function registrableDomain(host: string): string | null {
  const labels = host.split(".");
  for (const size of [2, 1]) if (labels.length > size && PUBLIC_SUFFIXES.has(labels.slice(-size).join("."))) return labels.slice(-size - 1).join(".");
  return null;
}

/** Host part of a URL exactly as written (WHATWG URL would silently normalize 2852039166 → 169.254.169.254). */
function rawHost(url: string): string | null {
  const m = /^[a-z][a-z0-9+.-]*:\/\/([^/?#]*)/i.exec(url);
  if (!m) return null;
  const authority = m[1];
  if (authority.includes("@")) return null;
  if (authority.startsWith("[")) return authority.slice(0, authority.indexOf("]") + 1) || null;
  return authority.replace(/:443$/, "");
}

/** Literal-only check (no DNS): is this host a local name or an address in a deny range? */
export function hostIsDenied(host: string): boolean {
  const h = host.toLowerCase().replace(/^\[|\]$/g, "");
  if (LOCAL_NAMES.has(h) || LOCAL_SUFFIXES.some((s) => h.endsWith(s))) return true;
  if (h.split(".").every((l) => /^(\d+|0x[0-9a-f]*)$/.test(l))) return parseIp(h) === null || classifyIp(parseIp(h)!) !== null;
  const ip = parseIp(h);
  return !!ip && classifyIp(ip) !== null;
}

export function inspectDestination(url: string, allowlist: string[], dns: SimulatedDns): NetworkInspection {
  const done = new Map<NetCheckId, NetCheck>();
  const record = (check: NetCheckId, passed: boolean, detail?: string) => {
    done.set(check, { check, label: CHECK_LABELS[check], status: passed ? "PASSED" : "BLOCKED", detail });
    return passed;
  };
  const out: NetworkInspection = { url, host: null, registrableDomain: null, resolvedIps: [], pinnedIp: null, checks: [], decision: "ALLOW", reason: "" };
  const finish = (reason: string, deny: boolean) => {
    out.checks = ORDER.map((c) => done.get(c) ?? { check: c, label: CHECK_LABELS[c], status: "NOT_EVALUATED" as const });
    out.decision = deny ? "HARD_DENY" : "ALLOW";
    out.reason = reason;
    return out;
  };
  const rangeChecks = (ips: string[]) => {
    const hits = new Map<DenyCheck, string>();
    for (const t of ips) {
      const hit = classifyIp(parseIp(t)!);
      if (hit && !hits.has(hit.check)) hits.set(hit.check, `${t} ∈ ${hit.cidr}`);
    }
    for (const r of DENY_RANGES) record(r.check, !hits.has(r.check), hits.get(r.check));
    return [...hits.values()][0];
  };

  const host = rawHost(url)?.toLowerCase() ?? null;
  const ascii = /^[\x21-\x7e]+$/.test(url) && !url.includes("\\");
  const literal = host ? parseIp(host.replace(/^\[|\]$/g, "")) : null;
  const numericForm = !!host && !literal && host.split(".").every((l) => /^(\d+|0x[0-9a-f]*)$/.test(l));
  const validName = !!host && !literal && host.split(".").every((l) => LABEL.test(l));
  if (!record("URL_PARSE", ascii && !!host && !numericForm && (!!literal || validName), numericForm ? "non-canonical numeric IP encoding" : undefined))
    return finish(numericForm ? `${host} is an ambiguous numeric IP encoding` : "URL is not a single unambiguous ASCII URL", true);
  out.host = host;

  const scheme = url.slice(0, url.indexOf(":")).toLowerCase();
  if (!record("SCHEME_HTTPS", scheme === "https", scheme)) return finish(`scheme ${scheme} is not https`, true);

  if (literal) {
    record("LOCAL_HOSTNAME", true, "IP literal");
    const hit = rangeChecks([literal.text]);
    if (hit) return finish(`SSRF: ${hit}`, true);
    record("DOMAIN_ALLOWLIST", false, "IP literals are never allow-listed");
    return finish(`${literal.text} is an IP literal; only allow-listed domains are permitted`, true);
  }

  const local = LOCAL_NAMES.has(host!) || LOCAL_SUFFIXES.some((s) => host!.endsWith(s));
  if (!record("LOCAL_HOSTNAME", !local, local ? "local / private zone" : undefined)) return finish(`SSRF: ${host} names a local or private zone`, true);

  // The host must have a known registrable domain (eTLD+1), and equal or sit under an allow-listed
  // entry — a registrable domain ("github.com") or a specific registered endpoint ("docs.python.org").
  const domain = registrableDomain(host!);
  out.registrableDomain = domain;
  const entry = domain ? allowlist.map((d) => d.toLowerCase()).find((d) => host === d || host!.endsWith(`.${d}`)) : undefined;
  if (!record("DOMAIN_ALLOWLIST", !!entry, `eTLD+1 ${domain ?? "unknown"}${entry ? ` · matches ${entry}` : ""}`))
    return finish(`${host} is not under an allow-listed domain`, true);

  const answer = dns.resolve(host!);
  out.resolvedIps = answer.ips;
  const hit = rangeChecks(answer.ips);
  if (hit) {
    record("DNS_RESOLUTION_PINNED", false, "resolved into a denied range");
    return finish(`SSRF via DNS: ${host} resolves to ${hit}`, true);
  }
  out.pinnedIp = answer.ips[0];
  record("DNS_RESOLUTION_PINNED", true, `pinned ${out.pinnedIp}${answer.rebinding ? " · TTL 0 (rebinding-capable name)" : ""}`);
  return finish(`resolved once and pinned to ${out.pinnedIp}`, false);
}
