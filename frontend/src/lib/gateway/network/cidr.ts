/* Strict IPv4 / IPv6 parsing and the egress deny ranges. Pure, no DNS. */

export interface ParsedIp {
  family: 4 | 6;
  value: bigint;
  text: string;
}

const B = (n: number | string) => BigInt(n);

/** Dotted quad only: 4 decimal octets, no leading zeros. Integer/octal/hex forms are refused. */
export function parseIPv4(s: string): bigint | null {
  const parts = s.split(".");
  if (parts.length !== 4) return null;
  let v = B(0);
  for (const p of parts) {
    if (!/^(0|[1-9]\d{0,2})$/.test(p) || Number(p) > 255) return null;
    v = v * B(256) + B(p);
  }
  return v;
}

export function parseIPv6(input: string): bigint | null {
  let s = input.replace(/^\[|\]$/g, "").toLowerCase().split("%")[0];
  // Embedded IPv4 tail (::ffff:169.254.169.254)
  const tail = /^(.*:)(\d+\.\d+\.\d+\.\d+)$/.exec(s);
  if (tail) {
    const v4 = parseIPv4(tail[2]);
    if (v4 === null) return null;
    s = `${tail[1]}${(v4 >> B(16)).toString(16)}:${(v4 & B(0xffff)).toString(16)}`;
  }
  if ((s.match(/::/g) ?? []).length > 1) return null;
  const [head, rest] = s.includes("::") ? s.split("::") : [s, undefined];
  const hs = head ? head.split(":") : [];
  const ts = rest ? rest.split(":") : [];
  const missing = 8 - hs.length - ts.length;
  if (rest === undefined ? hs.length !== 8 : missing < 1) return null;
  const groups = [...hs, ...Array(rest === undefined ? 0 : missing).fill("0"), ...ts];
  let v = B(0);
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
    v = (v << B(16)) + B(parseInt(g, 16));
  }
  return v;
}

export function parseIp(s: string): ParsedIp | null {
  const v4 = parseIPv4(s);
  if (v4 !== null) return { family: 4, value: v4, text: s };
  const v6 = s.includes(":") ? parseIPv6(s) : null;
  return v6 !== null ? { family: 6, value: v6, text: s.replace(/^\[|\]$/g, "") } : null;
}

export function formatIPv4(v: bigint) {
  return [24, 16, 8, 0].map((sh) => Number((v >> B(sh)) & B(255))).join(".");
}

interface Cidr {
  family: 4 | 6;
  base: bigint;
  bits: number;
  text: string;
}

function cidr(text: string): Cidr {
  const [addr, len] = text.split("/");
  const ip = parseIp(addr)!;
  return { family: ip.family, base: ip.value, bits: Number(len), text };
}

const inCidr = (ip: ParsedIp, c: Cidr) => {
  if (ip.family !== c.family) return false;
  const width = ip.family === 4 ? 32 : 128;
  const shift = B(width - c.bits);
  return ip.value >> shift === c.base >> shift;
};

export type DenyCheck = "LOOPBACK" | "ZERO_ADDRESS" | "RFC1918_PRIVATE" | "LINK_LOCAL_METADATA" | "UNIQUE_LOCAL_V6" | "MULTICAST_BROADCAST";

export const DENY_RANGES: { check: DenyCheck; label: string; cidrs: Cidr[] }[] = [
  { check: "LOOPBACK", label: "Loopback", cidrs: ["127.0.0.0/8", "::1/128"].map(cidr) },
  { check: "ZERO_ADDRESS", label: "Zero address", cidrs: ["0.0.0.0/8", "::/128"].map(cidr) },
  { check: "RFC1918_PRIVATE", label: "RFC1918 private", cidrs: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"].map(cidr) },
  { check: "LINK_LOCAL_METADATA", label: "Link-local / cloud metadata", cidrs: ["169.254.0.0/16", "fe80::/10"].map(cidr) },
  { check: "UNIQUE_LOCAL_V6", label: "Unique local IPv6", cidrs: ["fc00::/7"].map(cidr) },
  { check: "MULTICAST_BROADCAST", label: "Multicast / broadcast", cidrs: ["224.0.0.0/4", "255.255.255.255/32", "ff00::/8"].map(cidr) },
];

const V4_MAPPED = cidr("::ffff:0:0/96");

/** Which deny range an address falls in (IPv4-mapped IPv6 is checked as IPv4), or null if public. */
export function classifyIp(ip: ParsedIp): { check: DenyCheck; cidr: string } | null {
  const target = inCidr(ip, V4_MAPPED) ? { family: 4 as const, value: ip.value & B(0xffffffff), text: formatIPv4(ip.value & B(0xffffffff)) } : ip;
  for (const r of DENY_RANGES) {
    const hit = r.cidrs.find((c) => inCidr(target, c));
    if (hit) return { check: r.check, cidr: hit.text };
  }
  return null;
}
