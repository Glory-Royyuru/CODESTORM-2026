import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import { VERDICTS, type Verdict } from "./types";

export const sha256Hex = (s: string) => bytesToHex(sha256(utf8ToBytes(s)));

/** RFC 8785-style canonical JSON: sorted keys, no whitespace. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value ?? null);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const obj = value as Record<string, unknown>;
  return `{${Object.keys(obj)
    .filter((k) => obj[k] !== undefined)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`)
    .join(",")}}`;
}

export const clamp = (v: number, lo = 0, hi = 1) => Math.min(hi, Math.max(lo, v));
export const sigmoid = (x: number) => 1 / (1 + Math.exp(-x));
export const round = (v: number, d = 2) => Math.round(v * 10 ** d) / 10 ** d;

export const severity = (v: Verdict) => VERDICTS.indexOf(v);
export const maxVerdict = (...vs: Verdict[]): Verdict =>
  vs.reduce<Verdict>((a, b) => (severity(b) > severity(a) ? b : a), "ALLOW");

/** Deterministic PRNG so seeded data and modeled latencies are reproducible. */
export function mulberry32(seed: number) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function hashSeed(s: string) {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) h = Math.imul(h ^ s.charCodeAt(i), 16777619);
  return h >>> 0;
}

export function uuid(): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) return crypto.randomUUID();
  const r = mulberry32(Date.now());
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
    const n = Math.floor(r() * 16);
    return (c === "x" ? n : (n & 0x3) | 0x8).toString(16);
  });
}

export const shortId = (prefix: string) => `${prefix}_${uuid().replace(/-/g, "").slice(0, 10)}`;

/** Flatten every string leaf of an argument object (with its path). */
export function stringLeaves(value: unknown, path = ""): { path: string; value: string }[] {
  if (typeof value === "string") return [{ path, value }];
  if (typeof value === "number" || typeof value === "boolean") return [{ path, value: String(value) }];
  if (Array.isArray(value)) return value.flatMap((v, i) => stringLeaves(v, `${path}[${i}]`));
  if (value && typeof value === "object")
    return Object.entries(value).flatMap(([k, v]) => stringLeaves(v, path ? `${path}.${k}` : k));
  return [];
}

export function shannonEntropy(s: string) {
  if (!s) return 0;
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of freq.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

export function percentile(values: number[], p: number) {
  if (!values.length) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1)];
}
