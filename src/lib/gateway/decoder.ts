/* M3 — Differential parameter-smuggling fuzzer
 *
 * Every string argument is decoded through at most N layers of
 * URL / Base64 / Hex / \u-escape encodings. The "strict" view (what the
 * policy engine sees) is compared with the "lenient" view (what a
 * downstream tool might decode to). If they disagree about whether the
 * value is dangerous, the parsers disagree → smuggling.
 */

export type Encoding = "url" | "base64" | "hex" | "unicode-escape" | "html-entity";

export interface DecodeReport {
  original: string;
  decoded: string;
  layers: Encoding[];
  hitLayerLimit: boolean;
  expansionExceeded: boolean;
  zeroWidth: boolean;
  dangerousRaw: string[];
  dangerousDecoded: string[];
  /** true when decoded content reveals danger the raw form hid */
  disagreement: boolean;
}

export const DANGER_PATTERNS: { id: string; re: RegExp }[] = [
  { id: "path-traversal", re: /(\.\.[\\/])|(\/etc\/(passwd|shadow))|(~\/\.ssh)/i },
  { id: "sql-ddl", re: /\b(drop\s+table|truncate\s+table|alter\s+table|delete\s+from|grant\s+all)\b/i },
  { id: "sql-injection", re: /(\bunion\s+select\b)|(;\s*--)|('\s*or\s*'?1'?\s*=\s*'?1)/i },
  { id: "ssrf-metadata", re: /(169\.254\.169\.254)|(metadata\.google\.internal)|(\blocalhost\b)|(127\.0\.0\.1)/i },
  { id: "shell", re: /(;\s*rm\s+-rf)|(\$\([^)]*\))|(\|\s*sh\b)|(`[^`]+`)/i },
  { id: "script", re: /<script\b|javascript:/i },
];

const PRINTABLE = /^[\x09\x0a\x0d\x20-\x7e]*$/;
const ZERO_WIDTH = /[​-‏⁠﻿]/;

function printableRatio(s: string) {
  if (!s.length) return 0;
  let n = 0;
  for (const ch of s) if (PRINTABLE.test(ch)) n++;
  return n / s.length;
}

function tryUrl(s: string): string | null {
  if (!/%[0-9a-f]{2}/i.test(s)) return null;
  try {
    const d = decodeURIComponent(s);
    return d !== s ? d : null;
  } catch {
    return null;
  }
}

function tryBase64(s: string): string | null {
  const t = s.trim();
  if (t.length < 8 || !/^[A-Za-z0-9+/_-]+={0,2}$/.test(t)) return null;
  // Pure-hex strings are handled by the hex decoder.
  if (/^[0-9a-f]+$/i.test(t)) return null;
  try {
    const norm = t.replace(/-/g, "+").replace(/_/g, "/");
    const bin = atob(norm + "===".slice((norm.length + 3) % 4));
    return printableRatio(bin) > 0.95 ? bin : null;
  } catch {
    return null;
  }
}

function tryHex(s: string): string | null {
  const t = s.trim().replace(/^0x/i, "");
  if (t.length < 8 || t.length % 2 || !/^[0-9a-f]+$/i.test(t)) return null;
  let out = "";
  for (let i = 0; i < t.length; i += 2) out += String.fromCharCode(parseInt(t.slice(i, i + 2), 16));
  return printableRatio(out) > 0.95 ? out : null;
}

function tryUnicodeEscape(s: string): string | null {
  if (!/\\u[0-9a-f]{4}|\\x[0-9a-f]{2}/i.test(s)) return null;
  return s
    .replace(/\\u([0-9a-f]{4})/gi, (_, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/\\x([0-9a-f]{2})/gi, (_, h) => String.fromCharCode(parseInt(h, 16)));
}

function tryHtmlEntity(s: string): string | null {
  if (!/&#x?[0-9a-f]+;/i.test(s)) return null;
  return s.replace(/&#(x?)([0-9a-f]+);/gi, (_, x, n) => String.fromCharCode(parseInt(n, x ? 16 : 10)));
}

const DECODERS: [Encoding, (s: string) => string | null][] = [
  ["url", tryUrl],
  ["unicode-escape", tryUnicodeEscape],
  ["html-entity", tryHtmlEntity],
  ["hex", tryHex],
  ["base64", tryBase64],
];

export const scanDanger = (s: string) => DANGER_PATTERNS.filter((p) => p.re.test(s)).map((p) => p.id);

export function decodeLayers(value: string, maxLayers = 4, expansionCap = 10): DecodeReport {
  let current = value;
  const layers: Encoding[] = [];
  let hitLayerLimit = false;
  let expansionExceeded = false;
  let peak = value.length;

  for (;;) {
    let next: string | null = null;
    let enc: Encoding | null = null;
    for (const [name, fn] of DECODERS) {
      next = fn(current);
      if (next !== null) {
        enc = name;
        break;
      }
    }
    if (next === null || enc === null) break;
    if (layers.length >= maxLayers) {
      hitLayerLimit = true;
      break;
    }
    layers.push(enc);
    peak = Math.max(peak, next.length);
    if (peak > Math.max(64, value.length * expansionCap)) {
      expansionExceeded = true;
      break;
    }
    current = next;
  }

  const lenient = current.normalize("NFKC").replace(/[​-‏⁠﻿]/g, "");
  const dangerousRaw = scanDanger(value);
  const dangerousDecoded = scanDanger(lenient);
  return {
    original: value,
    decoded: lenient,
    layers,
    hitLayerLimit,
    expansionExceeded,
    zeroWidth: ZERO_WIDTH.test(value),
    dangerousRaw,
    dangerousDecoded,
    disagreement: dangerousDecoded.some((d) => !dangerousRaw.includes(d)),
  };
}

/* ---------- mutators used by the Eval Lab payload fuzzer ---------- */

export const MUTATORS: Record<string, (s: string) => string> = {
  base64: (s) => btoa(unescape(encodeURIComponent(s))),
  hex: (s) => Array.from(new TextEncoder().encode(s), (b) => b.toString(16).padStart(2, "0")).join(""),
  url: (s) => Array.from(new TextEncoder().encode(s), (b) => "%" + b.toString(16).padStart(2, "0")).join(""),
  "unicode-escape": (s) => Array.from(s, (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0")).join(""),
  "zero-width": (s) => Array.from(s).join("​"),
  "case-flip": (s) => Array.from(s, (c, i) => (i % 2 ? c.toUpperCase() : c.toLowerCase())).join(""),
};
