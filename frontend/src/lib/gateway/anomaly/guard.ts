import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { strictParse } from "../ingress";

/*
 * Pre-parsing crypt-arithmetic quarantine guard.
 *
 * Runs on the raw payload text *before* JSON.parse, which would silently
 * round 2^256 to 1.157e77 or collapse 2^53+1 into 2^53. A small lexer walks
 * the text: numeric literals are judged as written (never converted), and
 * values of cryptographic fields (signatures, nonces, DPoP proofs, MACs,
 * CRCs, public keys) must be canonically encoded and structurally possible.
 * Checks are structural: the gateway holds no signer keys, so it refuses
 * values no valid signature, point or proof could have.
 */

export type AnomalyType =
  | "CORRUPT_CRYPTO_TOKEN"
  | "ARITHMETIC_INTEGER_OVERFLOW"
  | "NON_CANONICAL_ENCODING"
  | "SIGNATURE_VERIFICATION_FAILURE"
  | "DPOP_PROOF_TAMPERING"
  | "MALFORMED_BIGINT";
export type RiskSeverity = "CRITICAL" | "HIGH" | "ELEVATED";
export type Mitigation = "QUARANTINE_AND_HARD_DENY" | "STRIP_AND_RETRY_SANDBOX" | "ISOLATE_SESSION";

export const MITIGATION: Record<AnomalyType, Mitigation> = {
  ARITHMETIC_INTEGER_OVERFLOW: "QUARANTINE_AND_HARD_DENY",
  MALFORMED_BIGINT: "STRIP_AND_RETRY_SANDBOX",
  NON_CANONICAL_ENCODING: "QUARANTINE_AND_HARD_DENY",
  CORRUPT_CRYPTO_TOKEN: "QUARANTINE_AND_HARD_DENY",
  SIGNATURE_VERIFICATION_FAILURE: "QUARANTINE_AND_HARD_DENY",
  DPOP_PROOF_TAMPERING: "ISOLATE_SESSION",
};

export interface AnomalyFinding {
  type: AnomalyType;
  severity: RiskSeverity;
  /** JSON path of the value; keys that are not plain identifiers are shown as <key>. */
  location: string;
  detail: string;
  /** The offending value exactly as written. Only the ledger sees it, and only to fingerprint it. */
  raw: string;
}

export interface QuarantineScan {
  anomalies: AnomalyFinding[];
  /** Tool name read from a string value (safe to display); null if absent. */
  claimedTool: string | null;
}

const B = (n: number | string) => BigInt(n);
const MAX_CRYPTO_INT_BITS = 256;
const MAX_SAFE = B(Number.MAX_SAFE_INTEGER);
const ED25519_L = B(2) ** B(252) + B("27742317777372353535851937790883648493");

const CRYPTO_FIELD = /signature|(?:^|_)sig(?:$|_)|nonce|dpop|hmac|(?:^|_)mac(?:$|_)|crc|public_?key|pubkey|digest|jws/;
const CONFUSABLES: Record<string, string> = {
  а: "a", е: "e", о: "o", р: "p", с: "c", у: "y", х: "x", і: "i", ј: "j", ѕ: "s", ԁ: "d", ԛ: "q", ԝ: "w", һ: "h", ɡ: "g", ո: "n",
  α: "a", ε: "e", ι: "i", κ: "k", ν: "v", ο: "o", ρ: "p", τ: "t", υ: "u", χ: "x",
};
const skeleton = (k: string) => Array.from(k.normalize("NFKC").toLowerCase(), (c) => CONFUSABLES[c] ?? c).join("");
const SAFE_KEY = /^[A-Za-z0-9_]{1,64}$/;
const child = (path: string, key: string) => (SAFE_KEY.test(key) ? `${path}.${key}` : `${path}.<key>`);

/* ---------- encodings ---------- */

const bitLength = (v: bigint) => (v < B(0) ? -v : v).toString(2).length;
const leToBig = (b: Uint8Array) => b.reduceRight((acc, x) => (acc << B(8)) + B(x), B(0));

function b64Decode(s: string): Uint8Array | null {
  try {
    const bin = atob(s);
    return Uint8Array.from(bin, (c) => c.charCodeAt(0));
  } catch {
    return null;
  }
}
function b64Encode(b: Uint8Array) {
  let bin = "";
  for (const x of b) bin += String.fromCharCode(x);
  return btoa(bin);
}

/** Bytes, or the reason the encoding is invalid or not the one canonical spelling. */
export function decodeCanonical(value: string): Uint8Array | string {
  if (!value) return "empty value";
  if (/^(0x)?[0-9A-Fa-f]+$/.test(value)) {
    const body = value.startsWith("0x") ? value.slice(2) : value;
    if (body.length % 2) return "odd-length hexadecimal";
    if (body !== body.toLowerCase() && body !== body.toUpperCase()) return "mixed-case hexadecimal";
    return Uint8Array.from(body.match(/../g)!, (h) => parseInt(h, 16));
  }
  const std = /^[A-Za-z0-9+/]+={0,2}$/.test(value);
  const url = /^[A-Za-z0-9_-]+={0,2}$/.test(value);
  if (!std && !url) return "characters outside the hex and Base64 alphabets (mixed alphabets or misplaced padding)";
  const stripped = value.replace(/=+$/, "");
  const padding = value.length - stripped.length;
  if (stripped.length % 4 === 1) return "Base64 length is impossible";
  if (padding && (value.length % 4 || stripped.length % 4 === 0 || 4 - (stripped.length % 4) !== padding)) return "superfluous or incomplete Base64 padding";
  const normalized = (url && !std ? stripped.replace(/-/g, "+").replace(/_/g, "/") : stripped).padEnd(Math.ceil(stripped.length / 4) * 4, "=");
  const bytes = b64Decode(normalized);
  if (!bytes) return "invalid Base64";
  if (b64Encode(bytes).replace(/=+$/, "") !== normalized.replace(/=+$/, "")) return "non-canonical Base64 (non-zero trailing bits)";
  return bytes;
}

function isEd25519Point(b: Uint8Array) {
  if (b.length !== 32) return false;
  try {
    ed25519.Point.fromHex(bytesToHex(b));
    return true;
  } catch {
    return false;
  }
}

type Problem = [AnomalyType, RiskSeverity, string] | null;

function checkSignature(sig: Uint8Array): Problem {
  if (sig.every((b) => b === 0)) return ["SIGNATURE_VERIFICATION_FAILURE", "CRITICAL", "all-zero signature"];
  if (sig.length === 64) {
    if (leToBig(sig.slice(32)) >= ED25519_L) return ["SIGNATURE_VERIFICATION_FAILURE", "CRITICAL", "Ed25519 scalar S is not reduced mod ℓ (malleable signature)"];
    if (!isEd25519Point(sig.slice(0, 32))) return ["CORRUPT_CRYPTO_TOKEN", "HIGH", "Ed25519 R is not a valid edwards25519 point"];
    return null;
  }
  if ([256, 384, 512].includes(sig.length)) return sig.every((b) => b === 0xff) ? ["SIGNATURE_VERIFICATION_FAILURE", "CRITICAL", "degenerate RSA signature"] : null;
  return ["CORRUPT_CRYPTO_TOKEN", "HIGH", `signature of ${sig.length} bytes is neither Ed25519 (64) nor RSA (256/384/512)`];
}

function b64urlJson(segment: string): Record<string, unknown> | null {
  const bytes = decodeCanonical(segment);
  if (typeof bytes === "string" || segment.includes("=")) return null;
  try {
    const v = strictParse(new TextDecoder("utf-8", { fatal: true }).decode(bytes), 8).value;
    return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

/** RFC 9449 proof structure. */
function checkDpop(value: string): Problem {
  const t = (d: string): Problem => ["DPOP_PROOF_TAMPERING", "CRITICAL", d];
  const parts = value.split(".");
  if (parts.length !== 3 || !parts.every((p) => /^[A-Za-z0-9_-]+$/.test(p))) return t("DPoP proof is not a compact JWS (three base64url segments)");
  const header = b64urlJson(parts[0]);
  const claims = b64urlJson(parts[1]);
  if (!header || !claims) return t("DPoP header or claims are not canonical base64url JSON objects");
  if (header.typ !== "dpop+jwt") return t("DPoP header typ is not dpop+jwt");
  if (header.alg !== "EdDSA" && header.alg !== "ES256") return t(`DPoP alg is not an allowed asymmetric algorithm (alg=${String(header.alg).slice(0, 12)} refused)`);
  const jwk = header.jwk as Record<string, unknown> | undefined;
  if (!jwk || typeof jwk !== "object" || "d" in jwk) return t("DPoP jwk is missing or contains private key material");
  if (!["jti", "htm", "htu"].every((c) => typeof claims[c] === "string") || !Number.isInteger(claims.iat)) return t("DPoP claims jti/htm/htu/iat are missing or mistyped");
  const sig = decodeCanonical(parts[2]);
  if (typeof sig === "string" || sig.length !== 64) return t("DPoP signature is not 64 bytes");
  if (header.alg === "EdDSA") {
    const p = checkSignature(sig);
    if (p) return t(`DPoP signature: ${p[2]}`);
    const x = typeof jwk.x === "string" ? decodeCanonical(jwk.x) : "missing";
    if (jwk.crv !== "Ed25519" || typeof x === "string" || !isEd25519Point(x)) return t("DPoP jwk is not a valid Ed25519 public key");
  }
  return null;
}

function checkCryptoString(key: string, value: string): Problem {
  if (!/^[\x20-\x7e]*$/.test(value)) return ["NON_CANONICAL_ENCODING", "CRITICAL", "non-ASCII (look-alike) characters in a cryptographic value"];
  if (key.includes("crc")) return null; // checked with its sibling payload when the object closes
  if (key.includes("dpop")) return checkDpop(value);
  const bytes = decodeCanonical(value);
  if (typeof bytes === "string") return ["NON_CANONICAL_ENCODING", "HIGH", bytes];
  if (key.includes("sig") || key.includes("jws")) return checkSignature(bytes);
  if ((key.includes("hmac") || /(?:^|_)mac(?:$|_)/.test(key)) && ![32, 48, 64].includes(bytes.length))
    return ["CORRUPT_CRYPTO_TOKEN", "HIGH", `MAC of ${bytes.length} bytes is not an HMAC-SHA-256/384/512 tag`];
  if (key.includes("nonce") && bytes.every((b) => b === 0)) return ["CORRUPT_CRYPTO_TOKEN", "HIGH", "all-zero nonce"];
  if ((key.includes("public") || key.includes("pubkey")) && bytes.length === 32 && !isEd25519Point(bytes))
    return ["CORRUPT_CRYPTO_TOKEN", "HIGH", "public key is not a valid edwards25519 point"];
  return null;
}

const CRC_TABLE = Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});
export function crc32(text: string) {
  let c = 0xffffffff;
  for (const b of new TextEncoder().encode(text)) c = CRC_TABLE[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function checkNumber(literal: string): Problem {
  if (/[.eE]/.test(literal)) {
    const v = Number(literal);
    return !Number.isFinite(v) || Math.abs(v) >= 2 ** MAX_CRYPTO_INT_BITS ? ["ARITHMETIC_INTEGER_OVERFLOW", "CRITICAL", "numeric literal overflows the representable range"] : null;
  }
  const digits = literal.replace(/^-/, "").length;
  if (digits > 78) return ["ARITHMETIC_INTEGER_OVERFLOW", "CRITICAL", `integer literal with ${digits} digits exceeds ${MAX_CRYPTO_INT_BITS} bits`];
  const v = B(literal);
  const bits = bitLength(v);
  if (bits > MAX_CRYPTO_INT_BITS) return ["ARITHMETIC_INTEGER_OVERFLOW", "CRITICAL", `integer of ${bits} bits exceeds ${MAX_CRYPTO_INT_BITS} bits`];
  if ((v < B(0) ? -v : v) > MAX_SAFE)
    return ["MALFORMED_BIGINT", "ELEVATED", `integer of ${bits} bits is outside the IEEE-754 safe range; JSON.parse would silently round it`];
  return null;
}

/* ---------- the lexer ---------- */

interface Frame {
  kind: "obj" | "arr";
  path: string;
  key: string | null;
  index: number;
  expectKey: boolean;
  strings: Map<string, string>;
  numbers: Map<string, string>;
}

const MAX_NESTED_SCAN = 2;

export function quarantineScan(raw: string, depth = 0, base = "$"): QuarantineScan {
  const anomalies: AnomalyFinding[] = [];
  let claimedTool: string | null = null;
  const stack: Frame[] = [];
  const add = (p: Problem, location: string, value: string) => p && anomalies.push({ type: p[0], severity: p[1], location, detail: p[2], raw: value });
  const here = () => {
    const f = stack[stack.length - 1];
    if (!f) return base;
    return f.kind === "arr" ? `${f.path}[${f.index}]` : child(f.path, f.key ?? "");
  };

  const onValue = (kind: "string" | "number", value: string) => {
    const f = stack[stack.length - 1];
    const key = f?.kind === "obj" ? f.key : null;
    const location = here();
    if (kind === "number") {
      add(checkNumber(value), location, value);
      if (key) f!.numbers.set(key, value);
      return;
    }
    if (key === null) return;
    f!.strings.set(key, value);
    if ((key === "name" || key === "tool") && claimedTool === null && SAFE_KEY.test(value)) claimedTool = value;
    if (key === "path" && claimedTool === null) claimedTool = /\/v1\/tools\/([A-Za-z0-9_]{1,64})$/.exec(value)?.[1] ?? null;
    // OpenAI-style arguments are JSON inside a string: scan them too.
    if (key === "arguments" && depth < MAX_NESTED_SCAN && value.trimStart().startsWith("{")) {
      anomalies.push(...quarantineScan(value, depth + 1, location).anomalies);
      return;
    }
    if (CRYPTO_FIELD.test(skeleton(key)) && /^[\x20-\x7e]+$/.test(key)) add(checkCryptoString(key.toLowerCase(), value), location, value);
  };

  const onKey = (f: Frame, key: string) => {
    f.key = key;
    f.expectKey = false;
    if (CRYPTO_FIELD.test(skeleton(key)) && !/^[\x20-\x7e]+$/.test(key))
      anomalies.push({ type: "NON_CANONICAL_ENCODING", severity: "CRITICAL", location: child(f.path, key), detail: "cryptographic field name uses look-alike (homoglyph) characters", raw: key });
  };

  const closeObject = (f: Frame) => {
    for (const [key, v] of [...f.strings, ...f.numbers]) {
      if (!key.toLowerCase().includes("crc") || !/^[\x20-\x7e]+$/.test(key)) continue;
      const payload = f.strings.get("payload") ?? f.strings.get("data") ?? f.strings.get("body");
      let claimed: number | null = null;
      if (f.strings.has(key)) {
        const bytes = decodeCanonical(v);
        if (typeof bytes === "string" || bytes.length !== 4) {
          add(["NON_CANONICAL_ENCODING", "HIGH", "CRC-32 must be 8 hex digits"], child(f.path, key), v);
          continue;
        }
        claimed = ((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]) >>> 0;
      } else if (/^\d{1,10}$/.test(v) && Number(v) < 2 ** 32) claimed = Number(v);
      else {
        add(["CORRUPT_CRYPTO_TOKEN", "HIGH", "CRC-32 is not a 32-bit unsigned value"], child(f.path, key), v);
        continue;
      }
      if (payload !== undefined && crc32(payload) !== claimed) add(["CORRUPT_CRYPTO_TOKEN", "HIGH", "CRC-32 does not match the payload"], child(f.path, key), v);
    }
  };

  let i = 0;
  const readString = (): string | null => {
    const start = i++;
    while (i < raw.length && raw[i] !== '"') i += raw[i] === "\\" ? 2 : 1;
    i++;
    try {
      return JSON.parse(raw.slice(start, i)) as string;
    } catch {
      return null;
    }
  };
  const NUMBER = /-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/y;

  while (i < raw.length) {
    const ch = raw[i];
    const f = stack[stack.length - 1];
    if (ch === "{" || ch === "[") {
      stack.push({ kind: ch === "{" ? "obj" : "arr", path: here(), key: null, index: 0, expectKey: ch === "{", strings: new Map(), numbers: new Map() });
      i++;
    } else if (ch === "}" || ch === "]") {
      const closed = stack.pop();
      if (closed?.kind === "obj") closeObject(closed);
      i++;
    } else if (ch === ",") {
      if (f?.kind === "arr") f.index++;
      else if (f) f.expectKey = true;
      i++;
    } else if (ch === '"') {
      const s = readString();
      if (s === null) break; // malformed: the strict parser reports it
      if (f?.kind === "obj" && f.expectKey) onKey(f, s);
      else onValue("string", s);
    } else if (ch === "-" || (ch >= "0" && ch <= "9")) {
      NUMBER.lastIndex = i;
      const m = NUMBER.exec(raw);
      if (!m) break;
      onValue("number", m[0]);
      i += m[0].length;
    } else i++;
  }
  return { anomalies, claimedTool };
}

const RANK: Record<RiskSeverity, number> = { ELEVATED: 0, HIGH: 1, CRITICAL: 2 };
/** The anomaly that decides: highest severity, first found on ties. */
export const mostSevere = (a: AnomalyFinding[]) => a.reduce((w, x) => (RANK[x.severity] > RANK[w.severity] ? x : w));
