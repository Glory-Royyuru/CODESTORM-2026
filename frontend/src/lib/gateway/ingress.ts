import type { Protocol } from "./types";

/* ------------------------------------------------------------------ */
/* M1 — strict JSON parsing: duplicate keys, depth and size limits     */
/* ------------------------------------------------------------------ */

export class IngressError extends Error {
  constructor(public code: "DUPLICATE_KEY" | "DEPTH" | "SIZE" | "SYNTAX" | "PROTOCOL", message: string) {
    super(message);
  }
}

/**
 * A small recursive-descent JSON parser. Unlike JSON.parse it refuses
 * duplicate keys (a classic parser-differential smuggling vector) and
 * enforces a maximum nesting depth while parsing.
 */
export function strictParse(text: string, maxDepth: number): { value: unknown; depth: number } {
  let i = 0;
  let deepest = 0;

  const ws = () => {
    while (i < text.length && " \t\n\r".includes(text[i])) i++;
  };
  const fail = (msg: string): never => {
    throw new IngressError("SYNTAX", `${msg} at offset ${i}`);
  };

  const parseString = (): string => {
    if (text[i] !== '"') fail("expected string");
    const start = i;
    i++;
    while (i < text.length && text[i] !== '"') {
      if (text[i] === "\\") i++;
      i++;
    }
    if (i >= text.length) fail("unterminated string");
    i++;
    try {
      return JSON.parse(text.slice(start, i)) as string;
    } catch {
      return fail("invalid string escape");
    }
  };

  const parseValue = (depth: number): unknown => {
    ws();
    const ch = text[i];
    if (ch === "{" || ch === "[") {
      if (depth + 1 > maxDepth)
        throw new IngressError("DEPTH", `payload nesting depth exceeds ${maxDepth}`);
      deepest = Math.max(deepest, depth + 1);
    }
    if (ch === "{") {
      i++;
      const obj: Record<string, unknown> = {};
      const seen = new Set<string>();
      ws();
      if (text[i] === "}") {
        i++;
        return obj;
      }
      for (;;) {
        ws();
        const key = parseString();
        if (seen.has(key)) throw new IngressError("DUPLICATE_KEY", `duplicate JSON key "${key}" rejected`);
        seen.add(key);
        ws();
        if (text[i] !== ":") fail("expected ':'");
        i++;
        obj[key] = parseValue(depth + 1);
        ws();
        if (text[i] === ",") {
          i++;
          continue;
        }
        if (text[i] === "}") {
          i++;
          return obj;
        }
        fail("expected ',' or '}'");
      }
    }
    if (ch === "[") {
      i++;
      const arr: unknown[] = [];
      ws();
      if (text[i] === "]") {
        i++;
        return arr;
      }
      for (;;) {
        arr.push(parseValue(depth + 1));
        ws();
        if (text[i] === ",") {
          i++;
          continue;
        }
        if (text[i] === "]") {
          i++;
          return arr;
        }
        fail("expected ',' or ']'");
      }
    }
    if (ch === '"') return parseString();
    const m = /^(-?\d+(\.\d+)?([eE][+-]?\d+)?|true|false|null)/.exec(text.slice(i));
    if (!m) return fail("unexpected token");
    i += m[0].length;
    return JSON.parse(m[0]);
  };

  const value = parseValue(0);
  ws();
  if (i !== text.length) fail("trailing characters");
  return { value, depth: deepest };
}

export const byteLength = (s: string) => new TextEncoder().encode(s).length;

/* ------------------------------------------------------------------ */
/* Protocol adapters: MCP JSON-RPC, OpenAI function calling, REST      */
/* ------------------------------------------------------------------ */

export interface NormalizedCall {
  protocol: Protocol;
  tool: string;
  arguments: Record<string, unknown>;
  depth: number;
  bytes: number;
}

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);

export function detectProtocol(v: unknown): Protocol | null {
  if (!isObj(v)) return null;
  if (v.jsonrpc === "2.0") return "MCP";
  if (v.type === "function" || isObj(v.function)) return "OPENAI";
  if (typeof v.path === "string") return "REST";
  return null;
}

export function normalize(raw: string, limits: { maxDepth: number; maxBytes: number }): NormalizedCall {
  const bytes = byteLength(raw);
  if (bytes > limits.maxBytes)
    throw new IngressError("SIZE", `payload is ${(bytes / 1024).toFixed(1)}KB, limit ${limits.maxBytes / 1024}KB`);

  const { value, depth } = strictParse(raw, limits.maxDepth);
  const protocol = detectProtocol(value);
  if (!protocol || !isObj(value)) throw new IngressError("PROTOCOL", "unrecognized tool-call protocol envelope");

  if (protocol === "MCP") {
    const params = value.params;
    if (value.method !== "tools/call" || !isObj(params) || typeof params.name !== "string")
      throw new IngressError("PROTOCOL", "MCP request must be method tools/call with params.name");
    return { protocol, tool: params.name, arguments: isObj(params.arguments) ? params.arguments : {}, depth, bytes };
  }

  if (protocol === "OPENAI") {
    const fn = value.function;
    if (!isObj(fn) || typeof fn.name !== "string")
      throw new IngressError("PROTOCOL", "OpenAI tool call requires function.name");
    // OpenAI encodes arguments as a JSON string — parse it with the same strict rules.
    let args: unknown = fn.arguments ?? {};
    let argDepth = 0;
    if (typeof args === "string") {
      const parsed = strictParse(args, limits.maxDepth - depth);
      args = parsed.value;
      argDepth = parsed.depth;
    }
    if (!isObj(args)) throw new IngressError("PROTOCOL", "function.arguments must be an object");
    return { protocol, tool: fn.name, arguments: args, depth: depth + argDepth, bytes };
  }

  const path = String(value.path);
  const m = /^\/v1\/tools\/([a-z0-9_]+)$/i.exec(path);
  if (!m || value.method !== "POST") throw new IngressError("PROTOCOL", "REST calls must be POST /v1/tools/{name}");
  return { protocol, tool: m[1], arguments: isObj(value.body) ? value.body : {}, depth, bytes };
}

/** Render a call in a given wire protocol (used by the Attack Studio). */
export function toWire(protocol: Protocol, tool: string, args: Record<string, unknown>): string {
  if (protocol === "MCP")
    return JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: tool, arguments: args } }, null, 2);
  if (protocol === "OPENAI")
    return JSON.stringify({ type: "function", function: { name: tool, arguments: JSON.stringify(args) } }, null, 2);
  return JSON.stringify({ method: "POST", path: `/v1/tools/${tool}`, body: args }, null, 2);
}

/* ------------------------------------------------------------------ */
/* Token-bucket rate limiter (per agent)                               */
/* ------------------------------------------------------------------ */

export class RateLimiter {
  private buckets = new Map<string, { tokens: number; last: number }>();
  constructor(
    private capacity: number,
    private refillPerSec: number,
  ) {}

  take(key: string, now: number): boolean {
    const b = this.buckets.get(key) ?? { tokens: this.capacity, last: now };
    b.tokens = Math.min(this.capacity, b.tokens + ((now - b.last) / 1000) * this.refillPerSec);
    b.last = now;
    const ok = b.tokens >= 1;
    if (ok) b.tokens -= 1;
    this.buckets.set(key, b);
    return ok;
  }

  configure(capacity: number, refillPerSec: number) {
    this.capacity = capacity;
    this.refillPerSec = refillPerSec;
  }
}
