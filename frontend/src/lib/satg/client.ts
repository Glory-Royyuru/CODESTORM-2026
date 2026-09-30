/**
 * Browser client for the real SATG backend (FastAPI, `backend/`).
 *
 * The backend is the only security authority. This module sends the raw
 * request body through the same-origin proxy (`/api/satg/...`) and reports
 * what came back. It never decides, upgrades or fabricates a verdict:
 *   - a response is a verdict only if it matches the backend's `Verdict`
 *     model (backend/app/models/verdict.py) exactly;
 *   - ALLOW is accepted only with HTTP 200 (the backend never sends ALLOW
 *     with any other status); anything inconsistent is reported as malformed;
 *   - transport failures and non-verdict responses are errors, never verdicts.
 */

export const TOOLCALLS_PATH = "/api/satg/v1/toolcalls";
export const HEALTH_PATH = "/api/satg/health";
/** The backend endpoint the proxy forwards to. */
export const BACKEND_ENDPOINT = "POST /v1/toolcalls";

const CLIENT_TIMEOUT_MS = 15_000;

/* ---------- backend contract (mirrors backend/app/models/verdict.py) ---------- */

export type SatgVerdictType = "ALLOW" | "BLOCK" | "ESCALATE";
export type SatgSeverity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type SatgCheckStatus = "PASSED" | "FAILED";

export interface SatgCheck {
  check: string;
  status: SatgCheckStatus;
}

/** One network-boundary check for a URL destination (backend/app/gateway/network.py). */
export interface SatgNetworkCheck {
  check: string;
  status: "PASSED" | "BLOCKED" | "NOT_EVALUATED";
  detail: string | null;
}

export interface SatgNetworkInspection {
  parameter: string;
  requested_url: string;
  requested_host: string | null;
  registrable_domain: string | null;
  resolved_ips: string[];
  /** The execution layer must connect to this IP and never re-resolve. */
  pinned_ip: string | null;
  checks: SatgNetworkCheck[];
}

/** HMAC-SHA256 tag over the allowed request (ALLOW only). */
export interface SatgRequestIntegrity {
  algorithm: "HMAC-SHA256";
  key_id: string;
  signed_fields: string[];
  signature: string;
}

/** A quarantined crypt-arithmetic anomaly (CRYPTO-* rejections). */
export interface SatgAnomaly {
  anomaly_id: string;
  anomaly_type: string;
  risk_severity: "CRITICAL" | "HIGH" | "ELEVATED";
  rule_id: string;
  location: string;
  raw_payload_sha256: string;
  raw_payload_bytes: number;
  quarantined_hex_snippet: string;
  parser_error_detail: string;
  mitigation_action: "QUARANTINE_AND_HARD_DENY" | "STRIP_AND_RETRY_SANDBOX" | "ISOLATE_SESSION";
}

export interface SatgVerdict {
  verdict: SatgVerdictType;
  severity: SatgSeverity;
  agent_id: string | null;
  tool: string | null;
  rule_id: string;
  reason: string;
  stage: string;
  checks: SatgCheck[];
  checks_not_evaluated: string[];
  request_id: string;
  policy_version: string;
  tool_version: string | null;
  tool_manifest_hash: string | null;
  request_hash: string | null;
  /** Optional in the contract: older backends omit these fields. */
  network: SatgNetworkInspection[];
  request_integrity: SatgRequestIntegrity | null;
  anomalies: SatgAnomaly[];
}

/** Schema errors the backend attaches to an INGRESS-005 rejection. */
export interface SatgIngressError {
  loc: (string | number)[];
  msg: string;
  type: string;
}

export type SatgOutcome =
  /** The backend returned a well-formed verdict (any HTTP status). */
  | { kind: "verdict"; httpStatus: number; verdict: SatgVerdict; ingressErrors: SatgIngressError[]; roundTripMs: number; raw: unknown }
  /** The backend answered, but not with a verdict (e.g. 404, 405, bad JSON, contract mismatch). */
  | { kind: "backend_error"; httpStatus: number; message: string; roundTripMs: number; raw: unknown }
  /** No backend answer at all: backend down, proxy down, timeout. */
  | { kind: "network_error"; code: string; message: string; roundTripMs: number };

/* ---------- strict response validation ---------- */

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const isStr = (v: unknown): v is string => typeof v === "string";
const isOptStr = (v: unknown): v is string | null | undefined => v === null || v === undefined || typeof v === "string";
/** Only call after isOptStr() has accepted `v`. */
const optStr = (v: unknown): string | null => (typeof v === "string" ? v : null);
const oneOf = <T extends string>(v: unknown, allowed: readonly T[]): v is T => typeof v === "string" && (allowed as readonly string[]).includes(v);

const VERDICTS = ["ALLOW", "BLOCK", "ESCALATE"] as const;
const SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"] as const;
const CHECK_STATUSES = ["PASSED", "FAILED"] as const;
const NETWORK_STATUSES = ["PASSED", "BLOCKED", "NOT_EVALUATED"] as const;
const RISK_SEVERITIES = ["CRITICAL", "HIGH", "ELEVATED"] as const;
const MITIGATIONS = ["QUARANTINE_AND_HARD_DENY", "STRIP_AND_RETRY_SANDBOX", "ISOLATE_SESSION"] as const;
const isStrList = (v: unknown): v is string[] => Array.isArray(v) && v.every(isStr);

/** Optional list field: absent → [], present but malformed → null (reject the whole verdict). */
function optList<T>(v: unknown, parse: (item: unknown) => T | null): T[] | null {
  if (v === undefined) return [];
  if (!Array.isArray(v)) return null;
  const out = v.map(parse);
  return out.every((x): x is T => x !== null) ? out : null;
}

function parseNetwork(v: unknown): SatgNetworkInspection | null {
  if (!isObj(v) || !isStr(v.parameter) || !isStr(v.requested_url) || !isOptStr(v.requested_host) || !isOptStr(v.registrable_domain) || !isOptStr(v.pinned_ip)) return null;
  if (!isStrList(v.resolved_ips) || !Array.isArray(v.checks)) return null;
  const checks = v.checks.map((c) => (isObj(c) && isStr(c.check) && oneOf(c.status, NETWORK_STATUSES) && isOptStr(c.detail) ? { check: c.check, status: c.status, detail: optStr(c.detail) } : null));
  if (!checks.every((c) => c !== null)) return null;
  return {
    parameter: v.parameter,
    requested_url: v.requested_url,
    requested_host: optStr(v.requested_host),
    registrable_domain: optStr(v.registrable_domain),
    resolved_ips: [...v.resolved_ips],
    pinned_ip: optStr(v.pinned_ip),
    checks: checks as SatgNetworkCheck[],
  };
}

function parseAnomaly(v: unknown): SatgAnomaly | null {
  if (!isObj(v)) return null;
  const strings = ["anomaly_id", "anomaly_type", "rule_id", "location", "raw_payload_sha256", "quarantined_hex_snippet", "parser_error_detail"] as const;
  if (!strings.every((k) => isStr(v[k])) || typeof v.raw_payload_bytes !== "number") return null;
  if (!oneOf(v.risk_severity, RISK_SEVERITIES) || !oneOf(v.mitigation_action, MITIGATIONS)) return null;
  return {
    anomaly_id: v.anomaly_id as string,
    anomaly_type: v.anomaly_type as string,
    risk_severity: v.risk_severity,
    rule_id: v.rule_id as string,
    location: v.location as string,
    raw_payload_sha256: v.raw_payload_sha256 as string,
    raw_payload_bytes: v.raw_payload_bytes,
    quarantined_hex_snippet: v.quarantined_hex_snippet as string,
    parser_error_detail: v.parser_error_detail as string,
    mitigation_action: v.mitigation_action,
  };
}

/** absent/null → null; present but malformed → undefined (reject the whole verdict). */
function parseIntegrity(v: unknown): SatgRequestIntegrity | null | undefined {
  if (v === undefined || v === null) return null;
  if (!isObj(v) || v.algorithm !== "HMAC-SHA256" || !isStr(v.key_id) || !isStr(v.signature) || !isStrList(v.signed_fields)) return undefined;
  return { algorithm: "HMAC-SHA256", key_id: v.key_id, signature: v.signature, signed_fields: [...v.signed_fields] };
}

/** Returns the verdict if `v` matches the backend Verdict model, else null. */
export function parseVerdict(v: unknown): SatgVerdict | null {
  if (!isObj(v)) return null;
  if (!oneOf(v.verdict, VERDICTS) || !oneOf(v.severity, SEVERITIES)) return null;
  if (!isStr(v.rule_id) || !isStr(v.reason) || !isStr(v.stage) || !isStr(v.request_id) || !isStr(v.policy_version)) return null;
  for (const k of ["agent_id", "tool", "tool_version", "tool_manifest_hash", "request_hash"] as const) if (!isOptStr(v[k])) return null;
  if (!Array.isArray(v.checks) || !v.checks.every((c) => isObj(c) && isStr(c.check) && oneOf(c.status, CHECK_STATUSES))) return null;
  if (!Array.isArray(v.checks_not_evaluated) || !v.checks_not_evaluated.every(isStr)) return null;
  const network = optList(v.network, parseNetwork);
  const anomalies = optList(v.anomalies, parseAnomaly);
  const integrity = parseIntegrity(v.request_integrity);
  if (network === null || anomalies === null || integrity === undefined) return null;
  // An integrity tag is only ever issued with an ALLOW.
  if (integrity && v.verdict !== "ALLOW") return null;
  return {
    verdict: v.verdict,
    severity: v.severity,
    agent_id: optStr(v.agent_id),
    tool: optStr(v.tool),
    rule_id: v.rule_id,
    reason: v.reason,
    stage: v.stage,
    checks: (v.checks as Record<string, unknown>[]).map((c) => ({ check: c.check as string, status: c.status as SatgCheckStatus })),
    checks_not_evaluated: [...(v.checks_not_evaluated as string[])],
    request_id: v.request_id,
    policy_version: v.policy_version,
    tool_version: optStr(v.tool_version),
    tool_manifest_hash: optStr(v.tool_manifest_hash),
    request_hash: optStr(v.request_hash),
    network,
    request_integrity: integrity,
    anomalies,
  };
}

function parseIngressErrors(v: unknown): SatgIngressError[] {
  if (!isObj(v) || !Array.isArray(v.detail)) return [];
  return v.detail
    .filter((e): e is Record<string, unknown> => isObj(e) && isStr(e.msg))
    .map((e) => ({
      loc: Array.isArray(e.loc) ? e.loc.filter((p): p is string | number => typeof p === "string" || typeof p === "number") : [],
      msg: e.msg as string,
      type: isStr(e.type) ? e.type : "",
    }));
}

/** Classify a completed HTTP exchange. Exported for tests. */
export function classifyResponse(httpStatus: number, body: unknown, proxyErrorCode: string | null, roundTripMs: number): SatgOutcome {
  if (proxyErrorCode) {
    const message = isObj(body) && isObj(body.proxy_error) && isStr(body.proxy_error.message) ? body.proxy_error.message : "SATG backend is not reachable";
    return { kind: "network_error", code: proxyErrorCode, message, roundTripMs };
  }
  const verdict = parseVerdict(body);
  if (!verdict) {
    return { kind: "backend_error", httpStatus, message: `Backend responded with HTTP ${httpStatus} but no valid verdict`, roundTripMs, raw: body };
  }
  if (verdict.verdict === "ALLOW" && httpStatus !== 200) {
    // Contract violation: never surface an ALLOW that arrived on an error status.
    return { kind: "backend_error", httpStatus, message: `Backend returned ALLOW with HTTP ${httpStatus}; response rejected as inconsistent`, roundTripMs, raw: body };
  }
  return { kind: "verdict", httpStatus, verdict, ingressErrors: parseIngressErrors(body), roundTripMs, raw: body };
}

/**
 * Send a raw tool-call body to the backend. `body` is forwarded byte-for-byte
 * (the backend's ingress checks must see exactly what the user typed).
 */
export async function submitToolCall(body: string): Promise<SatgOutcome> {
  const started = performance.now();
  const elapsed = () => Math.round((performance.now() - started) * 10) / 10;
  let res: Response;
  try {
    res = await fetch(TOOLCALLS_PATH, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body,
      cache: "no-store",
      signal: AbortSignal.timeout(CLIENT_TIMEOUT_MS),
    });
  } catch (error) {
    const timeout = error instanceof DOMException && error.name === "TimeoutError";
    return {
      kind: "network_error",
      code: timeout ? "CLIENT_TIMEOUT" : "PROXY_UNREACHABLE",
      message: timeout ? `No response within ${CLIENT_TIMEOUT_MS / 1000}s` : "Could not reach the SATG console server",
      roundTripMs: elapsed(),
    };
  }

  let parsed: unknown = null;
  const text = await res.text().catch(() => "");
  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    parsed = text.slice(0, 500);
  }
  return classifyResponse(res.status, parsed, res.headers.get("x-satg-proxy-error"), elapsed());
}

export type BackendHealth = "online" | "offline" | "degraded";

/** Probe the backend's `/health` through the proxy. */
export async function checkHealth(): Promise<BackendHealth> {
  try {
    const res = await fetch(HEALTH_PATH, { cache: "no-store", signal: AbortSignal.timeout(5_000) });
    if (res.headers.get("x-satg-proxy-error")) return "offline";
    const body: unknown = await res.json().catch(() => null);
    return res.ok && isObj(body) && body.status === "ok" ? "online" : "degraded";
  } catch {
    return "offline";
  }
}

/** How the UI should present an outcome. Derived only from the backend's own answer. */
export type OutcomeCategory = "ALLOWED" | "BLOCKED" | "ESCALATED" | "BACKEND_ERROR" | "NETWORK_ERROR";

export function categorize(o: SatgOutcome): OutcomeCategory {
  if (o.kind === "network_error") return "NETWORK_ERROR";
  if (o.kind === "backend_error") return "BACKEND_ERROR";
  if (o.verdict.verdict === "ALLOW") return "ALLOWED";
  if (o.verdict.verdict === "ESCALATE") return "ESCALATED";
  return "BLOCKED";
}
