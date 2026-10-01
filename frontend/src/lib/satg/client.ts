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

// Longer than the proxy's backend timeout (25 s, proxy.ts), so a slow
// backend surfaces as the proxy's BACKEND_TIMEOUT rather than a bare abort.
const CLIENT_TIMEOUT_MS = 30_000;

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

/** Advisory ML assessment (backend/app/ml). Computed by the backend only. */
export interface SatgMl {
  status: "ok" | "unavailable" | "error" | "not_consulted" | "disabled";
  mode: string;
  model_version: string | null;
  risk_score: number | null;
  risk_level: string | null;
  prediction: "risky" | "benign" | null;
  conformal_abstain: boolean | null;
  signals: Record<string, number>;
  top_factors: { feature: string; value: number; contribution: number }[];
  context_used: string[];
  latency_ms: number | null;
  detail: string | null;
}

export interface SatgDecision {
  deterministic_verdict: "ALLOW" | "BLOCK";
  deterministic_rule_id: string;
  ml_mode: string;
  ml_high_risk_threshold: number;
  ml_critical_risk_threshold: number;
  final_verdict: SatgVerdictType;
  final_rule_id: string;
}

export type SatgExecutionStatus =
  | "success"
  | "tool_error"
  | "rejected"
  | "timeout"
  | "killed"
  | "sandbox_unavailable"
  | "integrity_failed"
  | "error"
  | "not_executed";

/** Result of running an ALLOWED call in the Docker sandbox. */
export interface SatgExecution {
  sandbox_id: string | null;
  status: SatgExecutionStatus;
  exit_code: number | null;
  duration_ms: number | null;
  stdout: string;
  stderr: string;
  result: Record<string, unknown> | null;
  error: string | null;
  container_removed: boolean | null;
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
  ml: SatgMl | null;
  decision: SatgDecision | null;
  execution: SatgExecution | null;
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

const ML_STATUSES = ["ok", "unavailable", "error", "not_consulted", "disabled"] as const;
const EXECUTION_STATUSES = ["success", "tool_error", "rejected", "timeout", "killed", "sandbox_unavailable", "integrity_failed", "error", "not_executed"] as const;
const isNum = (v: unknown): v is number => typeof v === "number" && Number.isFinite(v);
const optNum = (v: unknown): number | null => (isNum(v) ? v : null);
const numRecord = (v: unknown): Record<string, number> | null =>
  isObj(v) && Object.values(v).every(isNum) ? (Object.fromEntries(Object.entries(v)) as Record<string, number>) : null;

/** Optional object field: absent/null → null; present but malformed → undefined (reject the whole verdict). */
function optObject<T>(v: unknown, parse: (o: Record<string, unknown>) => T | null): T | null | undefined {
  if (v === undefined || v === null) return null;
  if (!isObj(v)) return undefined;
  return parse(v) ?? undefined;
}

function parseMl(v: Record<string, unknown>): SatgMl | null {
  if (!oneOf(v.status, ML_STATUSES) || !isStr(v.mode)) return null;
  const signals = v.signals === undefined ? {} : numRecord(v.signals);
  const factors = v.top_factors === undefined ? [] : v.top_factors;
  if (!signals || !Array.isArray(factors) || !factors.every((f) => isObj(f) && isStr(f.feature) && isNum(f.value) && isNum(f.contribution))) return null;
  if (!["model_version", "risk_level", "detail"].every((k) => isOptStr(v[k]))) return null;
  if (v.risk_score !== undefined && v.risk_score !== null && (!isNum(v.risk_score) || v.risk_score < 0 || v.risk_score > 1)) return null;
  return {
    status: v.status,
    mode: v.mode,
    model_version: optStr(v.model_version),
    risk_score: optNum(v.risk_score),
    risk_level: optStr(v.risk_level),
    prediction: v.prediction === "risky" || v.prediction === "benign" ? v.prediction : null,
    conformal_abstain: typeof v.conformal_abstain === "boolean" ? v.conformal_abstain : null,
    signals,
    top_factors: (factors as Record<string, unknown>[]).map((f) => ({ feature: f.feature as string, value: f.value as number, contribution: f.contribution as number })),
    context_used: isStrList(v.context_used) ? [...v.context_used] : [],
    latency_ms: optNum(v.latency_ms),
    detail: optStr(v.detail),
  };
}

function parseDecision(v: Record<string, unknown>): SatgDecision | null {
  if (!oneOf(v.deterministic_verdict, ["ALLOW", "BLOCK"] as const) || !oneOf(v.final_verdict, VERDICTS)) return null;
  if (!isStr(v.deterministic_rule_id) || !isStr(v.final_rule_id) || !isStr(v.ml_mode) || !isNum(v.ml_high_risk_threshold) || !isNum(v.ml_critical_risk_threshold)) return null;
  return {
    deterministic_verdict: v.deterministic_verdict,
    deterministic_rule_id: v.deterministic_rule_id,
    ml_mode: v.ml_mode,
    ml_high_risk_threshold: v.ml_high_risk_threshold,
    ml_critical_risk_threshold: v.ml_critical_risk_threshold,
    final_verdict: v.final_verdict,
    final_rule_id: v.final_rule_id,
  };
}

function parseExecution(v: Record<string, unknown>): SatgExecution | null {
  if (!oneOf(v.status, EXECUTION_STATUSES) || !isOptStr(v.sandbox_id) || !isOptStr(v.error)) return null;
  if (v.result !== undefined && v.result !== null && !isObj(v.result)) return null;
  return {
    sandbox_id: optStr(v.sandbox_id),
    status: v.status,
    exit_code: optNum(v.exit_code),
    duration_ms: optNum(v.duration_ms),
    stdout: isStr(v.stdout) ? v.stdout : "",
    stderr: isStr(v.stderr) ? v.stderr : "",
    result: isObj(v.result) ? v.result : null,
    error: optStr(v.error),
    container_removed: typeof v.container_removed === "boolean" ? v.container_removed : null,
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
  const ml = optObject(v.ml, parseMl);
  const decision = optObject(v.decision, parseDecision);
  const execution = optObject(v.execution, parseExecution);
  if (network === null || anomalies === null || integrity === undefined || ml === undefined || decision === undefined || execution === undefined) return null;
  // An integrity tag is only ever issued with an ALLOW, and only an ALLOW reaches the sandbox.
  if ((integrity || execution) && v.verdict !== "ALLOW") return null;
  if (decision && decision.final_verdict !== v.verdict) return null;
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
    ml,
    decision,
    execution,
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
