/**
 * Browser client for the SATG backend's read-only audit API
 * (`GET /v1/audit/events`, backend/app/audit/api.py), through the same-origin
 * proxy, which adds the operator token server-side.
 *
 * What it returns is the backend's in-memory audit history since its process
 * started: not persistent, signed or shared between workers. It is a different
 * thing from `useSatgLog` (this browser tab's own requests) and from the demo
 * ledger (simulated).
 *
 * Parsing is strict, like `parseVerdict` (client.ts): a page is accepted only if
 * it matches the backend's AuditPage model, its events are consistent, and it
 * contains none of the fields the API must never return.
 */

import type { SatgSeverity, SatgVerdictType } from "./client";

export const AUDIT_EVENTS_PATH = "/api/satg/v1/audit/events";
const CLIENT_TIMEOUT_MS = 30_000;
export const AUDIT_MAX_LIMIT = 200;

/* ---------- contract (mirrors backend/app/audit/api.py) ---------- */

export interface AuditCheck {
  check: string;
  status: "PASSED" | "FAILED";
}

export interface AuditDecision {
  deterministic_verdict: "ALLOW" | "BLOCK";
  deterministic_rule_id: string;
  final_verdict: SatgVerdictType;
  final_rule_id: string;
  ml_mode: string;
  ml_high_risk_threshold: number;
  ml_critical_risk_threshold: number;
}

/** Operator summary of the ML assessment; the backend withholds model internals. */
export interface AuditMl {
  status: "ok" | "unavailable" | "error" | "not_consulted" | "disabled";
  mode: string;
  model_version: string | null;
  risk_score: number | null;
  risk_level: string | null;
  prediction: "risky" | "benign" | null;
  latency_ms: number | null;
  context_used: string[];
}

export interface AuditExecution {
  status: string;
  sandbox_id: string | null;
  exit_code: number | null;
  duration_ms: number | null;
  container_removed: boolean | null;
  stdout_sha256: string | null;
  stdout_bytes: number | null;
  stderr_sha256: string | null;
  stderr_bytes: number | null;
  error_code: string | null;
  error_summary: string | null;
}

export interface AuditNetwork {
  parameter: string;
  /** scheme://host[:port]/path; the backend removed query, fragment and userinfo. */
  url: string;
  url_query_removed: boolean;
  requested_host: string | null;
  registrable_domain: string | null;
  resolved_ips: string[];
  pinned_ip: string | null;
  checks: { check: string; status: "PASSED" | "BLOCKED" | "NOT_EVALUATED"; detail: string | null }[];
}

export interface AuditAnomaly {
  anomaly_id: string;
  anomaly_type: string;
  risk_severity: string;
  rule_id: string;
  location: string;
  raw_payload_sha256: string;
  raw_payload_bytes: number;
  mitigation_action: string;
}

export interface AuditIntegrity {
  algorithm: string;
  key_id: string;
  signed_fields: string[];
}

export interface AuditEvent {
  seq: number;
  /** When the backend wrote the audit record (after the decision and any sandbox run), UTC. Not request arrival. */
  timestamp: string;
  request_id: string;
  verdict: SatgVerdictType;
  severity: SatgSeverity;
  rule_id: string;
  reason: string;
  stage: string;
  /** Self-asserted by the caller. */
  agent_id: string | null;
  tool: string | null;
  authenticated: boolean;
  auth_method: string | null;
  checks: AuditCheck[];
  checks_not_evaluated: string[];
  policy_version: string;
  tool_version: string | null;
  tool_manifest_hash: string | null;
  request_hash: string | null;
  decision: AuditDecision | null;
  ml: AuditMl | null;
  execution: AuditExecution | null;
  network: AuditNetwork[];
  request_integrity: AuditIntegrity | null;
  anomalies: AuditAnomaly[];
}

export interface AuditPage {
  events: AuditEvent[];
  next_before_seq: number | null;
  storage: "in_memory";
  scope: "this_backend_process";
  process_started_at: string;
  capacity: number;
  retained: number;
  total_recorded: number;
  evicted: number;
  oldest_seq: number | null;
  newest_seq: number | null;
  note: string;
}

export interface AuditQuery {
  limit?: number;
  before_seq?: number;
  verdict?: SatgVerdictType;
  rule_id?: string;
  tool?: string;
  agent_id?: string;
  request_id?: string;
}

export type AuditOutcome =
  | { kind: "ok"; page: AuditPage }
  /** The backend refused the operator token (401/403). */
  | { kind: "auth_error"; httpStatus: number; message: string }
  /** No token configured on the console server or the backend (503). */
  | { kind: "not_configured"; message: string }
  /** The backend rejected the query (422). */
  | { kind: "invalid_query"; message: string }
  /** No backend answer: backend down, proxy down, timeout. */
  | { kind: "unreachable"; code: string; message: string }
  /** An answer that is not a valid audit page. Nothing from it is shown. */
  | { kind: "malformed"; httpStatus: number; message: string };

/* ---------- strict validation ---------- */

/** Fields the audit API must never return. A page containing any of them is rejected outright. */
export const FORBIDDEN_AUDIT_KEYS: ReadonlySet<string> = new Set([
  "parameters", "context", "untrusted_context", "result", "stdout", "stderr", "signature", "features",
  "signals", "top_factors", "quarantined_hex_snippet", "parser_error_detail", "error", "requested_url",
]);

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const isStr = (v: unknown): v is string => typeof v === "string";
const isNum = (v: unknown): v is number => typeof v === "number" && Number.isFinite(v);
const isInt = (v: unknown, min = 0): v is number => Number.isInteger(v) && (v as number) >= min;
const optStr = (v: unknown): v is string | null => v === null || isStr(v);
const optNum = (v: unknown): v is number | null => v === null || isNum(v);
const optInt = (v: unknown): v is number | null => v === null || isInt(v);
const strList = (v: unknown): v is string[] => Array.isArray(v) && v.every(isStr);
const oneOf = <T extends string>(v: unknown, allowed: readonly T[]): v is T => isStr(v) && (allowed as readonly string[]).includes(v);

const VERDICTS = ["ALLOW", "BLOCK", "ESCALATE"] as const;
const SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"] as const;
const ML_STATUSES = ["ok", "unavailable", "error", "not_consulted", "disabled"] as const;

/** The first forbidden key anywhere in `v`, or null. `detail` is forbidden only inside `ml`. */
function forbiddenKey(v: unknown, parent = ""): string | null {
  if (Array.isArray(v)) {
    for (const item of v) {
      const hit = forbiddenKey(item, parent);
      if (hit) return hit;
    }
    return null;
  }
  if (!isObj(v)) return null;
  for (const [k, child] of Object.entries(v)) {
    if (FORBIDDEN_AUDIT_KEYS.has(k) || (parent === "ml" && k === "detail")) return parent ? `${parent}.${k}` : k;
    const hit = forbiddenKey(child, k);
    if (hit) return hit;
  }
  return null;
}

function parseDecision(v: unknown): AuditDecision | null | undefined {
  if (v === null) return null;
  if (!isObj(v) || !oneOf(v.deterministic_verdict, ["ALLOW", "BLOCK"] as const) || !oneOf(v.final_verdict, VERDICTS)) return undefined;
  if (!isStr(v.deterministic_rule_id) || !isStr(v.final_rule_id) || !isStr(v.ml_mode) || !isNum(v.ml_high_risk_threshold) || !isNum(v.ml_critical_risk_threshold)) return undefined;
  return {
    deterministic_verdict: v.deterministic_verdict,
    deterministic_rule_id: v.deterministic_rule_id,
    final_verdict: v.final_verdict,
    final_rule_id: v.final_rule_id,
    ml_mode: v.ml_mode,
    ml_high_risk_threshold: v.ml_high_risk_threshold,
    ml_critical_risk_threshold: v.ml_critical_risk_threshold,
  };
}

function parseMl(v: unknown): AuditMl | null | undefined {
  if (v === null) return null;
  if (!isObj(v) || !oneOf(v.status, ML_STATUSES) || !isStr(v.mode) || !optStr(v.model_version) || !optStr(v.risk_level)) return undefined;
  if (!optNum(v.risk_score) || (v.risk_score !== null && (v.risk_score < 0 || v.risk_score > 1)) || !optNum(v.latency_ms) || !strList(v.context_used)) return undefined;
  if (v.prediction !== null && v.prediction !== "risky" && v.prediction !== "benign") return undefined;
  return {
    status: v.status,
    mode: v.mode,
    model_version: v.model_version,
    risk_score: v.risk_score,
    risk_level: v.risk_level,
    prediction: v.prediction,
    latency_ms: v.latency_ms,
    context_used: [...v.context_used],
  };
}

function parseExecution(v: unknown): AuditExecution | null | undefined {
  if (v === null) return null;
  if (!isObj(v) || !isStr(v.status)) return undefined;
  const strs = ["sandbox_id", "stdout_sha256", "stderr_sha256", "error_code", "error_summary"] as const;
  const ints = ["exit_code", "stdout_bytes", "stderr_bytes"] as const;
  if (!strs.every((k) => optStr(v[k])) || !optNum(v.duration_ms) || !(v.container_removed === null || typeof v.container_removed === "boolean")) return undefined;
  if (!ints.every((k) => v[k] === null || Number.isInteger(v[k]))) return undefined;
  return {
    status: v.status,
    sandbox_id: v.sandbox_id as string | null,
    exit_code: v.exit_code as number | null,
    duration_ms: v.duration_ms,
    container_removed: v.container_removed,
    stdout_sha256: v.stdout_sha256 as string | null,
    stdout_bytes: v.stdout_bytes as number | null,
    stderr_sha256: v.stderr_sha256 as string | null,
    stderr_bytes: v.stderr_bytes as number | null,
    error_code: v.error_code as string | null,
    error_summary: v.error_summary as string | null,
  };
}

function parseNetwork(v: unknown): AuditNetwork | null {
  if (!isObj(v) || !isStr(v.parameter) || !isStr(v.url) || typeof v.url_query_removed !== "boolean") return null;
  if (!optStr(v.requested_host) || !optStr(v.registrable_domain) || !optStr(v.pinned_ip) || !strList(v.resolved_ips) || !Array.isArray(v.checks)) return null;
  const checks = v.checks.map((c) =>
    isObj(c) && isStr(c.check) && oneOf(c.status, ["PASSED", "BLOCKED", "NOT_EVALUATED"] as const) && optStr(c.detail) ? { check: c.check, status: c.status, detail: c.detail } : null,
  );
  if (!checks.every((c) => c !== null)) return null;
  return {
    parameter: v.parameter,
    url: v.url,
    url_query_removed: v.url_query_removed,
    requested_host: v.requested_host,
    registrable_domain: v.registrable_domain,
    resolved_ips: [...v.resolved_ips],
    pinned_ip: v.pinned_ip,
    checks: checks as AuditNetwork["checks"],
  };
}

function parseAnomaly(v: unknown): AuditAnomaly | null {
  if (!isObj(v)) return null;
  const strs = ["anomaly_id", "anomaly_type", "risk_severity", "rule_id", "location", "raw_payload_sha256", "mitigation_action"] as const;
  if (!strs.every((k) => isStr(v[k])) || !isInt(v.raw_payload_bytes)) return null;
  return {
    anomaly_id: v.anomaly_id as string,
    anomaly_type: v.anomaly_type as string,
    risk_severity: v.risk_severity as string,
    rule_id: v.rule_id as string,
    location: v.location as string,
    raw_payload_sha256: v.raw_payload_sha256 as string,
    raw_payload_bytes: v.raw_payload_bytes,
    mitigation_action: v.mitigation_action as string,
  };
}

function parseIntegrity(v: unknown): AuditIntegrity | null | undefined {
  if (v === null) return null;
  if (!isObj(v) || !isStr(v.algorithm) || !isStr(v.key_id) || !strList(v.signed_fields)) return undefined;
  return { algorithm: v.algorithm, key_id: v.key_id, signed_fields: [...v.signed_fields] };
}

/** One audit event, or null if it does not match the backend's AuditEvent model. */
export function parseAuditEvent(v: unknown): AuditEvent | null {
  if (!isObj(v) || !isInt(v.seq, 1) || !isStr(v.timestamp) || Number.isNaN(Date.parse(v.timestamp)) || !isStr(v.request_id)) return null;
  if (!oneOf(v.verdict, VERDICTS) || !oneOf(v.severity, SEVERITIES) || !isStr(v.rule_id) || !isStr(v.reason) || !isStr(v.stage)) return null;
  if (!optStr(v.agent_id) || !optStr(v.tool) || typeof v.authenticated !== "boolean" || !optStr(v.auth_method) || !isStr(v.policy_version)) return null;
  if (!optStr(v.tool_version) || !optStr(v.tool_manifest_hash) || !optStr(v.request_hash) || !strList(v.checks_not_evaluated)) return null;
  if (!Array.isArray(v.checks) || !v.checks.every((c) => isObj(c) && isStr(c.check) && oneOf(c.status, ["PASSED", "FAILED"] as const))) return null;
  if (!Array.isArray(v.network) || !Array.isArray(v.anomalies)) return null;
  const decision = parseDecision(v.decision);
  const ml = parseMl(v.ml);
  const execution = parseExecution(v.execution);
  const integrity = parseIntegrity(v.request_integrity);
  const network = v.network.map(parseNetwork);
  const anomalies = v.anomalies.map(parseAnomaly);
  if (decision === undefined || ml === undefined || execution === undefined || integrity === undefined) return null;
  if (!network.every((n) => n !== null) || !anomalies.every((a) => a !== null)) return null;
  // The same invariants the Live Gateway enforces: only an ALLOW is signed or executed, and the decision trace agrees with the verdict.
  if ((integrity || execution) && v.verdict !== "ALLOW") return null;
  if (decision && (decision.final_verdict !== v.verdict || decision.final_rule_id !== v.rule_id)) return null;
  return {
    seq: v.seq,
    timestamp: v.timestamp,
    request_id: v.request_id,
    verdict: v.verdict,
    severity: v.severity,
    rule_id: v.rule_id,
    reason: v.reason,
    stage: v.stage,
    agent_id: v.agent_id,
    tool: v.tool,
    authenticated: v.authenticated,
    auth_method: v.auth_method,
    checks: (v.checks as Record<string, unknown>[]).map((c) => ({ check: c.check as string, status: c.status as AuditCheck["status"] })),
    checks_not_evaluated: [...v.checks_not_evaluated],
    policy_version: v.policy_version,
    tool_version: v.tool_version,
    tool_manifest_hash: v.tool_manifest_hash,
    request_hash: v.request_hash,
    decision,
    ml,
    execution,
    network: network as AuditNetwork[],
    request_integrity: integrity,
    anomalies: anomalies as AuditAnomaly[],
  };
}

/** A whole page, or an explanation of why it was rejected. Nothing from a rejected page is used. */
export function parseAuditPage(v: unknown): { ok: true; page: AuditPage } | { ok: false; reason: string } {
  if (!isObj(v)) return { ok: false, reason: "response is not a JSON object" };
  const forbidden = forbiddenKey(v);
  if (forbidden) return { ok: false, reason: `response contains a field the audit API must never return (${forbidden})` };
  if (v.storage !== "in_memory" || v.scope !== "this_backend_process") return { ok: false, reason: "unexpected storage/scope" };
  if (!isStr(v.process_started_at) || Number.isNaN(Date.parse(v.process_started_at)) || !isStr(v.note)) return { ok: false, reason: "missing process metadata" };
  const counts = ["capacity", "retained", "total_recorded", "evicted"] as const;
  if (!counts.every((k) => isInt(v[k])) || !optInt(v.next_before_seq) || !optInt(v.oldest_seq) || !optInt(v.newest_seq)) return { ok: false, reason: "invalid page counters" };
  if ((v.evicted as number) !== (v.total_recorded as number) - (v.retained as number)) return { ok: false, reason: "inconsistent page counters" };
  if (!Array.isArray(v.events)) return { ok: false, reason: "events is not a list" };
  const events = v.events.map(parseAuditEvent);
  const bad = events.findIndex((e) => e === null);
  if (bad >= 0) return { ok: false, reason: `event ${bad} does not match the audit event contract` };
  const parsed = events as AuditEvent[];
  if (!parsed.every((e, i) => i === 0 || e.seq < parsed[i - 1].seq)) return { ok: false, reason: "events are not newest-first by seq" };
  return {
    ok: true,
    page: {
      events: parsed,
      next_before_seq: v.next_before_seq as number | null,
      storage: "in_memory",
      scope: "this_backend_process",
      process_started_at: v.process_started_at,
      capacity: v.capacity as number,
      retained: v.retained as number,
      total_recorded: v.total_recorded as number,
      evicted: v.evicted as number,
      oldest_seq: v.oldest_seq as number | null,
      newest_seq: v.newest_seq as number | null,
      note: v.note,
    },
  };
}

/** Classify a completed exchange with the audit route. Exported for checks. */
export function classifyAuditResponse(httpStatus: number, body: unknown, proxyErrorCode: string | null): AuditOutcome {
  const detail = isObj(body) && isStr(body.detail) ? body.detail : null;
  const proxyMessage = isObj(body) && isObj(body.proxy_error) && isStr(body.proxy_error.message) ? body.proxy_error.message : null;
  if (proxyErrorCode === "AUDIT_NOT_CONFIGURED") return { kind: "not_configured", message: proxyMessage ?? "Audit token is not configured on the console server" };
  if (proxyErrorCode) return { kind: "unreachable", code: proxyErrorCode, message: proxyMessage ?? "SATG backend is not reachable" };
  if (httpStatus === 401 || httpStatus === 403) return { kind: "auth_error", httpStatus, message: detail ?? "The backend refused the audit credential" };
  if (httpStatus === 503) return { kind: "not_configured", message: detail ?? "The backend's audit API is disabled" };
  if (httpStatus === 422) return { kind: "invalid_query", message: "The backend rejected the filter or page parameters" };
  if (httpStatus !== 200) return { kind: "malformed", httpStatus, message: `Backend responded with HTTP ${httpStatus}` };
  const parsed = parseAuditPage(body);
  return parsed.ok ? { kind: "ok", page: parsed.page } : { kind: "malformed", httpStatus, message: `Invalid audit response: ${parsed.reason}` };
}

/** Fetch one page of the backend's audit history through the proxy. Never throws. */
export async function fetchAuditEvents(query: AuditQuery): Promise<AuditOutcome> {
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) if (v !== undefined && v !== "") params.set(k, String(v));
  let res: Response;
  try {
    res = await fetch(`${AUDIT_EVENTS_PATH}?${params}`, { cache: "no-store", signal: AbortSignal.timeout(CLIENT_TIMEOUT_MS) });
  } catch (error) {
    const timeout = error instanceof DOMException && error.name === "TimeoutError";
    return { kind: "unreachable", code: timeout ? "CLIENT_TIMEOUT" : "PROXY_UNREACHABLE", message: timeout ? "No response from the console server" : "Could not reach the console server" };
  }
  const body: unknown = await res.json().catch(() => null);
  return classifyAuditResponse(res.status, body, res.headers.get("x-satg-proxy-error"));
}
