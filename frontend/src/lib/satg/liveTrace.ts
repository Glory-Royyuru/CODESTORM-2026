/**
 * Live request trace: a read-only view of one real SATG round trip, derived
 * from a `useSatgLog` entry (the exact request body this tab sent, and the
 * backend's parsed answer).
 *
 * It decides nothing. Every stage restates a field of the backend's Verdict
 * (backend/app/models/verdict.py) or, for `source: "request"`, what the
 * browser sent. The verdict is copied from the backend, never recomputed from
 * the stages. Nothing here is provenance: the backend tracks no data lineage,
 * taint, sessions, workload identity or per-stage timing, so none appear.
 */

import { categorize, type OutcomeCategory, type SatgAnomaly, type SatgDecision, type SatgMl, type SatgNetworkInspection, type SatgVerdict, type SatgVerdictType } from "./client";
import type { SatgLogEntry } from "./log";

export type TraceStageStatus =
  | "passed"
  | "failed"
  /** ML-001 / a final ESCALATE: held for review, never executed. */
  | "escalated"
  /** The backend reports the stage did not run (checks_not_evaluated, ML not consulted or disabled). */
  | "not_evaluated"
  /** The sandbox was not started. */
  | "not_executed"
  /** ML was consulted but returned no assessment (unavailable / error). */
  | "unavailable"
  /** The response does not say. */
  | "unknown";

export interface TraceStage {
  key: string;
  label: string;
  status: TraceStageStatus;
  ruleId?: string;
  detail?: string;
  /** backend: restates a backend field. frontend: a statement about a field the backend left empty. */
  source: "backend" | "frontend";
}

/** The request exactly as this browser sent it. Self-asserted and unverified; `context` is untrusted. */
export interface TraceRequest {
  /** False when the body is not a JSON object (e.g. a malformed-ingress test); fields are then absent. */
  parsed: boolean;
  agentId?: string;
  tool?: string;
  parameters?: unknown;
  context?: unknown;
  /** The raw body, byte-for-byte what was submitted. */
  body: string;
}

export interface LiveTrace {
  seq: number;
  /** When this browser recorded the response (browser clock; the backend returns no timestamp). */
  at: string;
  source: SatgLogEntry["source"];
  title: string;
  request: TraceRequest;

  outcome: "verdict" | "backend_error" | "network_error";
  category: OutcomeCategory;
  /** Absent for network errors: no HTTP response from the backend. */
  httpStatus?: number;
  /** Browser → proxy → backend → browser, measured in the browser. */
  roundTripMs: number;
  /** The backend's verdict, copied as-is. Absent whenever there is no valid verdict. */
  verdict?: SatgVerdictType;
  ruleId?: string;
  reason?: string;
  /** Present only for backend_error / network_error. */
  error?: { code?: string; message: string };

  /** Empty when there is no valid verdict: no backend stage is claimed without one. */
  stages: TraceStage[];

  requestId?: string;
  requestHash?: string;
  policyVersion?: string;
  toolVersion?: string;
  toolManifestHash?: string;
  /** URL destinations only, as returned by the backend. */
  network: SatgNetworkInspection[];
  /** CRYPTO-* quarantine records, as returned by the backend. */
  anomalies: SatgAnomaly[];
  /** Copied from the backend's `ml` block, when the response has one. */
  ml?: { status: SatgMl["status"]; riskScore: number | null; riskLevel: string | null; modelVersion: string | null };
  /** Copied from the backend's `decision` block, when the response has one. */
  decision?: { deterministicVerdict: SatgDecision["deterministic_verdict"]; deterministicRuleId: string; finalRuleId: string };
}

/** Display names for the backend's check identifiers (backend/app/gateway/pipeline.py). Unknown names are kept raw. */
const CHECK_LABELS: Record<string, string> = {
  REQUEST_STRUCTURE: "Ingress & canonicalization",
  TOOL_REGISTRY: "Registry & manifest",
  TOOL_ENABLED: "Tool enabled",
  AGENT_PERMISSION: "Agent permission",
  PARAMETER_VALIDATION: "Parameter validation",
  DESTINATION_VALIDATION: "Destination validation",
  GATEWAY_INTERNAL: "Gateway internal",
};

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

function parseRequest(body: string): TraceRequest {
  let data: unknown;
  try {
    data = JSON.parse(body);
  } catch {
    return { parsed: false, body };
  }
  if (!isObj(data)) return { parsed: false, body };
  return {
    parsed: true,
    agentId: typeof data.agent_id === "string" ? data.agent_id : undefined,
    tool: typeof data.tool === "string" ? data.tool : undefined,
    parameters: "parameters" in data ? data.parameters : undefined,
    context: "context" in data ? data.context : undefined,
    body,
  };
}

function checkStages(v: SatgVerdict): TraceStage[] {
  const stages: TraceStage[] = v.checks.map((c) => {
    const label = CHECK_LABELS[c.check] ?? c.check;
    if (c.status === "PASSED") return { key: c.check, label, status: "passed", source: "backend" };
    // The backend stops at the first failed check, and that failure is the deterministic rule it reports.
    return {
      key: c.check,
      label,
      status: "failed",
      ruleId: v.decision?.deterministic_rule_id ?? v.rule_id,
      detail: `${v.reason} · stage ${v.stage} · severity ${v.severity}`,
      source: "backend",
    };
  });
  for (const c of v.checks_not_evaluated) {
    stages.push({ key: c, label: CHECK_LABELS[c] ?? c, status: "not_evaluated", detail: "Reported by the backend as not evaluated.", source: "backend" });
  }
  return stages;
}

function decisionStage(v: SatgVerdict): TraceStage | null {
  const d = v.decision;
  if (!d) return null;
  return {
    key: "DETERMINISTIC_DECISION",
    label: "Deterministic decision",
    status: d.deterministic_verdict === "ALLOW" ? "passed" : "failed",
    ruleId: d.deterministic_rule_id,
    detail: `${d.deterministic_verdict} · policy ${v.policy_version}`,
    source: "backend",
  };
}

function mlStage(v: SatgVerdict): TraceStage {
  const base = { key: "ML", label: "ML risk analysis" };
  const ml = v.ml;
  if (!ml) return { ...base, status: "not_evaluated", detail: "No ML assessment in the backend response.", source: "frontend" };
  if (ml.status === "not_consulted") {
    return { ...base, status: "not_evaluated", detail: "Not evaluated — deterministic BLOCK is terminal.", source: "backend" };
  }
  if (ml.status === "disabled") return { ...base, status: "not_evaluated", detail: `ML layer disabled (ML_MODE=${ml.mode}).`, source: "backend" };
  if (ml.status !== "ok") {
    // ML-003: ML_MODE=required and no usable assessment → the backend blocked (fail closed).
    const failClosed = v.rule_id === "ML-003";
    return {
      ...base,
      status: failClosed ? "failed" : "unavailable",
      ruleId: failClosed ? "ML-003" : undefined,
      detail: `ML ${ml.status}${ml.detail ? `: ${ml.detail}` : ""} · ML_MODE=${ml.mode}${failClosed ? " · blocked, fail closed" : " · deterministic decision kept"}`,
      source: "backend",
    };
  }
  const thresholds = v.decision ? ` · escalate ≥ ${v.decision.ml_high_risk_threshold} · block ≥ ${v.decision.ml_critical_risk_threshold}` : "";
  const latency = ml.latency_ms !== null ? ` · ${ml.latency_ms} ms` : "";
  const detail = `risk ${ml.risk_score?.toFixed(3) ?? "—"} · level ${ml.risk_level ?? "—"} · ${ml.model_version ?? "model ?"}${thresholds}${latency}`;
  if (v.rule_id === "ML-002") return { ...base, status: "failed", ruleId: "ML-002", detail, source: "backend" };
  if (v.rule_id === "ML-001") return { ...base, status: "escalated", ruleId: "ML-001", detail, source: "backend" };
  return { ...base, status: "passed", detail, source: "backend" };
}

function finalStage(v: SatgVerdict): TraceStage {
  return {
    key: "FINAL_VERDICT",
    label: "Final verdict",
    status: v.verdict === "ALLOW" ? "passed" : v.verdict === "ESCALATE" ? "escalated" : "failed",
    ruleId: v.rule_id,
    detail: `${v.verdict} · ${v.reason}`,
    source: "backend",
  };
}

function integrityStage(v: SatgVerdict): TraceStage | null {
  const i = v.request_integrity;
  if (!i) return null;
  return { key: "REQUEST_INTEGRITY", label: "Request integrity", status: "passed", detail: `${i.algorithm} tag issued · key ${i.key_id}`, source: "backend" };
}

function sandboxStage(v: SatgVerdict): TraceStage {
  const base = { key: "SANDBOX", label: "Docker sandbox" };
  const e = v.execution;
  if (!e) {
    // Only a final ALLOW reaches the sandbox, and the backend reports an execution result for every ALLOW.
    return v.verdict === "ALLOW"
      ? { ...base, status: "unknown", detail: "ALLOW, but the backend response reports no execution result.", source: "frontend" }
      : { ...base, status: "not_executed", detail: `Not executed — ${v.verdict} never reaches the sandbox.`, source: "frontend" };
  }
  const facts = [e.status, e.exit_code !== null ? `exit ${e.exit_code}` : null, e.duration_ms !== null ? `${e.duration_ms} ms` : null, e.error].filter(Boolean).join(" · ");
  if (e.status === "success") return { ...base, status: "passed", detail: facts, source: "backend" };
  if (e.status === "not_executed") return { ...base, status: "not_executed", detail: facts, source: "backend" };
  return { ...base, status: "failed", detail: facts, source: "backend" };
}

function stagesFor(v: SatgVerdict): TraceStage[] {
  return [
    ...checkStages(v),
    decisionStage(v),
    mlStage(v),
    finalStage(v),
    integrityStage(v),
    sandboxStage(v),
  ].filter((s): s is TraceStage => s !== null);
}

/** Derive the trace for one logged round trip. Pure: same entry in, same trace out. */
export function toLiveTrace(entry: SatgLogEntry): LiveTrace {
  const o = entry.outcome;
  const common = {
    seq: entry.seq,
    at: new Date(entry.at).toISOString(),
    source: entry.source,
    title: entry.presetTitle,
    request: parseRequest(entry.requestBody),
    category: categorize(o),
    roundTripMs: o.roundTripMs,
  };
  if (o.kind === "network_error") {
    return { ...common, outcome: "network_error", error: { code: o.code, message: o.message }, stages: [], network: [], anomalies: [] };
  }
  if (o.kind === "backend_error") {
    return { ...common, outcome: "backend_error", httpStatus: o.httpStatus, error: { message: o.message }, stages: [], network: [], anomalies: [] };
  }
  const v = o.verdict;
  return {
    ...common,
    outcome: "verdict",
    httpStatus: o.httpStatus,
    verdict: v.verdict,
    ruleId: v.rule_id,
    reason: v.reason,
    stages: stagesFor(v),
    requestId: v.request_id,
    requestHash: v.request_hash ?? undefined,
    policyVersion: v.policy_version,
    toolVersion: v.tool_version ?? undefined,
    toolManifestHash: v.tool_manifest_hash ?? undefined,
    network: v.network,
    anomalies: v.anomalies,
    ml: v.ml ? { status: v.ml.status, riskScore: v.ml.risk_score, riskLevel: v.ml.risk_level, modelVersion: v.ml.model_version } : undefined,
    decision: v.decision ? { deterministicVerdict: v.decision.deterministic_verdict, deterministicRuleId: v.decision.deterministic_rule_id, finalRuleId: v.decision.final_rule_id } : undefined,
  };
}

/** Newest first. */
export function toLiveTraces(entries: readonly SatgLogEntry[]): LiveTrace[] {
  return entries.map(toLiveTrace).reverse();
}
