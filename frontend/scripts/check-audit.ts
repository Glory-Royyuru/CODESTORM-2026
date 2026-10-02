/* Assertions for the live audit client (src/lib/satg/audit.ts) and the audit proxy route (src/lib/satg/proxy.ts). Exits 1 on failure.
 *
 * Fixtures follow backend/app/audit/api.py's AuditPage model; the ALLOW / DEST-001 / ML-001 values are those of real backend
 * responses. The proxy is exercised against a local stand-in HTTP server to see exactly what it forwards. */
import { createServer, type IncomingMessage } from "node:http";
import type { AddressInfo } from "node:net";
import { classifyAuditResponse, parseAuditPage, type AuditPage } from "../src/lib/satg/audit";
import { forwardAuditEvents, pickAuditQuery } from "../src/lib/satg/proxy";

let failures = 0;
function check(name: string, ok: boolean) {
  if (!ok) failures++;
  console.log(`${ok ? "ok  " : "FAIL"} ${name}`);
}

const CHECKS = ["REQUEST_STRUCTURE", "TOOL_REGISTRY", "TOOL_ENABLED", "AGENT_PERMISSION", "PARAMETER_VALIDATION", "DESTINATION_VALIDATION"];
const thresholds = { ml_mode: "required", ml_high_risk_threshold: 0.6, ml_critical_risk_threshold: 0.8 };
const base = (seq: number, request_id: string) => ({
  seq, timestamp: `2026-10-02T09:00:0${seq}.000000+00:00`, request_id, severity: "LOW", stage: "gateway",
  agent_id: "support-bot-3", tool: "send_email", authenticated: false, auth_method: "self_asserted",
  checks: CHECKS.map((check) => ({ check, status: "PASSED" })), checks_not_evaluated: [] as string[], policy_version: "deterministic-core-1.2.0",
  tool_version: "1.0.0", tool_manifest_hash: "sha256:03717e99", request_hash: `sha256:${request_id}`,
  execution: null as unknown, request_integrity: null as unknown, network: [] as unknown[], anomalies: [] as unknown[],
});
const escalate = {
  ...base(3, "req_6f75dd0051834031b58aa6a26722bae8"), verdict: "ESCALATE", severity: "MEDIUM", rule_id: "ML-001", stage: "ml",
  reason: "ML risk 0.667 >= high threshold 0.6; held for review",
  decision: { deterministic_verdict: "ALLOW", deterministic_rule_id: "BASE-001", final_verdict: "ESCALATE", final_rule_id: "ML-001", ...thresholds },
  ml: { status: "ok", mode: "required", model_version: "satg-ml-v0.1", risk_score: 0.666667, risk_level: "HUMAN_APPROVAL", prediction: "risky", latency_ms: 379.8, context_used: ["task", "observation"] },
};
const block = {
  ...base(2, "req_d363b092a49940cd8bad59f6238cf4a3"), verdict: "BLOCK", severity: "HIGH", rule_id: "DEST-001", reason: "Destination domain 'evil.com' is not allowed",
  checks: [...CHECKS.slice(0, 5).map((check) => ({ check, status: "PASSED" })), { check: "DESTINATION_VALIDATION", status: "FAILED" }],
  decision: { deterministic_verdict: "BLOCK", deterministic_rule_id: "DEST-001", final_verdict: "BLOCK", final_rule_id: "DEST-001", ...thresholds },
  ml: { status: "not_consulted", mode: "required", model_version: null, risk_score: null, risk_level: null, prediction: null, latency_ms: null, context_used: [] },
};
const allow = {
  ...base(1, "req_bda456f9965e49489bd6eceac0cca477"), verdict: "ALLOW", rule_id: "BASE-001", reason: "Tool call passed basic gateway validation",
  decision: { deterministic_verdict: "ALLOW", deterministic_rule_id: "BASE-001", final_verdict: "ALLOW", final_rule_id: "BASE-001", ...thresholds },
  ml: { status: "ok", mode: "required", model_version: "satg-ml-v0.1", risk_score: 0.272152, risk_level: "STEP_UP", prediction: "benign", latency_ms: 100.6, context_used: ["task"] },
  request_integrity: { algorithm: "HMAC-SHA256", key_id: "satg-hmac-67e0376e7258", signed_fields: ["request_id", "agent_id", "tool"] },
  execution: { status: "success", sandbox_id: "satg-sbx-beaca4855b0d456d", exit_code: 0, duration_ms: 6655.6, container_removed: true, stdout_sha256: "b7766a71", stdout_bytes: 209, stderr_sha256: "e3b0c442", stderr_bytes: 0, error_code: null, error_summary: null },
  network: [{ parameter: "url", url: "https://docs.example.com/q3", url_query_removed: true, requested_host: "docs.example.com", registrable_domain: "example.com", resolved_ips: ["93.184.216.34"], pinned_ip: "93.184.216.34", checks: [{ check: "SCHEME_HTTPS", status: "PASSED", detail: "scheme https" }] }],
};
const page = (events: unknown[], extra: Record<string, unknown> = {}) => ({
  events, next_before_seq: null, storage: "in_memory", scope: "this_backend_process", process_started_at: "2026-10-02T08:59:00.000000+00:00",
  capacity: 10000, retained: 3, total_recorded: 3, evicted: 0, oldest_seq: 1, newest_seq: 3,
  note: "In-memory audit history of this backend process since it started, up to its capacity. Not persistent, signed or shared between workers; a restart starts empty.",
  ...extra,
});
const clone = <T>(v: T): T => JSON.parse(JSON.stringify(v));
const parsedOk = (v: unknown): AuditPage | null => { const r = parseAuditPage(v); return r.ok ? r.page : null; };
const rejected = (v: unknown, why: RegExp) => { const r = parseAuditPage(v); return !r.ok && why.test(r.reason); };

/* Valid pages */
const good = parsedOk(page([escalate, block, allow]));
check("valid page parses", good !== null && good.events.length === 3);
check("verdicts and rules copied as sent", good?.events.map((e) => `${e.verdict}:${e.rule_id}`).join() === "ESCALATE:ML-001,BLOCK:DEST-001,ALLOW:BASE-001");
check("ESCALATE: deterministic ALLOW, ML ok 0.667 HUMAN_APPROVAL, no execution", good?.events[0].decision?.deterministic_verdict === "ALLOW" && good.events[0].ml?.risk_score === 0.666667 && good.events[0].ml.risk_level === "HUMAN_APPROVAL" && good.events[0].execution === null);
check("BLOCK: ML not_consulted with no score, no execution", good?.events[1].ml?.status === "not_consulted" && good.events[1].ml.risk_score === null && good.events[1].execution === null);
check("ALLOW: execution and integrity metadata kept", good?.events[2].execution?.status === "success" && good.events[2].request_integrity?.key_id === "satg-hmac-67e0376e7258");
check("network check detail is allowed", good?.events[2].network[0].checks[0].detail === "scheme https");
check("empty page parses", parsedOk(page([], { retained: 0, total_recorded: 0, oldest_seq: null, newest_seq: null })) !== null);

/* Fields the API must never return */
const withKey = (mutate: (p: ReturnType<typeof page>) => void) => { const p = clone(page([escalate, block, allow])); mutate(p); return p; };
check("rejects ml.features", rejected(withKey((p) => ((p.events[0] as typeof escalate).ml as Record<string, unknown>).features = { p_inject: 0.9 }), /ml\.features/));
check("rejects ml.top_factors", rejected(withKey((p) => ((p.events[0] as typeof escalate).ml as Record<string, unknown>).top_factors = []), /top_factors/));
check("rejects ml.detail", rejected(withKey((p) => ((p.events[0] as typeof escalate).ml as Record<string, unknown>).detail = "inference failed"), /ml\.detail/));
check("rejects an HMAC signature", rejected(withKey((p) => ((p.events[2] as typeof allow).request_integrity as Record<string, unknown>).signature = "9e19c9a4"), /signature/));
check("rejects request parameters", rejected(withKey((p) => ((p.events[2] as Record<string, unknown>).parameters = { to: "x@company.com" })), /parameters/));
check("rejects context", rejected(withKey((p) => ((p.events[2] as Record<string, unknown>).context = { task: "x" })), /context/));
check("rejects raw execution stdout/error", rejected(withKey((p) => ((p.events[2] as typeof allow).execution as Record<string, unknown>).error = "not_found: ava@northwind.io"), /error/));
check("rejects the anomaly hex snippet", rejected(withKey((p) => (p.events[2] as Record<string, unknown>).anomalies = [{ quarantined_hex_snippet: "00ff" }]), /quarantined_hex_snippet/));
check("rejects a raw requested_url", rejected(withKey((p) => (((p.events[2] as typeof allow).network[0]) as Record<string, unknown>).requested_url = "https://x/?token=1"), /requested_url/));

/* Contract and invariants */
check("rejects an unknown verdict", rejected(page([{ ...escalate, verdict: "MAYBE" }, block, allow]), /event 0/));
check("rejects execution on a non-ALLOW", rejected(page([escalate, { ...block, execution: allow.execution }, allow]), /event 1/));
check("rejects an integrity tag on ESCALATE", rejected(page([{ ...escalate, request_integrity: allow.request_integrity }, block, allow]), /event 0/));
check("rejects a decision trace that disagrees with the verdict", rejected(page([{ ...escalate, decision: { ...escalate.decision, final_verdict: "ALLOW" } }, block, allow]), /event 0/));
check("rejects persistent/distributed storage claims", rejected(page([escalate, block, allow], { storage: "postgres" }), /storage/) && rejected(page([escalate, block, allow], { scope: "cluster" }), /scope/));
check("rejects inconsistent counters", rejected(page([escalate, block, allow], { evicted: 5 }), /inconsistent/));
check("rejects events that are not newest first", rejected(page([allow, block, escalate]), /newest-first/));
check("rejects an ML risk outside [0, 1]", rejected(page([{ ...escalate, ml: { ...escalate.ml, risk_score: 1.5 } }, block, allow]), /event 0/));
check("rejects a non-object body", rejected("nope", /not a JSON object/));

/* Classification of what came back */
check("200 + valid page → ok", classifyAuditResponse(200, page([escalate, block, allow]), null).kind === "ok");
check("200 + invalid page → malformed, nothing shown", classifyAuditResponse(200, withKey((p) => ((p.events[0] as typeof escalate).ml as Record<string, unknown>).signals = {}), null).kind === "malformed");
check("401 → auth_error", classifyAuditResponse(401, { detail: "Missing or invalid audit API token" }, null).kind === "auth_error");
check("503 from backend → not_configured", classifyAuditResponse(503, { detail: "Audit API is disabled" }, null).kind === "not_configured");
check("proxy AUDIT_NOT_CONFIGURED → not_configured", classifyAuditResponse(503, { proxy_error: { code: "AUDIT_NOT_CONFIGURED", message: "m" } }, "AUDIT_NOT_CONFIGURED").kind === "not_configured");
check("proxy BACKEND_UNREACHABLE → unreachable", classifyAuditResponse(502, { proxy_error: { code: "BACKEND_UNREACHABLE", message: "m" } }, "BACKEND_UNREACHABLE").kind === "unreachable");
check("422 → invalid_query", classifyAuditResponse(422, { detail: [] }, null).kind === "invalid_query");
check("500 → malformed", classifyAuditResponse(500, null, null).kind === "malformed");

/* Proxy: query allowlist */
const picked = pickAuditQuery(new URLSearchParams("limit=5&verdict=BLOCK&verdict=ALLOW&token=abc&url=http://x&request_id=&tool=" + "t".repeat(300) + "&agent_id=support-bot-3"));
check("proxy forwards only known query parameters", picked.toString() === "limit=5&verdict=BLOCK&agent_id=support-bot-3");

/* Proxy: token added server-side, only to the backend */
async function proxyChecks() {
  const seen: { url?: string; auth?: string } = {};
  const server = createServer((req: IncomingMessage, res) => {
    seen.url = req.url;
    seen.auth = req.headers.authorization;
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify(page([escalate, block, allow])));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;
  process.env.SATG_BACKEND_URL = `http://127.0.0.1:${port}`;

  delete process.env.SATG_AUDIT_API_TOKEN;
  const missing = await forwardAuditEvents(new URLSearchParams("limit=5"));
  check("no console-side token → 503 AUDIT_NOT_CONFIGURED, backend not called", missing.status === 503 && missing.headers.get("x-satg-proxy-error") === "AUDIT_NOT_CONFIGURED" && seen.url === undefined);

  const token = "console-side-token-0123456789abcdefXYZ";
  process.env.SATG_AUDIT_API_TOKEN = token;
  const res = await forwardAuditEvents(new URLSearchParams("limit=5&verdict=BLOCK&secret=1"));
  const text = await res.text();
  check("proxy adds the bearer token on the backend request", seen.auth === `Bearer ${token}`);
  check("proxy calls only /v1/audit/events with the filtered query", seen.url === "/v1/audit/events?limit=5&verdict=BLOCK");
  check("token is not in the response to the browser", res.status === 200 && !text.includes(token) && ![...res.headers.values()].some((h) => h.includes(token)));
  server.close();

  process.env.SATG_BACKEND_URL = "http://127.0.0.1:9";
  const down = await forwardAuditEvents(new URLSearchParams());
  check("backend down → BACKEND_UNREACHABLE", down.headers.get("x-satg-proxy-error") === "BACKEND_UNREACHABLE");
}

proxyChecks().then(() => {
  console.log(failures ? `\n${failures} check(s) failed` : "\nall live-audit checks passed");
  process.exit(failures ? 1 : 0);
});
