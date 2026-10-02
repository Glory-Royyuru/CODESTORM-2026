/* Assertions for the live request trace mapper (src/lib/satg/liveTrace.ts). Exits 1 on failure.
 *
 * Responses go through the real client parser (classifyResponse), so the mapper sees exactly what the Live
 * Gateway sees. The ALLOW, DEST-001 BLOCK and ML-001 ESCALATE bodies are real backend responses captured on
 * 2026-10-01 (signatures, ML feature maps and sandbox output shortened). The other cases follow the backend
 * code paths: decision_engine.py (ML-002), ingress.py (INGRESS-*), pipeline.py (canonicalization),
 * main.py (GATEWAY-001, sandbox failure) and the proxy's x-satg-proxy-error header. */
import { classifyResponse, type SatgOutcome } from "../src/lib/satg/client";
import type { SatgLogEntry } from "../src/lib/satg/log";
import { toLiveTrace, toLiveTraces, type LiveTrace } from "../src/lib/satg/liveTrace";

let failures = 0;
function check(name: string, ok: boolean) {
  if (!ok) failures++;
  console.log(`${ok ? "ok  " : "FAIL"} ${name}`);
}

const CHECKS = ["REQUEST_STRUCTURE", "TOOL_REGISTRY", "TOOL_ENABLED", "AGENT_PERMISSION", "PARAMETER_VALIDATION", "DESTINATION_VALIDATION"];
const passed = (names = CHECKS) => names.map((check) => ({ check, status: "PASSED" }));
const thresholds = { ml_mode: "required", ml_high_risk_threshold: 0.6, ml_critical_risk_threshold: 0.8 };
const notConsulted = { status: "not_consulted", mode: "required", model_version: null, feature_version: null, risk_score: null, risk_level: null, prediction: null, conformal_abstain: null, signals: {}, features: {}, top_factors: [], context_used: [], latency_ms: null, detail: null };
const mlOk = (risk_score: number, risk_level: string, prediction: string, latency_ms: number) => ({
  status: "ok", mode: "required", model_version: "satg-ml-v0.1", feature_version: "1.0", risk_score, risk_level, prediction, conformal_abstain: false,
  signals: { p_inject: 0.989 }, features: { anomaly_score: 0.991 }, top_factors: [{ feature: "p_inject", value: 0.9893, contribution: 0.3412 }],
  context_used: ["task"], latency_ms, detail: null,
});
const common = (request_id: string, request_hash: string) => ({
  agent_id: "support-bot-3", tool: "send_email", checks_not_evaluated: [], request_id, policy_version: "deterministic-core-1.2.0",
  tool_version: "1.0.0", tool_manifest_hash: "sha256:03717e9966d2a14f72189216c23261a5ae261a7acb4ccbdf1b3cf4b8e49c1ce3", request_hash,
  network: [], anomalies: [], request_integrity: null, execution: null,
});

const emailBody = (to: string) => JSON.stringify({ agent_id: "support-bot-3", tool: "send_email", parameters: { to, subject: "Status", body: "All good" }, context: { task: "Send a status update" } });

let seq = 0;
const entry = (outcome: SatgOutcome, requestBody: string, source: SatgLogEntry["source"] = "studio"): SatgLogEntry => ({ seq: ++seq, at: Date.UTC(2026, 9, 2, 9, 0, seq), presetTitle: `case ${seq}`, outcome, requestBody, source });
const verdict = (status: number, body: unknown) => classifyResponse(status, body, null, 42.5);
const stage = (t: LiveTrace, key: string) => t.stages.find((s) => s.key === key);

/* 1. Real ALLOW (send_email to ops@company.com) */
const allowBody = emailBody("ops@company.com");
const allowOutcome = verdict(200, {
  ...common("req_bda456f9965e49489bd6eceac0cca477", "sha256:bb627c8533e4ee5155bc232c883b72939d1b807b392145088fedc555ba9f74fb"),
  verdict: "ALLOW", severity: "LOW", rule_id: "BASE-001", reason: "Tool call passed basic gateway validation", stage: "gateway",
  checks: passed(),
  decision: { deterministic_verdict: "ALLOW", deterministic_rule_id: "BASE-001", final_verdict: "ALLOW", final_rule_id: "BASE-001", ...thresholds },
  ml: mlOk(0.272152, "STEP_UP", "benign", 100.6),
  request_integrity: { algorithm: "HMAC-SHA256", key_id: "satg-hmac-67e0376e7258", signed_fields: ["request_id", "agent_id", "tool", "request_hash", "tool_manifest_hash", "policy_version", "pinned_ips"], signature: "9e19c9a4937c4949" },
  execution: { sandbox_id: "satg-sbx-beaca4855b0d456d", status: "success", exit_code: 0, duration_ms: 6655.6, stdout: '{"ok": true}', stderr: "", result: { sent: true }, error: null, container_removed: true },
});
const allow = toLiveTrace(entry(allowOutcome, allowBody));
check("ALLOW: outcome is a verdict", allow.outcome === "verdict" && allowOutcome.kind === "verdict");
check("ALLOW: backend verdict preserved", allow.verdict === "ALLOW" && allow.category === "ALLOWED");
check("ALLOW: backend rule ID preserved", allow.ruleId === "BASE-001" && stage(allow, "FINAL_VERDICT")?.ruleId === "BASE-001");
check("ALLOW: six backend checks, all passed, in order", allow.stages.slice(0, 6).map((s) => `${s.key}:${s.status}`).join() === CHECKS.map((c) => `${c}:passed`).join());
check("ALLOW: deterministic decision passed (BASE-001)", stage(allow, "DETERMINISTIC_DECISION")?.status === "passed" && stage(allow, "DETERMINISTIC_DECISION")?.ruleId === "BASE-001");
check("ALLOW: ML passed with backend risk/model", stage(allow, "ML")?.status === "passed" && /risk 0\.272 .*satg-ml-v0\.1/.test(stage(allow, "ML")?.detail ?? ""));
check("ALLOW: integrity tag stage present", stage(allow, "REQUEST_INTEGRITY")?.status === "passed");
check("ALLOW: sandbox executed (success, from backend)", stage(allow, "SANDBOX")?.status === "passed" && stage(allow, "SANDBOX")?.source === "backend");
check("ALLOW: request fields come from the captured body", allow.request.parsed && allow.request.agentId === "support-bot-3" && allow.request.tool === "send_email" && (allow.request.parameters as { to: string }).to === "ops@company.com");
check("ALLOW: raw body kept byte-for-byte", allow.request.body === allowBody);
check("ALLOW: identifiers copied", allow.requestId === "req_bda456f9965e49489bd6eceac0cca477" && allow.requestHash?.startsWith("sha256:bb627c") === true && allow.policyVersion === "deterministic-core-1.2.0");
check("ALLOW: http status and round trip kept", allow.httpStatus === 200 && allow.roundTripMs === 42.5);

/* 2. Deterministic BLOCK (DEST-001), ML not consulted */
const blockBody = emailBody("attacker@evil.com");
const block = toLiveTrace(entry(verdict(200, {
  ...common("req_d363b092a49940cd8bad59f6238cf4a3", "sha256:aaa0b2421696e436a3b1666642a02323fe03e803262e2189605092f7c49d9880"),
  verdict: "BLOCK", severity: "HIGH", rule_id: "DEST-001", reason: "Destination domain 'evil.com' is not allowed", stage: "gateway",
  checks: [...passed(CHECKS.slice(0, 5)), { check: "DESTINATION_VALIDATION", status: "FAILED" }],
  decision: { deterministic_verdict: "BLOCK", deterministic_rule_id: "DEST-001", final_verdict: "BLOCK", final_rule_id: "DEST-001", ...thresholds },
  ml: notConsulted,
}), blockBody, "agent"));
check("BLOCK: backend verdict preserved", block.verdict === "BLOCK" && block.category === "BLOCKED");
check("BLOCK: failed check carries DEST-001 and the backend reason", stage(block, "DESTINATION_VALIDATION")?.status === "failed" && stage(block, "DESTINATION_VALIDATION")?.ruleId === "DEST-001" && (stage(block, "DESTINATION_VALIDATION")?.detail ?? "").includes("'evil.com' is not allowed"));
check("BLOCK: deterministic decision failed (DEST-001)", stage(block, "DETERMINISTIC_DECISION")?.status === "failed" && stage(block, "DETERMINISTIC_DECISION")?.ruleId === "DEST-001");
check("BLOCK: ML not_consulted → not_evaluated, not failed", stage(block, "ML")?.status === "not_evaluated");
check("BLOCK: ML detail says deterministic BLOCK is terminal", stage(block, "ML")?.detail === "Not evaluated — deterministic BLOCK is terminal.");
check("BLOCK: sandbox null → not_executed", stage(block, "SANDBOX")?.status === "not_executed");
check("BLOCK: no integrity stage", !stage(block, "REQUEST_INTEGRITY"));
check("BLOCK: source and request fields from captured body", block.source === "agent" && (block.request.parameters as { to: string }).to === "attacker@evil.com");

/* 3. ML ESCALATE (ML-001) */
const escalate = toLiveTrace(entry(verdict(200, {
  ...common("req_6f75dd0051834031b58aa6a26722bae8", "sha256:d4e9d26220f86138e2259d72ab3e1d213143c26542a47800bebabfcf22cf402c"),
  verdict: "ESCALATE", severity: "MEDIUM", rule_id: "ML-001", reason: "ML risk 0.667 >= high threshold 0.6; held for review; top factors: p_inject", stage: "ml",
  checks: passed(),
  decision: { deterministic_verdict: "ALLOW", deterministic_rule_id: "BASE-001", final_verdict: "ESCALATE", final_rule_id: "ML-001", ...thresholds },
  ml: mlOk(0.666667, "HUMAN_APPROVAL", "risky", 379.8),
}), emailBody("ops@company.com"), "agent"));
check("ESCALATE: backend verdict preserved", escalate.verdict === "ESCALATE" && escalate.category === "ESCALATED");
check("ESCALATE: deterministic decision passed (BASE-001)", stage(escalate, "DETERMINISTIC_DECISION")?.status === "passed" && stage(escalate, "DETERMINISTIC_DECISION")?.ruleId === "BASE-001");
check("ESCALATE: ML escalated with ML-001", stage(escalate, "ML")?.status === "escalated" && stage(escalate, "ML")?.ruleId === "ML-001");
check("ESCALATE: final verdict ML-001", stage(escalate, "FINAL_VERDICT")?.status === "escalated" && escalate.ruleId === "ML-001");
check("ESCALATE: sandbox null → not_executed", stage(escalate, "SANDBOX")?.status === "not_executed");

/* 3b. ml / decision: read-only copies of the backend's ml and decision blocks (real captured fixtures above) */
const approx = (a: number | null | undefined, b: number) => a != null && Math.abs(a - b) < 0.0005;
const allowV = allowOutcome.kind === "verdict" ? allowOutcome.verdict : null;
check("ALLOW decision: deterministic ALLOW · BASE-001, final BASE-001", allow.decision?.deterministicVerdict === "ALLOW" && allow.decision.deterministicRuleId === "BASE-001" && allow.decision.finalRuleId === "BASE-001");
check("ALLOW ml: ok · risk ≈ 0.272 · STEP_UP · satg-ml-v0.1", allow.ml?.status === "ok" && approx(allow.ml.riskScore, 0.272) && allow.ml.riskLevel === "STEP_UP" && allow.ml.modelVersion === "satg-ml-v0.1");
check("ALLOW ml/decision equal the parsed backend fields exactly", !!allowV?.ml && !!allowV.decision && allow.ml?.riskScore === allowV.ml.risk_score && allow.ml.riskLevel === allowV.ml.risk_level && allow.ml.modelVersion === allowV.ml.model_version && allow.decision?.deterministicRuleId === allowV.decision.deterministic_rule_id);
check("BLOCK decision: deterministic BLOCK · DEST-001, final DEST-001", block.decision?.deterministicVerdict === "BLOCK" && block.decision.deterministicRuleId === "DEST-001" && block.decision.finalRuleId === "DEST-001");
check("BLOCK ml: status not_consulted, no score/level/model invented", block.ml?.status === "not_consulted" && block.ml.riskScore === null && block.ml.riskLevel === null && block.ml.modelVersion === null);
check("ESCALATE decision: deterministic ALLOW · BASE-001, final ML-001", escalate.decision?.deterministicVerdict === "ALLOW" && escalate.decision.deterministicRuleId === "BASE-001" && escalate.decision.finalRuleId === "ML-001");
check("ESCALATE ml: ok · risk ≈ 0.667 · HUMAN_APPROVAL · satg-ml-v0.1", escalate.ml?.status === "ok" && approx(escalate.ml.riskScore, 0.667) && escalate.ml.riskScore === 0.666667 && escalate.ml.riskLevel === "HUMAN_APPROVAL" && escalate.ml.modelVersion === "satg-ml-v0.1");
check("ESCALATE: copied fields agree with the backend verdict (final rule = rule_id)", escalate.decision?.finalRuleId === escalate.ruleId);

/* 4. ML BLOCK (ML-002) */
const mlBlock = toLiveTrace(entry(verdict(200, {
  ...common("req_ml2", "sha256:ml2"),
  verdict: "BLOCK", severity: "HIGH", rule_id: "ML-002", reason: "ML risk 0.912 >= critical threshold 0.8", stage: "ml",
  checks: passed(),
  decision: { deterministic_verdict: "ALLOW", deterministic_rule_id: "BASE-001", final_verdict: "BLOCK", final_rule_id: "ML-002", ...thresholds },
  ml: mlOk(0.912, "QUARANTINE", "risky", 120),
}), emailBody("ops@company.com")));
check("ML-002: verdict BLOCK, ML failed with ML-002, checks all passed", mlBlock.verdict === "BLOCK" && stage(mlBlock, "ML")?.status === "failed" && stage(mlBlock, "ML")?.ruleId === "ML-002" && mlBlock.stages.slice(0, 6).every((s) => s.status === "passed"));
check("ML-002: sandbox not_executed", stage(mlBlock, "SANDBOX")?.status === "not_executed");

/* 5. Ingress rejection (INGRESS-002, HTTP 400): only the stages the response supports */
const dupBody = '{"agent_id":"support-bot-3","tool":"send_email","tool":"send_email","parameters":{}}';
const ingress = toLiveTrace(entry(verdict(400, {
  ...common("req_ing", "x"), request_hash: null, tool_version: null, tool_manifest_hash: null,
  verdict: "BLOCK", severity: "MEDIUM", rule_id: "INGRESS-002", reason: "Request body contains duplicate JSON keys", stage: "ingress",
  checks: [{ check: "REQUEST_STRUCTURE", status: "FAILED" }], ml: null, decision: null,
}), dupBody));
check("INGRESS: verdict BLOCK with INGRESS-002", ingress.verdict === "BLOCK" && ingress.ruleId === "INGRESS-002" && ingress.httpStatus === 400);
check("INGRESS: only REQUEST_STRUCTURE is a check stage", ingress.stages.filter((s) => CHECKS.includes(s.key)).map((s) => s.key).join() === "REQUEST_STRUCTURE");
check("INGRESS: no later check claimed (none evaluated or listed)", !CHECKS.slice(1).some((c) => stage(ingress, c)));
check("INGRESS: no deterministic-decision stage without a decision trace", !stage(ingress, "DETERMINISTIC_DECISION"));
check("INGRESS: ML not_evaluated (absent), sandbox not_executed", stage(ingress, "ML")?.status === "not_evaluated" && stage(ingress, "ML")?.source === "frontend" && stage(ingress, "SANDBOX")?.status === "not_executed");
check("INGRESS: no request hash claimed", ingress.requestHash === undefined);

/* 6. Canonicalization failure: later checks reported as not evaluated */
const canon = toLiveTrace(entry(verdict(200, {
  ...common("req_canon", "x"), request_hash: null,
  verdict: "BLOCK", severity: "MEDIUM", rule_id: "CANON-001", reason: "Value of parameters.body contains a disallowed control or invisible character", stage: "canonicalize",
  checks: [{ check: "REQUEST_STRUCTURE", status: "FAILED" }], checks_not_evaluated: CHECKS.slice(1), ml: null, decision: null,
}), emailBody("ops@company.com")));
check("CANON: REQUEST_STRUCTURE failed with the backend rule", stage(canon, "REQUEST_STRUCTURE")?.status === "failed" && stage(canon, "REQUEST_STRUCTURE")?.ruleId === "CANON-001");
check("CANON: five later checks not_evaluated (from checks_not_evaluated)", CHECKS.slice(1).every((c) => stage(canon, c)?.status === "not_evaluated"));

/* 7. Backend internal error (GATEWAY-001, HTTP 500) */
const internal = toLiveTrace(entry(verdict(500, {
  ...common("req_500", "sha256:x"),
  verdict: "BLOCK", severity: "HIGH", rule_id: "GATEWAY-001", reason: "Internal gateway error; request blocked", stage: "gateway",
  checks: [{ check: "GATEWAY_INTERNAL", status: "FAILED" }], ml: null, decision: null,
}), emailBody("ops@company.com")));
check("GATEWAY-001: verdict BLOCK at HTTP 500, internal check failed", internal.verdict === "BLOCK" && internal.httpStatus === 500 && stage(internal, "GATEWAY_INTERNAL")?.status === "failed" && stage(internal, "GATEWAY_INTERNAL")?.ruleId === "GATEWAY-001");

/* 8. ALLOW but the sandbox failed */
const sbx = toLiveTrace(entry(verdict(200, {
  ...common("req_sbx", "sha256:y"),
  verdict: "ALLOW", severity: "LOW", rule_id: "BASE-001", reason: "Tool call passed basic gateway validation", stage: "gateway",
  checks: passed(),
  decision: { deterministic_verdict: "ALLOW", deterministic_rule_id: "BASE-001", final_verdict: "ALLOW", final_rule_id: "BASE-001", ...thresholds },
  ml: mlOk(0.2, "ALLOW", "benign", 90),
  request_integrity: { algorithm: "HMAC-SHA256", key_id: "k", signed_fields: [], signature: "s" },
  execution: { sandbox_id: null, status: "sandbox_unavailable", exit_code: null, duration_ms: null, stdout: "", stderr: "", result: null, error: "Docker is unavailable or refused to start the sandbox; the tool was not run", container_removed: null },
}), emailBody("ops@company.com")));
check("SANDBOX FAIL: verdict stays ALLOW (backend's)", sbx.verdict === "ALLOW");
check("SANDBOX FAIL: sandbox stage failed with backend status", stage(sbx, "SANDBOX")?.status === "failed" && (stage(sbx, "SANDBOX")?.detail ?? "").startsWith("sandbox_unavailable"));

/* 9. Proxy/network failure: no verdict, no stages */
const net = toLiveTrace(entry(classifyResponse(502, { proxy_error: { code: "BACKEND_UNREACHABLE", message: "SATG backend is not reachable" } }, "BACKEND_UNREACHABLE", 12), emailBody("ops@company.com")));
check("NETWORK: no verdict invented", net.verdict === undefined && net.ruleId === undefined && net.category === "NETWORK_ERROR");
check("NETWORK: no backend stages fabricated", net.stages.length === 0);
check("NETWORK: no HTTP status claimed, error kept", net.httpStatus === undefined && net.error?.code === "BACKEND_UNREACHABLE");
check("NETWORK: request fields still from the captured body", net.request.tool === "send_email");

/* 10. Backend answered without a valid verdict */
const bad = toLiveTrace(entry(verdict(404, { detail: "Not Found" }), emailBody("ops@company.com")));
check("BACKEND ERROR: no verdict, no stages, status kept", bad.outcome === "backend_error" && bad.verdict === undefined && bad.stages.length === 0 && bad.httpStatus === 404);

/* 11. Request body that is not JSON (malformed-ingress test) */
const raw = toLiveTrace(entry(verdict(400, {
  ...common("req_raw", "x"), agent_id: null, tool: null, request_hash: null, tool_version: null, tool_manifest_hash: null,
  verdict: "BLOCK", severity: "MEDIUM", rule_id: "INGRESS-001", reason: "Request body is not valid JSON", stage: "ingress",
  checks: [{ check: "REQUEST_STRUCTURE", status: "FAILED" }], ml: null, decision: null,
}), "{not json"));
check("RAW BODY: parsed=false, no request fields invented, raw kept", !raw.request.parsed && raw.request.tool === undefined && raw.request.agentId === undefined && raw.request.body === "{not json");

/* ml / decision absent when the backend sent none (ingress, canonicalization, 500) or there is no verdict */
check("no ml/decision invented without backend blocks", [ingress, canon, internal, raw].every((t) => t.ml === undefined && t.decision === undefined));
check("no ml/decision for no-verdict outcomes", [net, bad].every((t) => t.ml === undefined && t.decision === undefined));

/* Invariants across every case */
const all = [allow, block, escalate, mlBlock, ingress, canon, internal, sbx, net, bad, raw];
check("every non-ALLOW verdict: sandbox not executed", all.filter((t) => t.verdict && t.verdict !== "ALLOW").every((t) => stage(t, "SANDBOX")?.status === "not_executed"));
check("every deterministic BLOCK: ML never evaluated", all.filter((t) => stage(t, "DETERMINISTIC_DECISION")?.status === "failed").every((t) => stage(t, "ML")?.status === "not_evaluated"));
check("final-verdict stage always mirrors the backend verdict", all.filter((t) => t.verdict).every((t) => stage(t, "FINAL_VERDICT")?.detail?.startsWith(`${t.verdict} · `)));
check("no stage claims provenance/taint/identity", all.every((t) => t.stages.every((s) => !/taint|atom|lineage|spiffe|mtls|ebpf|dlp|ed25519|trifecta/i.test(`${s.key} ${s.label} ${s.detail ?? ""}`))));
check("toLiveTraces is newest first", toLiveTraces([entry(allowOutcome, allowBody), entry(allowOutcome, allowBody)]).map((t) => t.seq).join() === `${seq},${seq - 1}`);

console.log(failures ? `\n${failures} check(s) failed` : "\nall live-trace checks passed");
process.exit(failures ? 1 : 0);
