import { MITIGATION, quarantineScan, type QuarantineScan } from "./anomaly/guard";
import { AnomalyLedger, quarantineEnvelope } from "./anomaly/ledger";
import { generateSigningKey, signText, type SigningKey } from "./crypto";
import { decodeLayers, type DecodeReport } from "./decoder";
import { inspectResponse } from "./dlp";
import { IngressError, normalize, RateLimiter } from "./ingress";
import { MlPipeline } from "./ml";
import { newEbpfState } from "./network/ebpf";
import { inspectDestination } from "./network/firewall";
import { attestWorkload, generateIntegrityKey, signRequest, verifyRequest, type IntegrityKey, type RequestIntegrityTag } from "./network/identity";
import { SimulatedDns } from "./network/resolver";
import {
  argsDigest,
  DEFAULT_BUNDLE,
  evaluatePolicies,
  grantIsValid,
  grantSigningText,
} from "./policy";
import { GENESIS_HASH, signReceipt } from "./receipts";
import { manifestHash, rugPullManifest, scanManifest, seedRegistry } from "./registry";
import { executeInSandbox } from "./sandbox";
import { OWNERSHIP } from "./scenarios";
import { extractAtoms, isPrivate, isUntrusted, join, joinAll, matchAtoms, sourceLabel } from "./taint";
import type {
  ApprovalRequest,
  Capability,
  CapabilityGrant,
  DataAtom,
  DlpResult,
  GatewayMode,
  LedgerEntry,
  MlScores,
  PipelineResult,
  PolicyBundle,
  Principal,
  RegisteredTool,
  RuleFinding,
  SandboxResult,
  SessionState,
  StageId,
  StageResult,
  TaintLattice,
  ToolCallEnvelope,
  ToolManifest,
  Verdict,
} from "./types";
import { hashSeed, maxVerdict, mulberry32, round, severity, sha256Hex, shortId, stringLeaves, uuid } from "./util";

export interface CallRequest {
  raw: string;
  sessionId: string;
  rugPull?: boolean;
  advertisedManifest?: ToolManifest;
  grantId?: string;
  scriptedOutput?: string;
  /** Scripted tool misbehaviour inside the sandbox (see ScenarioStep.socket). */
  socket?: "direct" | "rebind";
  groundTruth: "attack" | "benign";
  scenario?: string;
  now?: number;
}

const EGRESS_CAPS: Capability[] = ["email:send", "chat:post", "payments:transfer"];

export const STAGE_LABELS: Record<StageId, string> = {
  ingress: "Ingress",
  canonicalize: "Canonicalize",
  registry: "Registry",
  policy: "Policy",
  ml: "ML Scoring",
  fusion: "Decision Fusion",
  sandbox: "Sandbox",
  dlp: "DLP",
  receipt: "Receipt",
};

/** Modeled per-stage cost (ms) of the production Go/OPA/ONNX stack. */
const STAGE_BASE_MS: Record<StageId, [number, number]> = {
  ingress: [0.3, 0.25],
  canonicalize: [0.45, 0.4],
  registry: [0.35, 0.3],
  policy: [2.6, 1.8],
  ml: [17, 13],
  fusion: [0.12, 0.1],
  sandbox: [0, 0],
  dlp: [0.8, 0.7],
  receipt: [0.6, 0.35],
};

const EMPTY_SCORES: MlScores = { p_injection: 0, p_misaligned: 0, isolation_forest_anomaly: 0, trigram_surprise: 0, cusum_shift: 0 };

export class Gateway {
  readonly key: SigningKey;
  registry: Map<string, RegisteredTool>;
  sessions = new Map<string, SessionState>();
  bundle: PolicyBundle;
  ledger: LedgerEntry[] = [];
  approvals: ApprovalRequest[] = [];
  grants = new Map<string, CapabilityGrant>();
  mode: GatewayMode = "ENFORCING";
  modeChangedAt = 0;
  mlEnabled = true;
  readonly ephemeral: boolean;
  /** Append-only store of quarantined crypt-arithmetic anomalies (own pub/sub). */
  readonly anomalies = new AnomalyLedger();
  readonly dns = new SimulatedDns();
  /** Gateway secret for application request-integrity HMACs. */
  readonly integrityKey: IntegrityKey = generateIntegrityKey();
  private rate = new RateLimiter(20, 2);
  private ml = new MlPipeline();
  private listeners = new Set<() => void>();
  version = 0;

  constructor(opts: { ephemeral?: boolean; bundle?: PolicyBundle; key?: SigningKey; now?: number } = {}) {
    this.ephemeral = !!opts.ephemeral;
    this.key = opts.key ?? generateSigningKey();
    this.bundle = structuredClone(opts.bundle ?? DEFAULT_BUNDLE);
    this.registry = seedRegistry(opts.now ?? Date.now());
  }

  /* ---------- subscription (useSyncExternalStore) ---------- */

  subscribe = (fn: () => void) => {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  };
  getVersion = () => this.version;
  emit() {
    this.version++;
    this.listeners.forEach((l) => l());
  }

  /* ---------- sessions ---------- */

  createSession(principal: Principal, goal: string, scopes: Capability[], opts: { title?: string; scenario?: string; now?: number } = {}) {
    const now = opts.now ?? Date.now();
    const id = shortId("sess");
    const promptId = `${id}:prompt`;
    const token = { token: `tt_${uuid().replace(/-/g, "")}`, scopes, sessionId: id, issuedAt: now, expiresAt: now + 300_000 };
    const session: SessionState = {
      id,
      principal,
      goal,
      title: opts.title ?? goal,
      scenario: opts.scenario,
      startedAt: now,
      flags: { privateData: false, untrustedContent: false, outboundChannel: scopes.some((s) => EGRESS_CAPS.includes(s)) },
      atoms: [],
      nodes: [
        { id: promptId, kind: "prompt", label: "User prompt", sublabel: goal, step: 0, taint: "TRUSTED", atoms: [], payload: { goal, user: principal.userId } },
      ],
      edges: [],
      egress: { rowsOut: 0, bytesOut: 0, maxRows: 50, maxBytes: 32768, ewmaBytes: 0, outboundCalls: 0 },
      toolHistory: [],
      cusum: 0,
      step: 0,
      quarantined: false,
      token,
      ebpf: newEbpfState(32768),
      identity: attestWorkload(principal, token.token, now),
    };
    this.sessions.set(id, session);
    return session;
  }

  refreshToken(sessionId: string, now = Date.now()) {
    const s = this.sessions.get(sessionId);
    if (s) s.token = { ...s.token, token: `tt_${uuid().replace(/-/g, "")}`, issuedAt: now, expiresAt: now + 300_000 };
  }

  /* ---------- the pipeline ---------- */

  process(req: CallRequest): PipelineResult {
    const now = req.now ?? Date.now();
    const session = this.sessions.get(req.sessionId);
    if (!session) throw new Error(`unknown session ${req.sessionId}`);
    const envId = uuid();
    const rnd = mulberry32(hashSeed(envId));
    const stages: StageResult[] = [];
    const lat: Partial<Record<StageId, number>> = {};
    const t0 = typeof performance !== "undefined" ? performance.now() : 0;
    let tMark = t0;

    const stage = (id: StageId, status: StageResult["status"], detail: string) => {
      const tNow = typeof performance !== "undefined" ? performance.now() : 0;
      const [base, jitter] = STAGE_BASE_MS[id];
      const measured = Math.max(0, tNow - tMark);
      tMark = tNow;
      const ms = status === "skip" ? 0 : round(base + rnd() * jitter + Math.min(measured, 2), 2);
      lat[id] = ms;
      stages.push({ stage: id, label: STAGE_LABELS[id], latencyMs: ms, status, detail });
    };

    const findings: RuleFinding[] = [];
    const env: ToolCallEnvelope = {
      id: envId,
      protocol: "MCP",
      sessionId: session.id,
      principal: session.principal,
      userGoal: session.goal,
      rawPayload: req.raw,
      tool: "∅",
      arguments: {},
      taskToken: session.token,
      grantId: req.grantId,
      receivedAt: now,
    };

    /* Phase 0 — Ingress (M1) */
    let ingressOk = true;
    let ingressDetail = "";
    let scan: QuarantineScan | null = null;
    const fingerprints: string[] = [];
    if (this.mode === "FAIL_CLOSED") {
      ingressOk = false;
      findings.push({ ruleId: "kill_switch", ruleVersion: "1.0.0", module: "M1", outcome: "BLOCK", reason: "global emergency kill switch engaged — gateway FAIL_CLOSED", counterfactual: "If the kill switch were disengaged, the call would be evaluated normally." });
    } else if (!this.ephemeral && !this.rate.take(session.principal.agentId, now)) {
      ingressOk = false;
      findings.push({ ruleId: "rate_limit", ruleVersion: "1.0.0", module: "M1", outcome: "BLOCK", reason: `token bucket exhausted for ${session.principal.agentId} (20 burst / 2 per s)`, counterfactual: "If the agent had stayed under its rate limit, the call would be evaluated." });
    } else if ((scan = quarantineScan(req.raw)).anomalies.length) {
      // Crypt-arithmetic quarantine: refused before any JSON / numeric deserialization.
      ingressOk = false;
      env.tool = scan.claimedTool ?? "∅";
      for (const a of scan.anomalies) {
        const fp = `sha256:${sha256Hex(a.raw)}`;
        fingerprints.push(fp);
        findings.push({
          ruleId: `quarantine.${a.type.toLowerCase()}@${a.location}`,
          ruleVersion: "1.0.0",
          module: "M1",
          outcome: "BLOCK",
          reason: `${a.type} at ${a.location}: ${a.detail} → ${MITIGATION[a.type]}`,
          counterfactual: `If the value with anomaly_fingerprint ${fp} were a canonical, in-range encoding, the payload would be parsed and evaluated.`,
        });
      }
      ingressDetail = `quarantined ${scan.anomalies.length} crypt-arithmetic anomal${scan.anomalies.length > 1 ? "ies" : "y"} before parsing → HARD_DENY`;
    } else {
      try {
        const n = normalize(req.raw, { maxDepth: 16, maxBytes: 256 * 1024 });
        env.protocol = n.protocol;
        env.tool = n.tool;
        env.arguments = n.arguments;
      } catch (e) {
        ingressOk = false;
        const err = e as IngressError;
        findings.push({ ruleId: `ingress.${(err.code ?? "SYNTAX").toLowerCase()}`, ruleVersion: "1.0.0", module: "M1", outcome: "BLOCK", reason: err.message, counterfactual: "If the payload were well-formed strict JSON within size/depth limits, it would be evaluated." });
      }
    }
    stage("ingress", ingressOk ? "pass" : "fail", ingressOk ? `${env.protocol} envelope · quarantine scan clean · strict JSON · rate-limit OK` : ingressDetail || findings[0].reason);

    const tool = ingressOk ? this.registry.get(env.tool) : undefined;
    let decodes: (DecodeReport & { path: string })[] = [];
    let matched: { atom: DataAtom; path: string }[] = [];
    let scores: MlScores = EMPTY_SCORES;
    let riskScore = 0;
    let contributions: LedgerEntry["receipt"]["body"]["contributions"] = [];
    let mlVerdict: Verdict = "ALLOW";
    let abstained = false;
    let nextCusum = session.cusum;
    let grantOk = false;

    if (!ingressOk) {
      (["canonicalize", "registry", "policy", "ml", "fusion"] as StageId[]).forEach((s) => stage(s, "skip", "halted at ingress"));
    } else {
      /* Phase 1 — Canonicalize (NFKC + bounded decode chain) */
      const sp = this.bundle.rules.find((r) => r.id === "param_smuggling")?.params ?? {};
      decodes = stringLeaves(env.arguments).map((l) => ({
        ...decodeLayers(l.value, Number(sp.max_layers ?? 4), Number(sp.expansion_cap ?? 10)),
        path: l.path,
      }));
      const layered = decodes.filter((d) => d.layers.length);
      stage(
        "canonicalize",
        layered.some((d) => d.disagreement || d.hitLayerLimit) ? "warn" : "pass",
        layered.length ? `decoded ${layered.map((d) => `${d.path}: ${d.layers.join("→")}`).join("; ")}` : "NFKC normalized · no encoded layers",
      );

      /* Phase 2 — Registry (M2) */
      if (!tool) {
        findings.push({ ruleId: "registry.unknown_tool", ruleVersion: "1.0.0", module: "M2", outcome: "BLOCK", reason: `tool "${env.tool}" is not registered`, counterfactual: "If the tool were registered and pinned, the call could be evaluated." });
        stage("registry", "fail", `unregistered tool ${env.tool}`);
      } else {
        const advertised = req.advertisedManifest ?? (req.rugPull ? rugPullManifest(tool.pinnedManifest) : undefined);
        if (advertised) {
          env.advertisedManifest = advertised;
          const h = manifestHash(advertised);
          if (h !== tool.pinnedHash && !this.ephemeral) this.markDrift(tool, advertised, h, now);
          else if (h !== tool.pinnedHash) {
            tool.currentHash = h;
            tool.status = "QUARANTINED";
          }
        }
        tool.calls++;
        stage(
          "registry",
          tool.status === "VERIFIED" ? "pass" : "fail",
          tool.status === "VERIFIED" ? `pinned ${tool.pinnedHash.slice(0, 12)}… · tier ${tool.tier}` : `${tool.status}: ${tool.findings.map((f) => f.kind).join(", ") || "hash drift"}`,
        );
      }

      /* Phase 3 — Deterministic policy (M3/M4/M5) */
      if (tool) {
        matched = matchAtoms(env.arguments, session.atoms);
        if (session.quarantined)
          findings.push({ ruleId: "session_quarantine", ruleVersion: "1.0.0", module: "M5", outcome: "QUARANTINE", reason: "session is quarantined after a confirmed compromise signal", counterfactual: "A new, clean session would be required." });
        findings.push(
          ...evaluatePolicies(this.bundle, {
            env,
            tool,
            session,
            decodes,
            matched,
            grants: this.grants,
            ownership: OWNERSHIP,
            publicKeyHex: this.key.publicKeyHex,
            now,
          }),
        );
        const g = env.grantId ? this.grants.get(env.grantId) : undefined;
        grantOk = !!g && grantIsValid(g, env, this.key.publicKeyHex, now);
        if (env.grantId && !grantOk && tool.tier !== 4)
          findings.push({ ruleId: "capability_grant", ruleVersion: "1.0.0", module: "M3", outcome: "BLOCK", reason: `capability grant ${env.grantId} is ${g?.used ? "already consumed (single-use)" : "invalid or expired"}`, counterfactual: "A fresh, unconsumed, args-bound grant would be required." });
        const hard = findings.filter((f) => severity(f.outcome) >= severity("STEP_UP"));
        stage("policy", hard.length ? "fail" : findings.length ? "warn" : "pass", hard.length ? `${hard.length} rule(s) fired: ${hard.map((f) => f.ruleId).join(", ")}` : `${this.bundle.rules.filter((r) => r.enabled).length} rules passed`);

        /* Phase 4 — ML intelligence (M6) */
        if (this.mlEnabled) {
          const ml = this.ml.score(env, tool, session, matched);
          ({ scores, riskScore, contributions, mlVerdict, abstained } = ml);
          nextCusum = ml.nextCusum;
          stage("ml", severity(mlVerdict) >= severity("STEP_UP") ? "warn" : "pass", `risk ${riskScore.toFixed(3)} → ${mlVerdict}${abstained ? " (conformal abstain)" : ""}`);
        } else stage("ml", "skip", "ML disabled by operator (deterministic-only)");
      } else {
        stage("policy", "skip", "no registered tool");
        stage("ml", "skip", "no registered tool");
      }
    }

    /* Phase 5 — Monotonic decision fusion (M7) */
    const detVerdict = maxVerdict(...findings.map((f) => f.outcome));
    let effectiveMl: Verdict = mlVerdict;
    let effectiveDet: Verdict = detVerdict;
    if (grantOk) {
      // A valid human grant satisfies approval-type escalations, never hard vetoes.
      const cap = (v: Verdict): Verdict => (v === "STEP_UP" || v === "HUMAN_APPROVAL" ? "MONITOR" : v);
      effectiveMl = cap(mlVerdict);
      effectiveDet = cap(detVerdict);
    }
    let verdict = maxVerdict(effectiveDet, effectiveMl);
    if (ingressOk)
      stage(
        "fusion",
        severity(verdict) >= severity("STEP_UP") ? "fail" : "pass",
        severity(mlVerdict) < severity(detVerdict)
          ? `rules=${detVerdict} · ML=${mlVerdict} (ML cannot loosen) → ${verdict}`
          : `rules=${detVerdict} · ML=${mlVerdict} → ${verdict}`,
      );

    /* Phase 6/7 — Sandbox (M8) + DLP (M9) */
    let sandbox: SandboxResult | null = null;
    let dlp: DlpResult | null = null;
    const executes = !!tool && ingressOk && severity(verdict) <= severity("MONITOR");
    const canaries = (this.bundle.rules.find((r) => r.id === "canary_honeytoken")?.params.tokens as string[]) ?? [];
    const toolNodeId = `${session.id}:call:${session.step + 1}`;
    let responseAtoms: DataAtom[] = [];

    let integrityTag: RequestIntegrityTag | undefined;
    if (executes && tool) {
      // Destination firewall: resolve once, check every answer, pin. The HMAC binds the pin.
      const urlLeaf = stringLeaves(env.arguments).find((l) => /^https?:\/\//i.test(l.value));
      const allow = (this.bundle.rules.find((r) => r.id === "destination_allowlist")?.params.url_domains as string[] | undefined) ?? [];
      const network = urlLeaf ? inspectDestination(urlLeaf.value, allow, this.dns) : undefined;
      const request = { decisionId: envId, sessionId: session.id, tool: env.tool, argsDigest: argsDigest(env.arguments), manifestHash: tool.currentHash, pinnedIp: network?.pinnedIp ?? null };
      integrityTag = signRequest(request, this.integrityKey);
      sandbox = executeInSandbox(env, tool, req.scriptedOutput, {
        network,
        integrity: { request, tag: integrityTag, verify: (r, t) => verifyRequest(r, t, this.integrityKey) },
        ebpf: session.ebpf,
        dns: this.dns,
        socket: req.socket,
        now,
      });
      if (!sandbox.executed) {
        const ruleId = network?.decision === "HARD_DENY" ? "egress.destination_firewall" : sandbox.integrityVerified ? "ebpf.egress_enforcement" : "request_integrity";
        verdict = maxVerdict(verdict, "BLOCK");
        findings.push({
          ruleId,
          ruleVersion: "1.0.0",
          module: "M8",
          outcome: "BLOCK",
          reason: sandbox.refusal ?? "sandbox refused execution",
          counterfactual: "If every socket had gone through the egress proxy to the pinned IP, within the session's byte budget, the tool would have run.",
        });
      }
      if (grantOk && env.grantId) this.grants.get(env.grantId)!.used = true;
      stage("sandbox", sandbox.executed ? "pass" : "fail", sandbox.executed ? `${sandbox.container.runtime} · ${sandbox.container.user} · HMAC ✓ · exec ${sandbox.execMs}ms` : (sandbox.refusal ?? "refused"));
      lat.sandbox = sandbox.execMs;
      stages[stages.length - 1].latencyMs = sandbox.execMs;
      dlp = inspectResponse(sandbox.output, canaries);
      if (dlp.canaryLeak) {
        verdict = maxVerdict(verdict, "QUARANTINE");
        findings.push({ ruleId: "dlp.canary_leak", ruleVersion: "1.0.0", module: "M9", outcome: "QUARANTINE", reason: "honeytoken observed in tool output", counterfactual: "Honeytokens never appear in legitimate output." });
      }
      if (dlp.secondaryInjection) {
        verdict = maxVerdict(verdict, "MONITOR");
        findings.push({ ruleId: "dlp.secondary_injection", ruleVersion: "1.0.0", module: "M9", outcome: "MONITOR", reason: "tool output contains instructions aimed at the agent; content fenced as UNTRUSTED", counterfactual: "If the output contained no embedded instructions, it would be returned unfenced." });
      }
      const nRedact = dlp.redactions.reduce((a, r) => a + r.count, 0);
      stage("dlp", dlp.canaryLeak ? "fail" : dlp.secondaryInjection || nRedact ? "warn" : "pass", dlp.canaryLeak ? "canary honeytoken leaked" : `${nRedact} redaction(s)${dlp.secondaryInjection ? " · secondary injection fenced" : ""}`);
      responseAtoms = extractAtoms(sandbox.output, tool, `${toolNodeId}:out`, now);
      if (dlp.secondaryInjection) responseAtoms.forEach((a) => (a.label = join(a.label, "UNTRUSTED")));
    } else {
      stage("sandbox", "skip", tool ? `not executed (${verdict})` : "not executed");
      stage("dlp", "skip", "no output to inspect");
    }

    /* Phase 8 — Signed receipt (M10) */
    const deterministicLatencyMs = round(
      (["ingress", "canonicalize", "registry", "policy", "fusion", "dlp"] as StageId[]).reduce((a, s) => a + (lat[s] ?? 0), 0) + STAGE_BASE_MS.receipt[0],
      2,
    );
    const top = [...findings].sort((a, b) => severity(b.outcome) - severity(a.outcome))[0];
    const counterfactual = this.counterfactual(findings, mlVerdict, verdict, top, contributions[0]?.feature);
    const prev = this.ledger[this.ledger.length - 1]?.receipt;
    stage("receipt", "pass", "Ed25519 signed · hash-chained");
    const receipt = signReceipt(
      {
        version: "satg.receipt/v1",
        seq: this.ledger.length + 1,
        receiptId: uuid(),
        decisionId: envId,
        timestamp: new Date(now).toISOString(),
        sessionId: session.id,
        principal: session.principal,
        protocol: env.protocol,
        tool: env.tool,
        argsDigest: argsDigest(env.arguments),
        manifestHash: tool?.currentHash ?? "n/a",
        pinnedManifestHash: tool?.pinnedHash ?? "n/a",
        gatewayMode: this.mode,
        policyBundle: { version: this.bundle.version, rules: Object.fromEntries(this.bundle.rules.filter((r) => r.enabled).map((r) => [r.id, `${r.version}${r.mode === "monitor" ? "+shadow" : ""}`])) },
        verdict,
        deterministicVerdict: detVerdict,
        mlVerdict,
        mlAbstained: abstained,
        findings,
        mlScores: scores,
        riskScore: round(riskScore, 4),
        contributions: contributions.map((c) => ({ ...c, value: round(c.value, 4), contribution: round(c.contribution, 4) })),
        counterfactual,
        stageLatenciesMs: lat,
        deterministicLatencyMs,
        totalLatencyMs: round(deterministicLatencyMs + (lat.ml ?? 0), 2),
        dlp: { redactions: dlp?.redactions.reduce((a, r) => a + r.count, 0) ?? 0, canaryLeak: !!dlp?.canaryLeak, secondaryInjection: !!dlp?.secondaryInjection },
        executed: !!sandbox?.executed,
        anomalyFingerprints: fingerprints.length ? fingerprints : undefined,
        requestIntegrity: integrityTag,
        workload: { spiffeId: session.identity.spiffeId, dpopJkt: session.identity.dpop.jkt, tls: `${session.identity.mtls.version} mTLS` },
        prevHash: prev?.hash ?? GENESIS_HASH,
      },
      this.key,
    );

    const anomalyIds = scan?.anomalies.map((a) => {
      const record = quarantineEnvelope(a, { sessionId: session.id, agentId: session.principal.agentId, tool: env.tool, receiptId: receipt.body.receiptId, at: now });
      this.anomalies.append(record);
      return record.anomaly_id;
    });
    // A forged proof-of-possession means the session's credential is suspect.
    if (scan?.anomalies.some((a) => MITIGATION[a.type] === "ISOLATE_SESSION")) session.quarantined = true;

    const entry: LedgerEntry = { receipt, envelope: env, stages, sandbox, dlp, groundTruth: req.groundTruth, scenario: req.scenario, anomalyIds };
    this.updateSession(session, env, tool, verdict, matched, responseAtoms, sandbox, nextCusum, toolNodeId, receipt.body.receiptId, findings);

    let approval: ApprovalRequest | undefined;
    if (verdict === "HUMAN_APPROVAL" || verdict === "STEP_UP") {
      approval = {
        id: shortId("apr"),
        createdAt: now,
        receiptId: receipt.body.receiptId,
        envelope: env,
        riskScore,
        reason: top?.reason ?? `ML risk ${riskScore.toFixed(2)}${abstained ? " (conformal abstention)" : ""}`,
        kind: verdict,
        approvals: [],
        requiredApprovals: verdict === "HUMAN_APPROVAL" ? 2 : 1,
        status: "PENDING",
      };
    }

    this.ledger.push(entry);
    if (approval) this.approvals.unshift(approval);
    if (!this.ephemeral) this.emit();
    return { entry, approval };
  }

  private counterfactual(findings: RuleFinding[], ml: Verdict, verdict: Verdict, top: RuleFinding | undefined, topFeature?: string) {
    if (!top && severity(ml) <= severity("MONITOR")) return "All deterministic rules passed and ML risk stayed below the escalation threshold; verdict would be unchanged.";
    if (!top) return `No rule fired; if ${topFeature ?? "the dominant ML feature"} were at its benign baseline, verdict would have been ALLOW instead of ${verdict}.`;
    const rest = maxVerdict(...findings.filter((f) => f !== top).map((f) => f.outcome), ml);
    return `${top.counterfactual} Without ${top.ruleId}, the remaining evidence yields ${rest}.`;
  }

  private markDrift(tool: RegisteredTool, advertised: ToolManifest, hash: string, now: number) {
    tool.manifest = advertised;
    tool.currentHash = hash;
    tool.status = "QUARANTINED";
    tool.lastAudit = now;
    tool.findings = [
      { kind: "HASH_DRIFT", detail: `manifest ${hash.slice(0, 12)}… ≠ pinned ${tool.pinnedHash.slice(0, 12)}…`, at: now },
      ...scanManifest(advertised, now, tool.pinnedManifest),
    ];
  }

  private updateSession(
    s: SessionState,
    env: ToolCallEnvelope,
    tool: RegisteredTool | undefined,
    verdict: Verdict,
    matched: { atom: DataAtom; path: string }[],
    responseAtoms: DataAtom[],
    sandbox: SandboxResult | null,
    nextCusum: number,
    nodeId: string,
    receiptId: string,
    findings: RuleFinding[],
  ) {
    s.step++;
    s.cusum = nextCusum;
    if (tool) s.toolHistory.push(tool.manifest.name);
    if (verdict === "QUARANTINE" || findings.some((f) => f.ruleId === "canary_honeytoken")) s.quarantined = true;

    const argLabel: TaintLattice = joinAll(matched.map((m) => m.atom.label));
    s.nodes.push({
      id: nodeId,
      kind: "tool",
      label: env.tool,
      sublabel: `${env.protocol} · ${verdict}`,
      step: s.step,
      taint: argLabel,
      verdict,
      receiptId,
      payload: env.arguments,
      atoms: matched.map((m) => m.atom.id),
    });

    // Inbound edges: atoms that flowed into the arguments, else the user prompt.
    const sources = new Map<string, TaintLattice>();
    for (const m of matched) sources.set(m.atom.sourceNodeId, join(sources.get(m.atom.sourceNodeId) ?? "TRUSTED", m.atom.label));
    if (!sources.size) s.edges.push({ from: `${s.id}:prompt`, to: nodeId, taint: "TRUSTED", label: "intent" });
    for (const [from, taint] of sources) s.edges.push({ from, to: nodeId, taint, label: "atoms" });

    // Outbound: destination for egress tools
    if (tool?.egress || tool?.capability === "net:fetch") {
      const dest = String(env.arguments.to ?? env.arguments.url ?? env.arguments.channel ?? env.arguments.to_iban ?? "");
      if (dest) {
        const extId = `${nodeId}:ext`;
        s.nodes.push({ id: extId, kind: "external", label: dest.replace(/^https?:\/\//, "").slice(0, 34), sublabel: severity(verdict) >= severity("STEP_UP") ? "blocked" : "reached", step: s.step, taint: tool.egress ? argLabel : "UNTRUSTED", atoms: [], payload: { destination: dest } });
        s.edges.push({ from: nodeId, to: extId, taint: tool.egress ? argLabel : "UNTRUSTED", label: severity(verdict) >= severity("STEP_UP") ? "vetoed" : tool.egress ? "egress" : "request" });
      }
    }

    if (sandbox?.executed && tool) {
      const label = responseAtoms.length ? joinAll(responseAtoms.map((a) => a.label)) : sourceLabel(tool);
      s.nodes.push({
        id: `${nodeId}:out`,
        kind: "data",
        label: tool.untrustedSource ? "Retrieved document" : tool.sensitiveSource ? "Private records" : "Tool result",
        sublabel: `${responseAtoms.length} atoms`,
        step: s.step,
        taint: label,
        atoms: responseAtoms.map((a) => a.id),
        payload: { output: sandbox.output.slice(0, 600) },
      });
      s.edges.push({ from: nodeId, to: `${nodeId}:out`, taint: label, label: "result" });
      s.atoms.push(...responseAtoms);
      if (tool.sensitiveSource || responseAtoms.some((a) => isPrivate(a.label))) s.flags.privateData = true;
      if (tool.untrustedSource || responseAtoms.some((a) => isUntrusted(a.label))) s.flags.untrustedContent = true;

      if (tool.egress) {
        const e = s.egress;
        const rows = matched.filter((m) => m.atom.label === "SENSITIVE" || m.atom.label === "TAINTED").length;
        const alpha = Number(this.bundle.rules.find((r) => r.id === "egress_budget")?.params.ewma_alpha ?? 0.3);
        e.rowsOut += rows;
        e.bytesOut += new TextEncoder().encode(JSON.stringify(env.arguments)).length;
        e.outboundCalls++;
        e.ewmaBytes = alpha * (rows > 0 ? 1 : 0) + (1 - alpha) * e.ewmaBytes;
      }
    }
    if (tool?.egress) s.flags.outboundChannel = true;
    const eb = this.bundle.rules.find((r) => r.id === "egress_budget")?.params;
    if (eb) {
      s.egress.maxRows = Number(eb.max_rows);
      s.egress.maxBytes = Number(eb.max_bytes);
    }
  }

  /* ---------- operations (M11) ---------- */

  setMode(mode: GatewayMode) {
    this.mode = mode;
    this.modeChangedAt = Date.now();
    this.emit();
  }

  setBundle(bundle: PolicyBundle) {
    this.bundle = structuredClone(bundle);
    this.emit();
  }

  setMlEnabled(on: boolean) {
    this.mlEnabled = on;
    this.emit();
  }

  simulateRugPull(name: string) {
    const tool = this.registry.get(name);
    if (!tool) return;
    const mutated = rugPullManifest(tool.manifest);
    this.markDrift(tool, mutated, manifestHash(mutated), Date.now());
    this.emit();
  }

  /** Operator review: re-scan the advertised manifest and re-pin it if clean. */
  repin(name: string): { ok: boolean; reason: string } {
    const tool = this.registry.get(name);
    if (!tool) return { ok: false, reason: "unknown tool" };
    const findings = scanManifest(tool.manifest, Date.now());
    if (findings.length) {
      tool.findings = findings;
      this.emit();
      return { ok: false, reason: `manifest still poisoned: ${findings.map((f) => f.detail).join("; ")}` };
    }
    tool.pinnedManifest = tool.manifest;
    tool.pinnedHash = tool.currentHash = manifestHash(tool.manifest);
    tool.status = "VERIFIED";
    tool.findings = [];
    tool.lastAudit = Date.now();
    this.emit();
    return { ok: true, reason: "re-pinned" };
  }

  /** Roll a drifted tool back to its pinned manifest. */
  restore(name: string) {
    const tool = this.registry.get(name);
    if (!tool) return;
    tool.manifest = tool.pinnedManifest;
    tool.currentHash = tool.pinnedHash;
    const findings = scanManifest(tool.manifest, Date.now());
    tool.findings = findings;
    tool.status = findings.length ? "POISONED" : "VERIFIED";
    tool.lastAudit = Date.now();
    this.emit();
  }

  registerTool(input: Omit<RegisteredTool, "pinnedHash" | "currentHash" | "status" | "findings" | "calls" | "lastAudit" | "registeredAt" | "pinnedManifest">) {
    const now = Date.now();
    const hash = manifestHash(input.manifest);
    const findings = scanManifest(input.manifest, now);
    const tool: RegisteredTool = {
      ...input,
      pinnedManifest: input.manifest,
      pinnedHash: hash,
      currentHash: hash,
      status: findings.length ? "POISONED" : "VERIFIED",
      findings,
      calls: 0,
      lastAudit: now,
      registeredAt: now,
    };
    this.registry.set(input.manifest.name, tool);
    this.emit();
    return tool;
  }

  approve(id: string, approver: string): { ok: boolean; message: string } {
    const a = this.approvals.find((x) => x.id === id);
    if (!a || a.status !== "PENDING") return { ok: false, message: "request is not pending" };
    if (a.approvals.some((x) => x.approver === approver)) return { ok: false, message: `${approver} already approved — a second, different approver is required` };
    if (approver.includes(a.envelope.principal.userId)) return { ok: false, message: "requester cannot approve their own request" };
    a.approvals.push({ approver, at: Date.now() });
    if (a.approvals.length >= a.requiredApprovals) {
      const now = Date.now();
      const unsigned = {
        grantId: shortId("grant"),
        approvalId: a.id,
        tool: a.envelope.tool,
        argsDigest: argsDigest(a.envelope.arguments),
        issuedAt: now,
        expiresAt: now + 300_000,
        approvers: a.approvals.map((x) => x.approver),
      };
      const grant: CapabilityGrant = { ...unsigned, signature: signText(grantSigningText(unsigned), this.key), used: false };
      this.grants.set(grant.grantId, grant);
      a.grant = grant;
      a.status = "APPROVED";
    }
    this.emit();
    return { ok: true, message: a.status === "APPROVED" ? "capability grant issued" : `approval ${a.approvals.length}/${a.requiredApprovals} recorded` };
  }

  reject(id: string, approver: string) {
    const a = this.approvals.find((x) => x.id === id);
    if (!a || a.status !== "PENDING") return;
    a.status = "REJECTED";
    a.rejectedBy = approver;
    this.emit();
  }

  /** Re-submit an approved call with its single-use grant attached. */
  executeApproved(id: string): PipelineResult | null {
    const a = this.approvals.find((x) => x.id === id);
    if (!a?.grant) return null;
    this.refreshToken(a.envelope.sessionId);
    const res = this.process({ raw: a.envelope.rawPayload, sessionId: a.envelope.sessionId, grantId: a.grant.grantId, groundTruth: "benign", scenario: "approved-replay" });
    if (res.entry.receipt.body.executed) a.status = "EXECUTED";
    this.emit();
    return res;
  }
}
