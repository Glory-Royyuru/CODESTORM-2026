/* Secure Agent Tool Gateway — shared data model */

export type Protocol = "MCP" | "OPENAI" | "REST";
export type GatewayMode = "ENFORCING" | "FAIL_CLOSED";

/** Ordered by severity. Fusion is monotonic: final = max(severity). */
export const VERDICTS = ["ALLOW", "MONITOR", "STEP_UP", "HUMAN_APPROVAL", "QUARANTINE", "BLOCK"] as const;
export type Verdict = (typeof VERDICTS)[number];

export const TAINT_LABELS = ["TRUSTED", "INTERNAL", "UNTRUSTED", "SENSITIVE", "SECRET", "TAINTED"] as const;
export type TaintLattice = (typeof TAINT_LABELS)[number];

export type RiskTier = 1 | 2 | 3 | 4;
export type ToolStatus = "VERIFIED" | "POISONED" | "QUARANTINED";
export type Capability =
  | "db:read"
  | "db:admin"
  | "net:fetch"
  | "email:send"
  | "chat:post"
  | "secrets:read"
  | "fs:read"
  | "orders:read"
  | "payments:transfer"
  | "calendar:read"
  | "weather:read"
  | "docs:read";

export type StageId =
  | "ingress"
  | "canonicalize"
  | "registry"
  | "policy"
  | "ml"
  | "fusion"
  | "sandbox"
  | "dlp"
  | "receipt";

export interface ParamSpec {
  type: "string" | "number" | "boolean" | "array" | "object";
  description?: string;
  enum?: string[];
}

export interface ToolManifest {
  name: string;
  description: string;
  parameters: Record<string, ParamSpec>;
  required: string[];
  server: { id: string; url: string; transport: "stdio" | "sse" | "http" };
  version: string;
}

export interface IntegrityFinding {
  kind: "HASH_DRIFT" | "DESCRIPTION_INJECTION" | "HIDDEN_UNICODE" | "SCHEMA_EXPANSION" | "SHADOWING";
  detail: string;
  at: number;
}

export interface RegisteredTool {
  manifest: ToolManifest;
  pinnedHash: string;
  currentHash: string;
  status: ToolStatus;
  tier: RiskTier;
  capability: Capability;
  /** Sends data outside the trust boundary. */
  egress: boolean;
  /** Returns data classified at least SENSITIVE. */
  sensitiveSource: boolean;
  /** Returns content from outside the trust boundary. */
  untrustedSource: boolean;
  needsSecret?: string;
  lastAudit: number;
  registeredAt: number;
  findings: IntegrityFinding[];
  calls: number;
  /** Manifest that was pinned, kept so rug-pulls can be diffed. */
  pinnedManifest: ToolManifest;
}

export interface Principal {
  agentId: string;
  userId: string;
  tenant: string;
}

export interface TaskToken {
  token: string;
  scopes: Capability[];
  sessionId: string;
  issuedAt: number;
  expiresAt: number;
}

export interface CapabilityGrant {
  grantId: string;
  approvalId: string;
  tool: string;
  argsDigest: string;
  issuedAt: number;
  expiresAt: number;
  approvers: string[];
  signature: string;
  used: boolean;
}

/** The normalized call every protocol adapter produces. */
export interface ToolCallEnvelope {
  id: string;
  protocol: Protocol;
  sessionId: string;
  principal: Principal;
  userGoal: string;
  rawPayload: string;
  tool: string;
  arguments: Record<string, unknown>;
  taskToken: TaskToken;
  /** Manifest the upstream MCP server advertises at call time (rug-pull detection). */
  advertisedManifest?: ToolManifest;
  grantId?: string;
  receivedAt: number;
}

export interface DataAtom {
  id: string;
  value: string;
  label: TaintLattice;
  kind: "email" | "url" | "secret" | "pii" | "text" | "id" | "instruction";
  sourceNodeId: string;
  sourceTool: string;
  createdAt: number;
}

export interface RuleFinding {
  ruleId: string;
  ruleVersion: string;
  outcome: Verdict;
  reason: string;
  /** What would have needed to be different for this rule not to fire. */
  counterfactual: string;
  module: "M1" | "M2" | "M3" | "M4" | "M5" | "M8" | "M9";
}

export interface MlScores {
  p_injection: number;
  p_misaligned: number;
  isolation_forest_anomaly: number;
  trigram_surprise: number;
  cusum_shift: number;
}

export interface FeatureContribution {
  feature: keyof MlScores;
  value: number;
  contribution: number;
}

export interface StageResult {
  stage: StageId;
  label: string;
  latencyMs: number;
  status: "pass" | "warn" | "fail" | "skip";
  detail: string;
}

export interface DlpResult {
  redactions: { kind: string; count: number }[];
  canaryLeak: boolean;
  secondaryInjection: boolean;
  redactedOutput: string;
}

export interface SandboxResult {
  executed: boolean;
  runtime: string;
  container: {
    image: string;
    runtime: "runsc (gVisor)";
    rootless: true;
    user: string;
    readOnlyRootFs: true;
    cpu: string;
    memory: string;
    network: string;
  };
  vaultLease?: { path: string; leaseId: string; ttlSeconds: number };
  egressProxy?: { host: string; pinnedIp: string; blocked: boolean };
  output: string;
  execMs: number;
}

export interface ReceiptBody {
  version: "satg.receipt/v1";
  seq: number;
  receiptId: string;
  decisionId: string;
  timestamp: string;
  sessionId: string;
  principal: Principal;
  protocol: Protocol;
  tool: string;
  argsDigest: string;
  manifestHash: string;
  pinnedManifestHash: string;
  gatewayMode: GatewayMode;
  policyBundle: { version: string; rules: Record<string, string> };
  verdict: Verdict;
  deterministicVerdict: Verdict;
  mlVerdict: Verdict;
  /** Split-conformal abstention: prediction set contained both classes → forced escalation. */
  mlAbstained: boolean;
  findings: RuleFinding[];
  mlScores: MlScores;
  riskScore: number;
  contributions: FeatureContribution[];
  counterfactual: string;
  stageLatenciesMs: Partial<Record<StageId, number>>;
  deterministicLatencyMs: number;
  totalLatencyMs: number;
  dlp: { redactions: number; canaryLeak: boolean; secondaryInjection: boolean };
  executed: boolean;
  prevHash: string;
}

export interface DecisionReceipt {
  body: ReceiptBody;
  canonical: string;
  hash: string;
  signature: string;
  publicKey: string;
}

/** Ledger entry = receipt + unsigned operator metadata. */
export interface LedgerEntry {
  receipt: DecisionReceipt;
  envelope: ToolCallEnvelope;
  stages: StageResult[];
  sandbox: SandboxResult | null;
  dlp: DlpResult | null;
  /** Ground-truth label for eval / time-machine replays (never signed). */
  groundTruth: "attack" | "benign";
  scenario?: string;
}

export interface TrifectaFlags {
  privateData: boolean;
  untrustedContent: boolean;
  outboundChannel: boolean;
}

export interface EgressBudget {
  rowsOut: number;
  bytesOut: number;
  maxRows: number;
  maxBytes: number;
  /** EWMA of bytes per outbound call, for slow-drip detection. */
  ewmaBytes: number;
  outboundCalls: number;
}

export type GraphNodeKind = "prompt" | "tool" | "data" | "external";

export interface GraphNode {
  id: string;
  kind: GraphNodeKind;
  label: string;
  sublabel?: string;
  step: number;
  taint: TaintLattice;
  verdict?: Verdict;
  receiptId?: string;
  payload?: Record<string, unknown>;
  atoms: string[];
}

export interface GraphEdge {
  from: string;
  to: string;
  taint: TaintLattice;
  label?: string;
}

export interface SessionState {
  id: string;
  principal: Principal;
  goal: string;
  title: string;
  startedAt: number;
  flags: TrifectaFlags;
  atoms: DataAtom[];
  nodes: GraphNode[];
  edges: GraphEdge[];
  egress: EgressBudget;
  toolHistory: string[];
  cusum: number;
  step: number;
  quarantined: boolean;
  token: TaskToken;
  scenario?: string;
}

export interface PolicyRule {
  id: string;
  name: string;
  module: RuleFinding["module"];
  version: string;
  enabled: boolean;
  mode: "enforce" | "monitor";
  description: string;
  params: Record<string, unknown>;
}

export interface PolicyBundle {
  version: string;
  rules: PolicyRule[];
}

export interface ApprovalRequest {
  id: string;
  createdAt: number;
  receiptId: string;
  envelope: ToolCallEnvelope;
  riskScore: number;
  reason: string;
  kind: "HUMAN_APPROVAL" | "STEP_UP";
  approvals: { approver: string; at: number }[];
  requiredApprovals: number;
  status: "PENDING" | "APPROVED" | "REJECTED" | "EXECUTED";
  grant?: CapabilityGrant;
  rejectedBy?: string;
}

export interface GatewayMetrics {
  total: number;
  byVerdict: Record<Verdict, number>;
  latencies: number[];
  deterministicLatencies: number[];
}

export interface PipelineResult {
  entry: LedgerEntry;
  approval?: ApprovalRequest;
}
