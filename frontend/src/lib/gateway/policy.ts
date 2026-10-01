import YAML from "yaml";
import { verifyText } from "./crypto";
import type { DecodeReport } from "./decoder";
import { hostIsDenied } from "./network/firewall";
import { isUntrusted } from "./taint";
import type {
  CapabilityGrant,
  DataAtom,
  PolicyBundle,
  PolicyRule,
  RegisteredTool,
  RuleFinding,
  SessionState,
  ToolCallEnvelope,
  Verdict,
} from "./types";
import { canonicalJson, sha256Hex, stringLeaves } from "./util";

/* M3 — Deterministic policy core (declarative YAML bundle, evaluated in-process) */

export const DEFAULT_BUNDLE: PolicyBundle = {
  version: "2026.09.3",
  rules: [
    {
      id: "tool_integrity",
      name: "Tool manifest integrity",
      module: "M2",
      version: "1.4.0",
      enabled: true,
      mode: "enforce",
      description: "Quarantine tools whose manifest hash drifted; block tools flagged as poisoned.",
      params: {},
    },
    {
      id: "capability_scope",
      name: "Task-bound capability token",
      module: "M3",
      version: "2.1.0",
      enabled: true,
      mode: "enforce",
      description: "Short-lived, session-bound token must carry the tool's capability scope.",
      params: { token_ttl_seconds: 300 },
    },
    {
      id: "object_ownership",
      name: "Object-level ownership",
      module: "M3",
      version: "1.2.0",
      enabled: true,
      mode: "enforce",
      description: "Resource identifiers in arguments must belong to the human principal.",
      params: { resource_args: ["order_id", "account_id", "from_account"] },
    },
    {
      id: "sql_semantic",
      name: "Semantic SQL validation",
      module: "M3",
      version: "3.0.1",
      enabled: true,
      mode: "enforce",
      description: "Read-only tools accept a single SELECT; DDL/DML, stacked queries and system tables are denied.",
      params: {
        forbidden_keywords: ["DROP", "DELETE", "UPDATE", "INSERT", "ALTER", "TRUNCATE", "GRANT", "CREATE"],
        denied_tables: ["pg_shadow", "information_schema", "pg_authid"],
        max_limit: 1000,
      },
    },
    {
      id: "path_traversal",
      name: "Path traversal defense",
      module: "M3",
      version: "1.1.0",
      enabled: true,
      mode: "enforce",
      description: "File paths must resolve inside the workspace root.",
      params: { root: "/workspace", denied_prefixes: ["/etc", "/proc", "/root", "~"] },
    },
    {
      id: "destination_allowlist",
      name: "Destination allowlist & SSRF",
      module: "M3",
      version: "2.3.0",
      enabled: true,
      mode: "enforce",
      description: "URLs, email recipients and payees must be allow-listed; private and metadata ranges are denied.",
      params: {
        url_domains: ["acme.com", "acme.dev", "partner-portal.com", "docs.python.org", "github.com", "wikipedia.org"],
        email_domains: ["acme.com"],
        payees: ["DE89370400440532013000", "GB29NWBK60161331926819"],
        block_private_ranges: true,
      },
    },
    {
      id: "param_smuggling",
      name: "Differential parameter-smuggling fuzzer",
      module: "M3",
      version: "1.0.3",
      enabled: true,
      mode: "enforce",
      description: "Bounded multi-layer decoding; strict and lenient parsers must agree on danger.",
      params: { max_layers: 4, expansion_cap: 10 },
    },
    {
      id: "taint_flow",
      name: "Provenance data-flow firewall",
      module: "M4",
      version: "1.3.0",
      enabled: true,
      mode: "enforce",
      description: "UNTRUSTED/TAINTED/SECRET atoms may not reach egress or destructive sinks.",
      params: { block_untrusted_to_egress: true, block_secret_to_egress: true },
    },
    {
      id: "lethal_trifecta",
      name: "Lethal trifecta veto",
      module: "M5",
      version: "1.0.0",
      enabled: true,
      mode: "enforce",
      description: "Private data + untrusted content + outbound channel in one session → hard veto on egress.",
      params: {},
    },
    {
      id: "egress_budget",
      name: "Egress budget & slow-drip",
      module: "M5",
      version: "1.2.2",
      enabled: true,
      mode: "enforce",
      description: "Per-session row/byte egress budgets with EWMA slow-drip detection.",
      params: { max_rows: 50, max_bytes: 32768, ewma_alpha: 0.3, slow_drip_calls: 4, slow_drip_threshold: 0.6 },
    },
    {
      id: "canary_honeytoken",
      name: "Canary honeytokens",
      module: "M5",
      version: "1.0.0",
      enabled: true,
      mode: "enforce",
      description: "Any use of a planted honeytoken is a confirmed compromise.",
      params: { tokens: ["AKIAHONEYTOKEN0000042", "canary-7f3a9c@acme.com", "ORD-000000"] },
    },
    {
      id: "tier4_approval",
      name: "Tier-4 two-person approval",
      module: "M3",
      version: "1.1.0",
      enabled: true,
      mode: "enforce",
      description: "Destructive tools require a signed, single-use, args-bound capability grant from two approvers.",
      params: { required_approvals: 2, grant_ttl_seconds: 300 },
    },
  ],
};

export interface PolicyContext {
  env: ToolCallEnvelope;
  tool: RegisteredTool;
  session: SessionState;
  decodes: (DecodeReport & { path: string })[];
  matched: { atom: DataAtom; path: string }[];
  grants: Map<string, CapabilityGrant>;
  ownership: Record<string, string>;
  publicKeyHex: string;
  now: number;
}

type Check = (rule: PolicyRule, ctx: PolicyContext) => Omit<RuleFinding, "ruleId" | "ruleVersion" | "module"> | null;

const p = <T>(rule: PolicyRule, key: string, fallback: T): T => (rule.params[key] as T) ?? fallback;
const str = (v: unknown) => (typeof v === "string" ? v : v == null ? "" : String(v));

/** Registrable-domain match: host equals or is a subdomain of an allowed domain. */
const domainAllowed = (host: string, allowed: string[]) =>
  allowed.some((d) => host === d.toLowerCase() || host.endsWith("." + d.toLowerCase()));

/** Local names, deny-range IP literals (IPv4 + IPv6, incl. v4-mapped) and ambiguous numeric IPs such as 2852039166. */
export const isPrivateHost = hostIsDenied;

export const argsDigest = (args: Record<string, unknown>) => sha256Hex(canonicalJson(args));
export const grantSigningText = (g: Omit<CapabilityGrant, "signature" | "used">) => canonicalJson(g);

const CHECKS: Record<string, Check> = {
  tool_integrity: (_r, { tool }) => {
    if (tool.status === "QUARANTINED" || tool.currentHash !== tool.pinnedHash)
      return {
        outcome: "QUARANTINE",
        reason: `manifest hash ${tool.currentHash.slice(0, 12)}… ≠ pinned ${tool.pinnedHash.slice(0, 12)}… (rug-pull)`,
        counterfactual: `If ${tool.manifest.name}'s manifest still matched its pinned SHA-256, this rule would not fire.`,
      };
    if (tool.status === "POISONED")
      return {
        outcome: "BLOCK",
        reason: `tool description contains injected instructions (${tool.findings.map((f) => f.detail).join("; ")})`,
        counterfactual: `If ${tool.manifest.name}'s description contained no hidden directives, this rule would not fire.`,
      };
    return null;
  },

  capability_scope: (_r, { env, tool, now }) => {
    const t = env.taskToken;
    if (t.expiresAt < now)
      return { outcome: "BLOCK", reason: "task token expired", counterfactual: "If the task token were still within its 5-minute TTL, verdict would not be BLOCK." };
    if (t.sessionId !== env.sessionId)
      return { outcome: "BLOCK", reason: "task token bound to a different session", counterfactual: "If the token were issued for this session, this rule would pass." };
    if (!t.scopes.includes(tool.capability))
      return {
        outcome: "BLOCK",
        reason: `token scopes [${t.scopes.join(", ")}] lack ${tool.capability}`,
        counterfactual: `If the task token had been granted the ${tool.capability} scope, this rule would pass.`,
      };
    return null;
  },

  object_ownership: (rule, { env, ownership }) => {
    for (const arg of p<string[]>(rule, "resource_args", [])) {
      const id = str(env.arguments[arg]);
      if (!id) continue;
      const owner = ownership[id];
      if (owner === undefined)
        return { outcome: "BLOCK", reason: `${arg}=${id} does not exist in the ownership index`, counterfactual: `If ${arg} referenced a known object, this rule could evaluate ownership.` };
      if (owner !== env.principal.userId && owner !== `tenant:${env.principal.tenant}`)
        return {
          outcome: "BLOCK",
          reason: `${arg}=${id} is owned by ${owner}, not ${env.principal.userId} (confused deputy)`,
          counterfactual: `If ${arg} had referenced an object owned by ${env.principal.userId}, verdict would have been ALLOW.`,
        };
    }
    return null;
  },

  sql_semantic: (rule, { env, tool }) => {
    if (tool.capability !== "db:read") return null;
    const q = str(env.arguments.query).trim();
    const upper = q.toUpperCase();
    const forbidden = p<string[]>(rule, "forbidden_keywords", []).find((k) => new RegExp(`\\b${k}\\b`).test(upper));
    if (forbidden)
      return { outcome: "BLOCK", reason: `read-only tool received ${forbidden} statement`, counterfactual: `If parameter \`query\` had not contained ${forbidden} syntax, verdict would have been ALLOW.` };
    if (!/^(SELECT|WITH)\b/.test(upper))
      return { outcome: "BLOCK", reason: "query must be a single SELECT", counterfactual: "If `query` were a plain SELECT statement, this rule would pass." };
    if (/;\s*\S/.test(q) || /--|\/\*/.test(q))
      return { outcome: "BLOCK", reason: "stacked statements or SQL comments detected", counterfactual: "If `query` contained a single statement without comments, this rule would pass." };
    const table = p<string[]>(rule, "denied_tables", []).find((t) => upper.includes(t.toUpperCase()));
    if (table)
      return { outcome: "BLOCK", reason: `access to system table ${table}`, counterfactual: `If \`query\` had not referenced ${table}, this rule would pass.` };
    const limit = /\bLIMIT\s+(\d+)/.exec(upper);
    const max = p<number>(rule, "max_limit", 1000);
    if (!limit || Number(limit[1]) > max)
      return { outcome: "STEP_UP", reason: `unbounded result set (LIMIT ${limit?.[1] ?? "missing"} > ${max})`, counterfactual: `If \`query\` had LIMIT ≤ ${max}, this rule would pass.` };
    return null;
  },

  path_traversal: (rule, { env, tool, decodes }) => {
    if (tool.capability !== "fs:read") return null;
    const raw = str(env.arguments.path);
    const decoded = decodes.find((d) => d.path === "path")?.decoded ?? raw;
    const root = p<string>(rule, "root", "/workspace");
    for (const candidate of [raw, decoded]) {
      if (candidate.includes("\0")) return { outcome: "BLOCK", reason: "null byte in path", counterfactual: "If `path` contained no NUL byte, this rule would pass." };
      const abs = candidate.startsWith("/") ? candidate : `${root}/${candidate}`;
      const parts: string[] = [];
      for (const seg of abs.split(/[\\/]+/)) {
        if (seg === "..") parts.pop();
        else if (seg && seg !== ".") parts.push(seg);
      }
      const resolved = "/" + parts.join("/");
      const denied = p<string[]>(rule, "denied_prefixes", []).find((d) => candidate.startsWith(d));
      if (denied || !resolved.startsWith(root))
        return {
          outcome: "BLOCK",
          reason: `path resolves to ${resolved}, outside ${root}`,
          counterfactual: `If \`path\` had resolved inside ${root}, verdict would have been ALLOW.`,
        };
    }
    return null;
  },

  destination_allowlist: (rule, { env, tool }) => {
    const urlDomains = p<string[]>(rule, "url_domains", []);
    for (const { path, value } of stringLeaves(env.arguments)) {
      if (!/^https?:\/\//i.test(value)) continue;
      let host: string;
      try {
        const u = new URL(value);
        host = u.hostname.toLowerCase();
        if (u.protocol !== "https:")
          return { outcome: "BLOCK", reason: `${path} uses ${u.protocol} (https required)`, counterfactual: `If \`${path}\` used https://, this rule would evaluate the destination.` };
      } catch {
        return { outcome: "BLOCK", reason: `${path} is not a valid URL`, counterfactual: `If \`${path}\` were a valid URL, this rule would pass.` };
      }
      if (p(rule, "block_private_ranges", true) && isPrivateHost(host))
        return { outcome: "BLOCK", reason: `SSRF: ${host} is a private / link-local / metadata address`, counterfactual: `If \`${path}\` targeted a public allow-listed host, verdict would have been ALLOW.` };
      if (!domainAllowed(host, urlDomains))
        return { outcome: "BLOCK", reason: `${host} is not on the destination allowlist`, counterfactual: `If \`${path}\` targeted an allow-listed domain (${urlDomains.slice(0, 2).join(", ")}…), this rule would pass.` };
    }
    if (tool.capability === "email:send") {
      const domains = p<string[]>(rule, "email_domains", []);
      const bad = str(env.arguments.to)
        .split(/[,;\s]+/)
        .filter(Boolean)
        .find((addr) => !domainAllowed(addr.split("@")[1]?.toLowerCase() ?? "", domains));
      if (bad)
        return { outcome: "BLOCK", reason: `recipient ${bad} is outside allow-listed domains`, counterfactual: `If \`to\` had targeted an allow-listed domain (${domains.join(", ")}), this rule would pass.` };
    }
    if (tool.capability === "payments:transfer") {
      const iban = str(env.arguments.to_iban).replace(/\s/g, "");
      if (!p<string[]>(rule, "payees", []).includes(iban))
        return { outcome: "BLOCK", reason: `payee ${iban} is not a registered beneficiary`, counterfactual: "If `to_iban` were a registered beneficiary, this rule would pass." };
    }
    return null;
  },

  param_smuggling: (_r, { decodes }) => {
    for (const d of decodes) {
      if (d.hitLayerLimit || d.expansionExceeded)
        return {
          outcome: "BLOCK",
          reason: `\`${d.path}\` exceeds decode bounds (${d.hitLayerLimit ? "layer limit" : "10x expansion cap"})`,
          counterfactual: `If \`${d.path}\` were encoded with ≤ 4 layers, the fuzzer could canonicalize it.`,
        };
      if (d.disagreement)
        return {
          outcome: "BLOCK",
          reason: `parser disagreement on \`${d.path}\`: ${d.layers.join(" → ")} decodes to ${d.dangerousDecoded.join(", ")} payload`,
          counterfactual: `If \`${d.path}\` had not hidden ${d.dangerousDecoded[0]} content under ${d.layers.length} encoding layer(s), verdict would have been ALLOW.`,
        };
      if (d.zeroWidth)
        return { outcome: "STEP_UP", reason: `zero-width characters in \`${d.path}\``, counterfactual: `If \`${d.path}\` had no invisible characters, this rule would pass.` };
    }
    return null;
  },

  taint_flow: (rule, { tool, matched }) => {
    const sink = tool.egress || tool.tier === 4;
    if (!sink) {
      const untrusted = matched.find((m) => isUntrusted(m.atom.label));
      if (untrusted && tool.capability === "db:read")
        return {
          outcome: "STEP_UP",
          reason: `untrusted atom from ${untrusted.atom.sourceTool} flows into \`${untrusted.path}\``,
          counterfactual: `If \`${untrusted.path}\` did not contain data from ${untrusted.atom.sourceTool}, this rule would pass.`,
        };
      return null;
    }
    const bad = matched.find(
      (m) =>
        (p(rule, "block_untrusted_to_egress", true) && isUntrusted(m.atom.label)) ||
        (p(rule, "block_secret_to_egress", true) && m.atom.label === "SECRET"),
    );
    if (bad)
      return {
        outcome: "BLOCK",
        reason: `${bad.atom.label} atom "${bad.atom.value.slice(0, 40)}" (from ${bad.atom.sourceTool}) flows into sink \`${bad.path}\``,
        counterfactual: `If \`${bad.path}\` had not copied ${bad.atom.label.toLowerCase()} data from ${bad.atom.sourceTool}, this rule would pass.`,
      };
    return null;
  },

  lethal_trifecta: (_r, { tool, session }) => {
    if (!tool.egress) return null;
    const f = session.flags;
    if (f.privateData && f.untrustedContent)
      return {
        outcome: "BLOCK",
        reason: "session holds private data AND untrusted content; outbound channel requested → lethal trifecta",
        counterfactual: "If the session had not ingested untrusted content before acquiring private data, the trifecta would stay open.",
      };
    return null;
  },

  egress_budget: (rule, { env, tool, session, matched }) => {
    if (!tool.egress) return null;
    const rows = matched.filter((m) => m.atom.label === "SENSITIVE" || m.atom.label === "TAINTED").length;
    const bytes = new TextEncoder().encode(canonicalJson(env.arguments)).length;
    const maxRows = p(rule, "max_rows", 50);
    const maxBytes = p(rule, "max_bytes", 32768);
    if (session.egress.rowsOut + rows > maxRows)
      return { outcome: "BLOCK", reason: `row egress budget exceeded (${session.egress.rowsOut + rows}/${maxRows})`, counterfactual: `If this call carried ≤ ${maxRows - session.egress.rowsOut} sensitive rows, this rule would pass.` };
    if (session.egress.bytesOut + bytes > maxBytes)
      return { outcome: "BLOCK", reason: `byte egress budget exceeded (${session.egress.bytesOut + bytes}/${maxBytes}B)`, counterfactual: "If the payload were within the remaining byte budget, this rule would pass." };
    const alpha = p(rule, "ewma_alpha", 0.3);
    const ewma = alpha * (rows > 0 ? 1 : 0) + (1 - alpha) * session.egress.ewmaBytes;
    if (session.egress.outboundCalls + 1 >= p(rule, "slow_drip_calls", 4) && ewma >= p(rule, "slow_drip_threshold", 0.6))
      return { outcome: "HUMAN_APPROVAL", reason: `slow-drip pattern: EWMA sensitive-egress rate ${ewma.toFixed(2)} across ${session.egress.outboundCalls + 1} calls`, counterfactual: "If recent outbound calls had not repeatedly carried sensitive atoms, this rule would pass." };
    return null;
  },

  canary_honeytoken: (rule, { env }) => {
    const tokens = p<string[]>(rule, "tokens", []);
    const hit = stringLeaves(env.arguments).find((l) => tokens.some((t) => l.value.includes(t)));
    if (hit)
      return { outcome: "BLOCK", reason: `honeytoken used in \`${hit.path}\` — confirmed compromise, session flagged`, counterfactual: "Honeytokens are never legitimately used; there is no benign counterfactual." };
    return null;
  },

  tier4_approval: (_r, { env, tool, grants, publicKeyHex, now }) => {
    if (tool.tier !== 4) return null;
    const g = env.grantId ? grants.get(env.grantId) : undefined;
    if (g) {
      if (grantIsValid(g, env, publicKeyHex, now)) return null;
      return { outcome: "BLOCK", reason: `capability grant ${g.grantId} is ${g.used ? "already consumed (single-use)" : "invalid for these arguments"}`, counterfactual: "A fresh, unconsumed, args-bound grant would be required." };
    }
    return {
      outcome: "HUMAN_APPROVAL",
      reason: `Tier-4 destructive operation (${tool.manifest.name}) requires 2-person approval`,
      counterfactual: "If a valid single-use capability grant were attached, this rule would pass.",
    };
  },
};

/** A grant is valid only once, before expiry, for the exact tool + canonical arguments it was issued for. */
export function grantIsValid(g: CapabilityGrant, env: ToolCallEnvelope, publicKeyHex: string, now: number) {
  const { signature, used, ...unsigned } = g;
  return (
    !used &&
    g.expiresAt > now &&
    g.tool === env.tool &&
    g.argsDigest === argsDigest(env.arguments) &&
    verifyText(grantSigningText(unsigned), signature, publicKeyHex)
  );
}

export function evaluatePolicies(bundle: PolicyBundle, ctx: PolicyContext): RuleFinding[] {
  const findings: RuleFinding[] = [];
  for (const rule of bundle.rules) {
    if (!rule.enabled) continue;
    const check = CHECKS[rule.id];
    const hit = check?.(rule, ctx);
    if (!hit) continue;
    findings.push({
      ...hit,
      outcome: rule.mode === "monitor" && hit.outcome !== "ALLOW" ? ("MONITOR" as Verdict) : hit.outcome,
      reason: rule.mode === "monitor" ? `[shadow] ${hit.reason}` : hit.reason,
      ruleId: rule.id,
      ruleVersion: rule.version,
      module: rule.module,
    });
  }
  return findings;
}

/* ---------- YAML round-trip for the policy editor ---------- */

export function bundleToYaml(bundle: PolicyBundle): string {
  return YAML.stringify(
    {
      apiVersion: "satg.policy/v1",
      version: bundle.version,
      rules: bundle.rules.map((r) => ({
        id: r.id,
        version: r.version,
        enabled: r.enabled,
        mode: r.mode,
        params: r.params,
      })),
    },
    { lineWidth: 0 },
  );
}

export function yamlToBundle(text: string, base: PolicyBundle): { bundle?: PolicyBundle; errors: string[] } {
  const errors: string[] = [];
  let doc: unknown;
  try {
    doc = YAML.parse(text, { uniqueKeys: true });
  } catch (e) {
    return { errors: [(e as Error).message.split("\n")[0]] };
  }
  const d = doc as { version?: unknown; rules?: unknown };
  if (!d || typeof d !== "object" || !Array.isArray(d.rules)) return { errors: ["document must contain a `rules` list"] };
  const rules: PolicyRule[] = [];
  for (const [i, raw] of (d.rules as Record<string, unknown>[]).entries()) {
    const known = base.rules.find((r) => r.id === raw?.id);
    if (!known) {
      errors.push(`rules[${i}]: unknown rule id "${String(raw?.id)}"`);
      continue;
    }
    if (raw.mode !== undefined && raw.mode !== "enforce" && raw.mode !== "monitor")
      errors.push(`${known.id}: mode must be enforce | monitor`);
    const params = (raw.params ?? {}) as Record<string, unknown>;
    for (const [k, v] of Object.entries(known.params)) {
      if (!(k in params)) continue;
      const expected = Array.isArray(v) ? "array" : typeof v;
      const actual = Array.isArray(params[k]) ? "array" : typeof params[k];
      if (expected !== actual) errors.push(`${known.id}.params.${k}: expected ${expected}, got ${actual}`);
    }
    rules.push({
      ...known,
      version: String(raw.version ?? known.version),
      enabled: raw.enabled !== false,
      mode: raw.mode === "monitor" ? "monitor" : "enforce",
      params: { ...known.params, ...params },
    });
  }
  if (errors.length) return { errors };
  return { bundle: { version: String(d.version ?? base.version), rules }, errors };
}
