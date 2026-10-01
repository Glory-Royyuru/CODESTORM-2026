import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import { sha256Hex, uuid } from "../util";
import { MITIGATION, type AnomalyFinding, type AnomalyType, type Mitigation, type RiskSeverity } from "./guard";

/* Append-only store of quarantined crypt-arithmetic anomalies, with pub/sub for the UI. */

export interface CryptArithmeticAnomalyRecord {
  anomaly_id: string; // UUIDv4
  timestamp: string;
  session_id: string;
  agent_id: string;
  anomaly_type: AnomalyType;
  risk_severity: RiskSeverity;
  raw_payload_sha256: string; // Fingerprint of the malicious value
  quarantined_hex_snippet: string; // Safe, truncated hex representation (max 64 bytes)
  parser_error_detail: string;
  mitigation_action: Mitigation;
  ed25519_receipt_id: string;
  /** JSON path of the value inside the payload. */
  location: string;
  raw_payload_bytes: number;
  tool: string;
}

export const MAX_SNIPPET_BYTES = 64;

/**
 * Isolation envelope: the raw value is reduced to a SHA-256 fingerprint and
 * at most 64 bytes of hex, so nothing stored can be re-parsed as the payload.
 */
export function quarantineEnvelope(
  a: AnomalyFinding,
  ctx: { sessionId: string; agentId: string; tool: string; receiptId: string; at: number; anomalyId?: string },
): CryptArithmeticAnomalyRecord {
  const bytes = utf8ToBytes(a.raw);
  return {
    anomaly_id: ctx.anomalyId ?? uuid(),
    timestamp: new Date(ctx.at).toISOString(),
    session_id: ctx.sessionId,
    agent_id: ctx.agentId,
    anomaly_type: a.type,
    risk_severity: a.severity,
    raw_payload_sha256: `sha256:${sha256Hex(a.raw)}`,
    quarantined_hex_snippet: bytesToHex(bytes.slice(0, MAX_SNIPPET_BYTES)),
    parser_error_detail: a.detail,
    mitigation_action: MITIGATION[a.type],
    ed25519_receipt_id: ctx.receiptId,
    location: a.location,
    raw_payload_bytes: bytes.length,
    tool: ctx.tool,
  };
}

export class AnomalyLedger {
  private items: readonly CryptArithmeticAnomalyRecord[] = [];
  private listeners = new Set<() => void>();
  private version = 0;

  /** Records are frozen and never edited or removed. */
  append(record: CryptArithmeticAnomalyRecord) {
    this.items = [...this.items, Object.freeze({ ...record })];
    this.version++;
    this.listeners.forEach((l) => l());
  }

  records(): readonly CryptArithmeticAnomalyRecord[] {
    return this.items;
  }

  subscribe = (fn: () => void) => {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  };

  getVersion = () => this.version;
}
