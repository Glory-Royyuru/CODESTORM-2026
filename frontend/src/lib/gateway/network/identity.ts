import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, randomBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import type { Principal } from "../types";
import { canonicalJson, sha256Hex } from "../util";

/*
 * Two separate boundaries:
 *   1. Transport / workload identity — *who* is calling: mTLS 1.3 with a
 *      SPIFFE X.509-SVID, plus a DPoP key bound to the session's task token.
 *   2. Application request integrity — *what* was approved: the gateway
 *      HMACs the canonical request, and the tool side refuses anything
 *      whose tag is missing or wrong.
 * Identity is simulated (no real TLS handshake happens in the browser);
 * the HMAC is real HMAC-SHA256.
 */

export interface WorkloadIdentity {
  spiffeId: string;
  svid: { serial: string; issuer: string; notAfter: string };
  mtls: { version: "TLSv1.3"; cipher: "TLS_AES_256_GCM_SHA384"; peerCertSha256: string };
  dpop: { alg: "EdDSA"; jkt: string; boundTo: string };
  attestedAt: number;
}

export function attestWorkload(principal: Principal, taskToken: string, now: number): WorkloadIdentity {
  const [name] = principal.agentId.replace(/^agent:/, "").split("@");
  const cert = sha256Hex(`svid:${principal.tenant}:${principal.agentId}`);
  return {
    spiffeId: `spiffe://${principal.tenant}.satg/agent/${name}`,
    svid: { serial: cert.slice(0, 16), issuer: `spiffe://${principal.tenant}.satg/spire/server`, notAfter: new Date(now + 3600_000).toISOString() },
    mtls: { version: "TLSv1.3", cipher: "TLS_AES_256_GCM_SHA384", peerCertSha256: cert },
    // RFC 7638 thumbprint of the DPoP public key; the task token is bound to it (cnf.jkt).
    dpop: { alg: "EdDSA", jkt: sha256Hex(`jwk:${principal.agentId}:${taskToken}`).slice(0, 43), boundTo: `${taskToken.slice(0, 12)}…` },
    attestedAt: now,
  };
}

export interface IntegrityKey {
  keyId: string;
  secret: Uint8Array;
}

export function generateIntegrityKey(): IntegrityKey {
  const secret = randomBytes(32);
  return { keyId: `satg-hmac-${bytesToHex(sha256(secret)).slice(0, 10)}`, secret };
}

/** The fields a downstream tool re-derives before it acts. */
export interface CanonicalRequest {
  decisionId: string;
  sessionId: string;
  tool: string;
  argsDigest: string;
  manifestHash: string;
  pinnedIp: string | null;
}

export interface RequestIntegrityTag {
  alg: "HMAC-SHA256";
  keyId: string;
  tag: string;
}

export function signRequest(req: CanonicalRequest, key: IntegrityKey): RequestIntegrityTag {
  return { alg: "HMAC-SHA256", keyId: key.keyId, tag: bytesToHex(hmac(sha256, key.secret, utf8ToBytes(canonicalJson(req)))) };
}

/** Tool-side check. Missing, foreign-key or mismatched tags fail closed. */
export function verifyRequest(req: CanonicalRequest, tag: RequestIntegrityTag | undefined, key: IntegrityKey): boolean {
  if (!tag || tag.alg !== "HMAC-SHA256" || tag.keyId !== key.keyId) return false;
  const expected = signRequest(req, key).tag;
  if (expected.length !== tag.tag.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) diff |= expected.charCodeAt(i) ^ tag.tag.charCodeAt(i);
  return diff === 0;
}
