import { signText, verifyText, type SigningKey } from "./crypto";
import type { DecisionReceipt, ReceiptBody } from "./types";
import { canonicalJson, sha256Hex } from "./util";

/* M10 — Ed25519-signed, SHA-256 hash-chained decision receipts */

export const GENESIS_HASH = "0".repeat(64);

export function signReceipt(body: ReceiptBody, key: SigningKey): DecisionReceipt {
  const canonical = canonicalJson(body);
  return {
    body,
    canonical,
    hash: sha256Hex(canonical),
    signature: signText(canonical, key),
    publicKey: key.publicKeyHex,
  };
}

export interface ReceiptVerification {
  canonicalMatches: boolean;
  hashValid: boolean;
  signatureValid: boolean;
  chainValid: boolean;
  ok: boolean;
}

/**
 * Re-derives everything from the receipt body, so any edit to the body,
 * hash, signature or chain link is detected.
 */
export function verifyReceipt(r: DecisionReceipt, prev: DecisionReceipt | null): ReceiptVerification {
  const canonical = canonicalJson(r.body);
  const canonicalMatches = canonical === r.canonical;
  const hashValid = sha256Hex(canonical) === r.hash;
  const signatureValid = verifyText(canonical, r.signature, r.publicKey);
  const chainValid = r.body.prevHash === (prev ? prev.hash : GENESIS_HASH);
  return { canonicalMatches, hashValid, signatureValid, chainValid, ok: canonicalMatches && hashValid && signatureValid && chainValid };
}
