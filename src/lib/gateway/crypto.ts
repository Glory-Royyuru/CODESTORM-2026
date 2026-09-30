import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";

/**
 * Gateway signing identity. A fresh Ed25519 key is generated per page load
 * (in production this would live in an HSM / KMS and be rotated).
 */
export interface SigningKey {
  keyId: string;
  secretKey: Uint8Array;
  publicKeyHex: string;
}

export function generateSigningKey(): SigningKey {
  const secretKey = ed25519.utils.randomSecretKey();
  const publicKeyHex = bytesToHex(ed25519.getPublicKey(secretKey));
  return { keyId: `satg-ed25519-${publicKeyHex.slice(0, 8)}`, secretKey, publicKeyHex };
}

export const signText = (text: string, key: SigningKey) => bytesToHex(ed25519.sign(utf8ToBytes(text), key.secretKey));

export function verifyText(text: string, signatureHex: string, publicKeyHex: string): boolean {
  try {
    return ed25519.verify(hexToBytes(signatureHex), utf8ToBytes(text), hexToBytes(publicKeyHex));
  } catch {
    return false;
  }
}
