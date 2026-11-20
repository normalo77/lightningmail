/**
 * bmail client crypto — E2EE primitives (stubs for PWA).
 * Full implementation loads libsodium.js for XChaCha20-Poly1305 + Ed25519.
 * Reference: relay/internal/crypto/ (Go) for the authoritative implementation.
 * Wire format: proto/bmail/v1/envelope.proto.
 *
 * shortcut: stubs return placeholders; real sodium integration M2+.
 * Verify against interop test: test/interop.sh + test/interop-client.mjs.
 */

export interface Envelope {
  senderPubkey: Uint8Array;   // 33 bytes compressed secp256k1
  recipientHash: Uint8Array;  // 32 bytes sha256(recipient pubkey)
  msgId: Uint8Array;          // 32 bytes random
  ciphertext: Uint8Array;     // 24B nonce + XChaCha20-Poly1305 ct||tag
  signature: Uint8Array;      // 64 bytes BIP340 Schnorr
  ephemeralPubkey?: Uint8Array; // 33 bytes ECIES senderkey
}

// toHex converts bytes to lowercase hex string.
export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// fromHex parses a hex string to bytes.
export function fromHex(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

// toBase64 converts bytes to standard base64.
export function toBase64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

// fromBase64 decodes a standard base64 string.
export function fromBase64(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}