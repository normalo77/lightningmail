// lightningmail client crypto — ECHT (mirrors relay/internal/crypto Go byte-for-byte).
// ECIES-light (ECDH secp256k1 + HKDF-SHA256 info=bmail-payload-v1), XChaCha20-Poly1305,
// BIP340-Schnorr, SEC1-PEM, LM1 envelope framing.
import { secp256k1, schnorr } from '@noble/curves/secp256k1.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';

const AUTH_HMAC_KEY = new TextEncoder().encode('bmail-auth-v1');
const PAYLOAD_INFO = new TextEncoder().encode('bmail-payload-v1');
const CHALLENGE_PREFIX = 'bmail-auth-v1:';
const NONCE = 24;

export const toHex = (b: Uint8Array): string => Buffer.from(b).toString('hex');
export const fromHex = (h: string): Uint8Array => new Uint8Array(Buffer.from(h, 'hex'));
export const fromB64 = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, 'base64'));
export const u8 = (s: string): Uint8Array => new TextEncoder().encode(s);

// SEC1 PEM: 30 xx 02 01 01 04 20 <priv32> ...
export function parseSec1PEM(pem: string): Uint8Array {
  const b64 = pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  const der = new Uint8Array(Buffer.from(b64, 'base64'));
  if (der.length < 7 || der[2] !== 0x02 || der[3] !== 0x01 || der[4] !== 0x01 || der[5] !== 0x04 || der[6] !== 0x20) {
    throw new Error('not SEC1 EC private key');
  }
  return der.slice(7, 39);
}

const bytesToNumber = (b: Uint8Array): bigint => BigInt("0x" + Buffer.from(b).toString("hex"));

export function pubFromPriv(priv: Uint8Array): Uint8Array {
  return secp256k1.Point.BASE.multiply(bytesToNumber(priv)).toBytes(true);
}

// Go: digest=HMAC(k=AuthKeyInfo,m=challenge); sig=Sign(priv,digest)= BIP340 über sha256(digest)
export function authSign(priv: Uint8Array, account: string): Uint8Array {
  const challenge = u8(CHALLENGE_PREFIX + account);
  const digest = hmac(sha256, AUTH_HMAC_KEY, challenge);
  return schnorr.sign(sha256(digest), priv);
}

// Verify einer BIP340-Signatur über sha256(msg) — mirror Go Verify()
export function verifySchnorr(pub33: Uint8Array, msg: Uint8Array, sig64: Uint8Array): boolean {
  try { return schnorr.verify(sig64, sha256(msg), pub33); } catch { return false; }
}

function ecdhX(priv: Uint8Array, pubCompressed: Uint8Array): Uint8Array {
  const p = secp256k1.Point.fromHex(toHex(pubCompressed));
  return p.multiply(bytesToNumber(priv)).toBytes(false).slice(1, 33);
}

function deriveKey(secret: Uint8Array): Uint8Array {
  return hkdf(sha256, secret, new Uint8Array(0), PAYLOAD_INFO, 32);
}

export function decryptPayload(priv: Uint8Array, ephPub: Uint8Array, sealed: Uint8Array, aad: Uint8Array): Uint8Array {
  const key = deriveKey(ecdhX(priv, ephPub));
  return xchacha20poly1305(key, sealed.slice(0, NONCE), aad).decrypt(sealed.slice(NONCE));
}

export function encryptPayload(recipientPub: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): { eph: Uint8Array; sealed: Uint8Array } {
  const ephPriv = secp256k1.utils.randomPrivateKey();
  const eph = pubFromPriv(ephPriv);
  const shared = ecdhX(ephPriv, recipientPub);
  const key = deriveKey(shared);
  const nonce = new Uint8Array(24);
  globalThis.crypto.getRandomValues(nonce);
  const c = xchacha20poly1305(key, nonce, aad).encrypt(plaintext);
  return { eph, sealed: new Uint8Array([...nonce, ...c]) };
}

// Envelope LM1: magic 0x4C 0x4D 0x31 0x01, dann [tag(1)|len(2 BE)|value]*
export interface EnvelopeFields { [tag: number]: Uint8Array; }
export function decodeEnvelope(buf: Uint8Array): EnvelopeFields {
  if (buf.length < 4 || buf[0] !== 0x4c || buf[1] !== 0x4d || buf[2] !== 0x31 || buf[3] !== 0x01) throw new Error('bad magic');
  const out: EnvelopeFields = {};
  let o = 4;
  while (o + 3 <= buf.length) {
    const tag = buf[o];
    const len = (buf[o + 1] << 8) | buf[o + 2];
    o += 3;
    if (o + len > buf.length) throw new Error('truncated');
    out[tag] = buf.slice(o, o + len);
    o += len;
  }
  return out;
}

export const TAG = { RecipientHash: 1, MsgID: 2, BlobRefs: 3, SenderPubkey: 4, Signature: 5, Timestamp: 6, Receipt: 7, Payload: 8, Ephemeral: 9 } as const;
export const blobCount = (refs: Uint8Array): number => refs[0];
export const blobRef = (refs: Uint8Array, i: number): Uint8Array => refs.slice(1 + 32 * i, 33 + 32 * i);
export { schnorr, sha256 };
