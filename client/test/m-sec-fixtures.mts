// m-sec-fixtures.mts — deterministic constants shared by m-sec-golden.mts and
// keywrap tests (M-SEC.1 parity fixtures). Same values are consumed Go-side by
// lm1/crypto/keyfile_test.go via the generated JSON.
import { Buffer } from "node:buffer";
import { webcrypto } from "node:crypto";

// Node 18 has no global crypto (noble's randomBytes needs it) — tsx tests only.
if (!(globalThis as any).crypto) (globalThis as any).crypto = webcrypto;

export const FIXED_PEM = `-----BEGIN EC PRIVATE KEY-----
MFQCAQEEIKurq6urq6urq6urq6urq6urq6urq6urq6urq6urq6uroAcGBSuBBAAK
oSQDIgADgaqtyKXoP0V234I88ipbGWnPcEoNX29ovXV0EMmReqw=
-----END EC PRIVATE KEY-----
`;

export const bytes = (start: number, n: number): Uint8Array =>
  Uint8Array.from({ length: n }, (_, i) => start + i);

// Canonical LMKEY2 costs (m in KiB — identical unit in noble and x/crypto).
export const ARG = { m: 65536, t: 3, p: 1, params: "m=65536,t=3,p=1" };

export const V2_CASES = [
  { name: "v2-wordlist", passphrase: "korrekt-horse-battery-staple", salt: bytes(0x00, 16), nonce: bytes(0x10, 24) },
  { name: "v2-umlaut-utf8", passphrase: "Paßwort-mit-ÄÖÜ-1234", salt: bytes(0xa0, 16), nonce: bytes(0xb0, 24) },
  { name: "v2-min8", passphrase: "abcdefgh", salt: bytes(0xf0, 16), nonce: bytes(0x01, 24) },
];

export const V1_CASE = { name: "v1-legacy-pbkdf2", passphrase: "sichere-passage-42",
  salt: bytes(0x50, 16), nonce: bytes(0x60, 24), iter: 310_000 };

export const PRF_CASE = { name: "prf-reject", nonce: bytes(0x00, 24), ct: bytes(0x00, 32) };

export const b64 = (b: Uint8Array): string => Buffer.from(b).toString("base64");

import { pbkdf2 } from "@noble/hashes/pbkdf2.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";

// Standalone V1 LMKEY1 writer for tests (the production write path is V2 now).
export function wrapV1(pem: string, passphrase: string, salt: Uint8Array, nonce: Uint8Array): string {
  const enc = new TextEncoder();
  const key = pbkdf2(sha256, enc.encode(passphrase), salt, { c: V1_CASE.iter, dkLen: 32 }) as Uint8Array;
  return `LMKEY1$${b64(salt)}$${b64(nonce)}$${b64(xchacha20poly1305(key, nonce).encrypt(enc.encode(pem)))}`;
}
