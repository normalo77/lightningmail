// keywrap.ts — password-encrypted key files in LMKEY1 format.
// WebCrypto (crypto.subtle) is unavailable over plain http in the LAN
// (secure-context requirement), so pure noble paths: PBKDF2-HMAC-SHA256 -> XChaCha20-Poly1305.
import { pbkdf2 } from "@noble/hashes/pbkdf2.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { randomBytes } from "@noble/hashes/utils.js";

const enc = new TextEncoder();
const dec = new TextDecoder();
const ITER = 310_000;

const b64 = (b: Uint8Array): string => btoa(String.fromCharCode(...b));
const ub64 = (s: string): Uint8Array => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

export function wrapKey(pem: string, passphrase: string): string {
  if (!passphrase || passphrase.length < 8) throw new Error("Passphrase zu kurz (min. 8 Zeichen)");
  const salt = randomBytes(16);
  const key = pbkdf2(sha256, enc.encode(passphrase), salt, { c: ITER, dkLen: 32 });
  const nonce = randomBytes(24);
  const ct = xchacha20poly1305(key as Uint8Array, nonce).encrypt(enc.encode(pem));
  return `LMKEY1$${b64(salt)}$${b64(nonce)}$${b64(ct)}`;
}

export function unwrapKey(fileText: string, passphrase: string): string {
  const parts = fileText.trim().split("$");
  if (parts.length !== 4 || parts[0] !== "LMKEY1") throw new Error("kein LMKEY1-Format");
  if (parts[1] === "PRF") throw new Error("PRF-Wrap — Anmeldung per Passkey nötig");
  const salt = ub64(parts[1]), nonce = ub64(parts[2]), ct = ub64(parts[3]);
  const key = pbkdf2(sha256, enc.encode(passphrase), salt, { c: ITER, dkLen: 32 }) as Uint8Array;
  let pem: Uint8Array;
  try {
    pem = xchacha20poly1305(key, nonce).decrypt(ct);
  } catch {
    throw new Error("Passphrase falsch oder Datei beschaedigt");
  }
  const text = dec.decode(pem);
  if (!text.includes("PRIVATE KEY")) throw new Error("Inhalt ist kein Privater Schluessel");
  return text;
}

export const isWrapped = (t: string): boolean => t.trim().startsWith("LMKEY1$");

// --- Etappe 6: PRF wraps (WebAuthn, CONCEPT §21) ---
// The PRF secret (32B, from the authenticator) replaces the passphrase as KDF input:
// format LMKEY1$PRF$<nonce>$<ct>, decryption directly with the secret.

export function prfSalt(address: string): Uint8Array {
  return sha256(enc.encode("lm-prf-v1:" + address));
}

export function wrapKeyPRF(pem: string, secret32: Uint8Array): string {
  if (secret32.length !== 32) throw new Error("PRF-Secret muss 32 Bytes haben");
  const nonce = randomBytes(24);
  const ct = xchacha20poly1305(secret32, nonce).encrypt(enc.encode(pem));
  return `LMKEY1$PRF$${b64(nonce)}$${b64(ct)}`;
}

export function unwrapKeyPRF(fileText: string, secret32: Uint8Array): string {
  const parts = fileText.trim().split("$");
  if (parts.length !== 4 || parts[0] !== "LMKEY1" || parts[1] !== "PRF") throw new Error("kein LMKEY1-PRF-Format");
  let pem: Uint8Array;
  try {
    pem = xchacha20poly1305(secret32, ub64(parts[2])).decrypt(ub64(parts[3]));
  } catch {
    throw new Error("PRF-Schluessel passt nicht zum Wrap");
  }
  const text = dec.decode(pem);
  if (!text.includes("PRIVATE KEY")) throw new Error("Inhalt ist kein Privater Schluessel");
  return text;
}

export const isPRFWrap = (t: string): boolean => t.trim().startsWith("LMKEY1$PRF$");
