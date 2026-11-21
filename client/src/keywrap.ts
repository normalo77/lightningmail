// keywrap.ts — password-encrypted key files. Write format is LMKEY2 (argon2id,
// M-SEC.1); LMKEY1 (PBKDF2) stays readable forever. WebCrypto (crypto.subtle) is
// unavailable over plain http in the LAN (secure-context requirement), so pure
// noble paths: KDF -> XChaCha20-Poly1305.
import { pbkdf2 } from "@noble/hashes/pbkdf2.js";
import { argon2id } from "@noble/hashes/argon2.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { randomBytes } from "@noble/hashes/utils.js";

const enc = new TextEncoder();
const dec = new TextDecoder();
const ITER = 310_000;

// Canonical LMKEY2 costs. m is KiB in noble AND in x/crypto — same unit, the
// golden fixtures (desktop/core/testdata/m-sec-golden.json) prove parity.
const V2_PARAMS = "m=65536,t=3,p=1";
const ARG_M = 65536, ARG_T = 3, ARG_P = 1, ARG_M_MAX = 1024 * 1024;

const b64 = (b: Uint8Array): string => btoa(String.fromCharCode(...b));
const ub64 = (s: string): Uint8Array => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

export function wrapKey(pem: string, passphrase: string): string {
  if (!passphrase || passphrase.length < 8) throw new Error("Passphrase zu kurz (min. 8 Zeichen)");
  const salt = randomBytes(16);
  const key = argon2id(enc.encode(passphrase), salt, { m: ARG_M, t: ARG_T, p: ARG_P, dkLen: 32 });
  const nonce = randomBytes(24);
  const ct = xchacha20poly1305(key as Uint8Array, nonce).encrypt(enc.encode(pem));
  return `LMKEY2$${V2_PARAMS}$${b64(salt)}$${b64(nonce)}$${b64(ct)}`;
}

export function unwrapKey(fileText: string, passphrase: string): string {
  const parts = fileText.trim().split("$");
  if (parts[0] === "LMKEY1") return unwrapV1(parts, passphrase);
  if (parts[0] === "LMKEY2") return unwrapV2(parts, passphrase);
  throw new Error("kein LMKEY1/LMKEY2-Format");
}

function unwrapV1(parts: string[], passphrase: string): string {
  if (parts.length !== 4) throw new Error("kein LMKEY1-Format");
  if (parts[1] === "PRF") throw new Error("PRF-Wrap — Anmeldung per Passkey nötig");
  const salt = ub64(parts[1]), nonce = ub64(parts[2]), ct = ub64(parts[3]);
  const key = pbkdf2(sha256, enc.encode(passphrase), salt, { c: ITER, dkLen: 32 }) as Uint8Array;
  return openAEAD(key, nonce, ct);
}

function unwrapV2(parts: string[], passphrase: string): string {
  if (parts.length !== 5) throw new Error("kein LMKEY2-Format");
  const [m, t, p] = parseArgonParams(parts[1]);
  const salt = ub64(parts[2]);
  if (salt.length !== 16) throw new Error("kein LMKEY2-Format (Salt)");
  const nonce = ub64(parts[3]);
  if (nonce.length !== 24) throw new Error("kein LMKEY2-Format (Nonce)");
  const key = argon2id(enc.encode(passphrase), salt, { m, t, p, dkLen: 32 }) as Uint8Array;
  return openAEAD(key, nonce, ub64(parts[4]));
}

function openAEAD(key: Uint8Array, nonce: Uint8Array, ct: Uint8Array): string {
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

// Exactly m,t,p accepted — unknown keys throw so nobody silently ignores e.g. m=1M.
function parseArgonParams(s: string): [number, number, number] {
  const vals: Record<string, number> = {};
  for (const kv of s.split(",")) {
    const mm = /^([mtp])=(\d+)$/.exec(kv);
    if (!mm) throw new Error("LMKEY2: unbekannter oder fehlerhafter Parameter '" + kv + "'");
    vals[mm[1]] = Number(mm[2]);
  }
  if (!("m" in vals) || !("t" in vals) || !("p" in vals)) throw new Error("LMKEY2: Parameter m,t,p fehlen");
  if (vals.m < 8 || vals.m > ARG_M_MAX || vals.t < 1 || vals.p < 1) throw new Error("LMKEY2: Parameterwerte nicht unterstuetzt");
  return [vals.m, vals.t, vals.p];
}

export const isWrapped = (t: string): boolean => {
  const s = t.trim();
  return s.startsWith("LMKEY1$") || s.startsWith("LMKEY2$");
};

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
