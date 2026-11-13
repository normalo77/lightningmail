// keywrap.ts — passwort-verschluesselte Key-Dateien im Format LMKEY1.
// WebCrypto (crypto.subtle) faellt im LAN unter http weg (Secure-Context-Pflicht),
// deshalb reine noble-Pfade: PBKDF2-HMAC-SHA256 -> XChaCha20-Poly1305.
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
