// m-sec-golden.mts — M-SEC.1 parity fixtures: writes desktop/core/testdata/
// m-sec-golden.json (consumed by lm1/crypto/keyfile_test.go). Argon2id is run
// with the canonical costs m=65536 (KiB!), t=3, p=1, dkLen=32 — the exact same
// numbers x/crypto/argon2.IDKey receives Go-side; the JSON is the referee.
import { writeFileSync, mkdirSync } from "node:fs";
import { argon2id } from "@noble/hashes/argon2.js";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { unwrapKey, wrapKey } from "../src/keywrap";
import { FIXED_PEM, ARG, V2_CASES, V1_CASE, PRF_CASE, b64, wrapV1 } from "./m-sec-fixtures.mts";

const enc = new TextEncoder();

const seal = (key: Uint8Array, nonce: Uint8Array): string =>
  b64(xchacha20poly1305(key, nonce).encrypt(enc.encode(FIXED_PEM)));

const unwrap: object[] = [], reject: object[] = [];

for (const c of V2_CASES) {
  const key = argon2id(enc.encode(c.passphrase), c.salt, { m: ARG.m, t: ARG.t, p: ARG.p, dkLen: 32 }) as Uint8Array;
  const line = `LMKEY2$${ARG.params}$${b64(c.salt)}$${b64(c.nonce)}$${seal(key, c.nonce)}`;
  unwrap.push({ name: c.name, line, passphrase: c.passphrase, pem: FIXED_PEM });
}

unwrap.push({ name: V1_CASE.name, line: wrapV1(FIXED_PEM, V1_CASE.passphrase, V1_CASE.salt, V1_CASE.nonce),
  passphrase: V1_CASE.passphrase, pem: FIXED_PEM });

// PRF blob: rejected by the passphrase path before any crypto (LMKEY2 has no PRF branch).
reject.push({ name: PRF_CASE.name, line: `LMKEY1$PRF$${b64(PRF_CASE.nonce)}$${b64(PRF_CASE.ct)}`, passphrase: "irgendeinpass1" });

// Wrong passphrase on the first V2 case.
reject.push({ name: "v2-wrong-passphrase", line: (unwrap[0] as any).line, passphrase: "falsche-passage-9" });

// Unknown parameter (x=...) must throw, not be ignored.
const first = (unwrap[0] as any).line.split("$");
reject.push({ name: "v2-unknown-param", line: `LMKEY2$${first[1]},x=5$${first[2]}$${first[3]}$${first[4]}`, passphrase: V2_CASES[0].passphrase });

// Self-check: this very keywrap.ts must read every fixture it just produced.
for (const c of unwrap as any[]) {
  if (unwrapKey(c.line, c.passphrase) !== FIXED_PEM) throw new Error("FAIL: fixture nicht lesbar: " + c.name);
}
for (const c of reject as any[]) {
  let threw = false;
  try { unwrapKey(c.line, c.passphrase); } catch { threw = true; }
  if (!threw) throw new Error("FAIL: Reject-Fall wurde akzeptiert: " + c.name);
}
if (!wrapKey(FIXED_PEM, "mindestens8").startsWith(`LMKEY2$${ARG.params}$`)) throw new Error("FAIL: Schriftpfad nicht V2");

const json = JSON.stringify({ generated_by: "client/test/m-sec-golden.mts", argon2: { m: ARG.m, t: ARG.t, p: ARG.p, unit: "KiB (noble memoryKiB == x/crypto memory)" }, unwrap, reject }, null, 1);
mkdirSync("desktop/core/testdata", { recursive: true });
writeFileSync("desktop/core/testdata/m-sec-golden.json", json);
console.log(`OK: m-sec-golden.json geschrieben (${unwrap.length} unwrap, ${reject.length} reject)`);
