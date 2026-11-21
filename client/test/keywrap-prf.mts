// keywrap-prf.mts — Etappe 6: PRF wrap roundtrip (runs via `npx tsx test/keywrap-prf.mts`).
// In the real flow the PRF secret comes from the authenticator; simulated deterministically here.
import { wrapKeyPRF, unwrapKeyPRF, unwrapKey, wrapKey, prfSalt } from '../src/keywrap';

const pem = `-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEIFake0fake0fake0fake0fake0fake0fake0\n-----END EC PRIVATE KEY-----`;
const secret = prfSalt('gisela'); // 32 bytes, deterministic
if (secret.length !== 32) throw new Error('FAIL: prfSalt nicht 32 Bytes');

const wrapped = wrapKeyPRF(pem, secret);
if (!wrapped.startsWith('LMKEY1$PRF$')) throw new Error('FAIL: falsches Praefix');
if (unwrapKeyPRF(wrapped, secret) !== pem) throw new Error('FAIL: Roundtrip');

// a wrong key must fail
const wrong = prfSalt('bernd');
let threw = false;
try { unwrapKeyPRF(wrapped, wrong); } catch { threw = true; }
if (!threw) throw new Error('FAIL: falscher PRF-Schluessel wurde akzeptiert');

// passphrase unwrap must reject the PRF blob
threw = false;
try { unwrapKey(wrapped, 'irgendeinpass1'); } catch { threw = true; }
if (!threw) throw new Error('FAIL: unwrapKey akzeptiert PRF-Blob');

// classic LMKEY1 wraps stay readable forever (write path is LMKEY2 since M-SEC.1)
import { wrapV1, V1_CASE } from "./m-sec-fixtures.mts";
const pw = wrapV1(pem, V1_CASE.passphrase, V1_CASE.salt, V1_CASE.nonce);
if (!pw.startsWith("LMKEY1$") || pw.startsWith("LMKEY1$PRF$")) throw new Error("FAIL: Praefix");
if (unwrapKey(pw, V1_CASE.passphrase) !== pem) throw new Error("FAIL: Passphrase-Roundtrip V1");
const pw2 = wrapKey(pem, "notfall-test-123");
if (!pw2.startsWith("LMKEY2$m=65536,t=3,p=1$")) throw new Error("FAIL: Schriftpfad nicht LMKEY2-canonical");
if (unwrapKey(pw2, "notfall-test-123") !== pem) throw new Error("FAIL: Passphrase-Roundtrip V2");

console.log('OK: PRF-Roundtrip, Wrong-Key-Rejection, Format-Trennung, LMKEY1-Kompatibilitaet + LMKEY2-Schriftpfad');
