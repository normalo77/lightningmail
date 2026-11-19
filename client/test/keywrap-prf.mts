// keywrap-prf.mts — Etappe 6: PRF-Wrap-Roundtrip (laeuft via `npx tsx test/keywrap-prf.mts`).
// PRF-Secret kommt im echten Flow vom Authenticator; hier deterministisch simuliert.
import { wrapKeyPRF, unwrapKeyPRF, unwrapKey, wrapKey, prfSalt } from '../src/keywrap';

const pem = `-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEIFake0fake0fake0fake0fake0fake0fake0\n-----END EC PRIVATE KEY-----`;
const secret = prfSalt('gisela'); // 32 Bytes, deterministisch
if (secret.length !== 32) throw new Error('FAIL: prfSalt nicht 32 Bytes');

const wrapped = wrapKeyPRF(pem, secret);
if (!wrapped.startsWith('LMKEY1$PRF$')) throw new Error('FAIL: falsches Praefix');
if (unwrapKeyPRF(wrapped, secret) !== pem) throw new Error('FAIL: Roundtrip');

// falscher Schluessel muss scheitern
const wrong = prfSalt('bernd');
let threw = false;
try { unwrapKeyPRF(wrapped, wrong); } catch { threw = true; }
if (!threw) throw new Error('FAIL: falscher PRF-Schluessel wurde akzeptiert');

// Passphrase-unwrap muss PRF-Blob ablehnen
threw = false;
try { unwrapKey(wrapped, 'irgendeinpass1'); } catch { threw = true; }
if (!threw) throw new Error('FAIL: unwrapKey akzeptiert PRF-Blob');

// klassischer LMKEY1-Wrap bleibt kompatibel
const pw = wrapKey(pem, 'notfall-test-123');
if (!pw.startsWith('LMKEY1$') || pw.startsWith('LMKEY1$PRF$')) throw new Error('FAIL: Praefix');
if (unwrapKey(pw, 'notfall-test-123') !== pem) throw new Error('FAIL: Passphrase-Roundtrip');

console.log('OK: PRF-Roundtrip, Wrong-Key-Rejection, Format-Trennung, LMKEY1-Kompatibilitaet');
