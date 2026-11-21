import { wrapKey, unwrapKey, isWrapped } from "../src/keywrap";
import { pubFromPriv, parseSec1PEM, toHex } from "../src/crypto";
import { FIXED_PEM, V1_CASE, wrapV1, ARG } from "./m-sec-fixtures.mts";

const pem = FIXED_PEM;
const ok = (c: boolean, m: string) => { console.log((c ? "PASS " : "FAIL ") + m); if (!c) process.exitCode = 1; };

// --- M-SEC.1: canonicaler Schriftpfad ist LMKEY2 (argon2id) ---
const w2 = wrapKey(pem, "sichere-passage-42");
ok(isWrapped(w2) && w2.startsWith(`LMKEY2$${ARG.params}$`), "wrap liefert LMKEY2 canonical");
ok(!w2.includes("PRIVATE KEY"), "Klartext nicht mehr sichtbar");
ok(unwrapKey(w2, "sichere-passage-42") === pem, "V2 roundtrip == Original-PEM");
let threw = false;
try { unwrapKey(w2, "falsche-passage-1"); } catch { threw = true; }
ok(threw, "V2 falsche Passphrase wirft");

// --- LMKEY1 bleibt für alle Ewigkeit lesbar (selbst erzeugt, Fixture-Format) ---
const w1 = wrapV1(pem, V1_CASE.passphrase, V1_CASE.salt, V1_CASE.nonce);
ok(w1.startsWith("LMKEY1$") && isWrapped(w1), "V1-Datei wird als gewrappt erkannt");
ok(unwrapKey(w1, V1_CASE.passphrase) === pem, "V1 roundtrip == Original-PEM");
threw = false;
try { unwrapKey(w1, "falsche-passage-1"); } catch { threw = true; }
ok(threw, "V1 falsche Passphrase wirft");
ok(toHex(pubFromPriv(parseSec1PEM(unwrapKey(w1, V1_CASE.passphrase)))) === toHex(pubFromPriv(parseSec1PEM(pem))), "entschluesselt == gleicher Schluessel");

// --- V2-Paranoia: unbekannter Parameter darf nicht ignoriert werden ---
threw = false;
try { unwrapKey(w2.replace(`$${ARG.params}$`, `$${ARG.params},x=5$`), "sichere-passage-42"); } catch { threw = true; }
ok(threw, "unbekannter LMKEY2-Parameter wirft");

threw = false;
try { unwrapKey("Quatsch", "x12345678"); } catch { threw = true; }
ok(threw, "MUell-Format wirft");
threw = false;
try { wrapKey(pem, "kurz"); } catch { threw = true; }
ok(threw, "zu kurze Passphrase abgelehnt");
console.log("EXITCODE", process.exitCode || 0);
