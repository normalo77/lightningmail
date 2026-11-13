import { readFileSync } from "node:fs";
import { wrapKey, unwrapKey, isWrapped } from "../src/keywrap";
import { parseSec1PEM, pubFromPriv, toHex } from "../src/crypto";

const pem = readFileSync("/root/lightningmail/test/e2e-home/bernd/bernd.key", "utf8");
const ok = (c: boolean, m: string) => { console.log((c ? "PASS " : "FAIL ") + m); if (!c) process.exitCode = 1; };

const w = wrapKey(pem, "sichere-passage-42");
ok(isWrapped(w), "wrap liefert LMKEY1");
ok(!w.includes("PRIVATE KEY"), "Klartext nicht mehr sichtbar");
const u = unwrapKey(w, "sichere-passage-42");
ok(u === pem, "roundtrip == Original-PEM");
ok(toHex(pubFromPriv(parseSec1PEM(u))) === toHex(pubFromPriv(parseSec1PEM(pem))), "entschluesselt == gleicher Schluessel");
let threw = false;
try { unwrapKey(w, "falsche-passage-1"); } catch { threw = true; }
ok(threw, "falsche Passphrase wirft");
threw = false;
try { unwrapKey("Quatsch", "x12345678"); } catch { threw = true; }
ok(threw, "MUell-Format wirft");
threw = false;
try { wrapKey(pem, "kurz"); } catch { threw = true; }
ok(threw, "zu kurze Passphrase abgelehnt");
console.log("EXITCODE", process.exitCode || 0);
