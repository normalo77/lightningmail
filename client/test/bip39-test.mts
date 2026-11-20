// bip39-test.mts — Etappe 6d (§27): Wort-Generierung, Checksumme, deterministische
// Ableitung, Quiz-Helfer, Recovery-Roundtrip gegen laufendes Relay.
// Ablauf: npx tsx test/bip39-test.mts   (RELAY= ueberschreibbar, Default alpha)
import { newMnemonic, checkMnemonic, keyFromMnemonic, quizPositions, quizOptions } from "../src/bip39";
import { pubFromPriv, authSign, toHex, validScalar } from "../src/crypto";

const base = process.env.RELAY || "http://127.0.0.1:8443";
const ok = (c: boolean, m: string) => { console.log((c ? "PASS " : "FAIL ") + m); if (!c) process.exitCode = 1; };

// --- Unit: Mnemonic ---
const mn = newMnemonic();
ok(mn.split(" ").length === 24, "neue Mnemonic = 24 Woerter");
ok(checkMnemonic(mn) === mn, "Checksumme gueltig");
ok(checkMnemonic(mn.toUpperCase().replaceAll(" ", ", ")) === mn, "Normalisierung (GROSS/komma) akzeptiert");
const bad = mn.split(" ");
bad[0] = bad[0] === "zoo" ? "abandon" : "zoo";
ok(checkMnemonic(bad.join(" ")) === null, "ein Wort getauscht -> Checksumme fail");
ok(checkMnemonic("quatsch mit sosse") === null, "Müll -> null");

// --- Unit: Ableitung ---
const k1 = keyFromMnemonic(mn);
ok(toHex(keyFromMnemonic(mn)) === toHex(k1), "deterministisch (gleiche Woerter -> gleicher Key)");
ok(validScalar(k1) && k1.length === 32, "gueltiger 32B-Skalar");
ok(toHex(keyFromMnemonic(newMnemonic())) !== toHex(k1), "andere Woerter -> anderer Key");
ok(toHex(keyFromMnemonic(mn, "zusatz")) !== toHex(k1), "BIP39-Passphrase aendert Key");
const pub = pubFromPriv(k1);
ok(pub.length === 33 && (pub[0] === 2 || pub[0] === 3), "Pubkey 33B komprimiert");

// --- Unit: Quiz-Helfer ---
const qs = quizPositions(mn, 3);
ok(qs.length === 3 && qs.every(p => p >= 0 && p < 24) && new Set(qs).size === 3, "3 eindeutige Quiz-Positionen");
const opts = quizOptions(mn, qs[0]);
ok(opts.length === 4 && new Set(opts).size === 4 && opts.includes(mn.split(" ")[qs[0]]), "Quiz-Optionen: 4 eindeutig, inkl. richtige");

// --- Integration: Wizard-Key wird Konto, Recovery-Login funktioniert ---
const name = "wiz" + Date.now().toString(36);
let r = await fetch(base + "/v1/account", { method: "POST", headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ name, pubkey: toHex(pub) }) });
ok(r.status === 200, `POST /v1/account (${name}) -> 200`);
// Recovery-Pfad: Schluessel NUR aus den Woertern neu ableiten und damit authen
const recovered = keyFromMnemonic(checkMnemonic(mn)!);
r = await fetch(base + "/v1/auth", { method: "POST", headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ address: name, pubkey_hex: toHex(pubFromPriv(recovered)), sig: toHex(authSign(recovered, name)) }) });
ok(r.status === 200 && !!((await r.json()) as any).token, "Recovery-Login: aus Woertern abgeleiteter Key authetisiert sich");
console.log("EXITCODE", process.exitCode || 0);
