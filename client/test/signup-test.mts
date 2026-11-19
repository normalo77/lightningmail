// Etappe 6c: Konto-Erzeugung (Schluessel im Browser) + POST /v1/account + Auth gegen laufendes Relay.
// Ablauf: npx tsx test/signup-test.mts   (RELAY=... ueberschreibbar, Default alpha auf 127.0.0.1:8443)
import { newPrivKey, sec1PEM, parseSec1PEM, pubFromPriv, authSign, toHex } from "../src/crypto";

const base = process.env.RELAY || "http://127.0.0.1:8443";
const ok = (c: boolean, m: string) => { console.log((c ? "PASS " : "FAIL ") + m); if (!c) process.exitCode = 1; };

// --- krypto: PEM roundtrip + Eindeutigkeit ---
const k = newPrivKey();
const pem = sec1PEM(k);
ok(toHex(parseSec1PEM(pem)) === toHex(k), "sec1PEM/parseSec1PEM roundtrip");
const pub = pubFromPriv(k);
ok(pub.length === 33 && (pub[0] === 2 || pub[0] === 3), "pubFromPriv liefert komprimierte 33 Byte");
const keys = new Set(Array.from({ length: 8 }, () => toHex(newPrivKey())));
ok(keys.size === 8, "8 generierte Keys sind eindeutig");

// --- gegen Relay: anlegen, doppelt, nameschecks, login ---
const name = "t" + Date.now().toString(36);
const post = (path: string, body: any) => fetch(base + path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
let r = await post("/v1/account", { name, pubkey: toHex(pub) });
ok(r.status === 200, `POST /v1/account (${name}) -> 200`);
r = await post("/v1/account", { name, pubkey: toHex(pub) });
ok(r.status === 409, "gleicher Name nochmal -> 409");
for (const bad of ["A B", "x", "@start", "mit space", "a".repeat(33)]) {
  r = await post("/v1/account", { name: bad, pubkey: toHex(pub) });
  ok(r.status === 400, `gueltiger-Name-Check: "${bad.slice(0, 12)}" -> 400`);
}
r = await post("/v1/auth", { address: name, pubkey_hex: toHex(pub), sig: toHex(authSign(k, name)) });
ok(r.status === 200, "login mit frischem schluessel -> 200");
const token = ((await r.json()) as any).token;
r = await fetch(base + "/v1/balance", { headers: { Authorization: `Bearer ${token}` } });
const bal = await r.json() as any;
ok(r.status === 200 && bal.balance_msat === 10_000_000, `neues konto hat 10.000 test-satoshis startguthaben (balance ${bal.balance_msat})`);
r = await post("/v1/auth", { address: name, pubkey_hex: toHex(pubFromPriv(newPrivKey())), sig: toHex(authSign(newPrivKey(), name)) });
ok(r.status === 401, "fremder schluessel fuer konto -> 401");
console.log("EXITCODE", process.exitCode || 0);
