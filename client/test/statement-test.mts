// statement-test.mts — Etappe G2 (§25): /v1/statement (JSON+CSV) mit
// Hash-Ketten-Nachrechnung im Client, /v1/relay/statement (Betreiber, Secret).
// Ablauf: npx tsx test/statement-test.mts  (RELAY=, BMAIL_DB=, RELAY_SECRET= ueberschreibbar)
import { newPrivKey, pubFromPriv, authSign, toHex } from "../src/crypto";
import { buildCardBytes, signCardBytes, makeConsent, cardToB64 } from "../src/directory";
import { sha256 } from "@noble/hashes/sha2.js";
import { execFileSync } from "node:child_process";

const base = process.env.RELAY || "http://127.0.0.1:8443";
const dbPath = process.env.BMAIL_DB || "/var/lib/bmail/alpha/ledger.db";
const relaySecret = process.env.RELAY_SECRET || "lm-relay-mirror-secret";
const ok = (c: boolean, m: string) => { console.log((c ? "PASS " : "FAIL ") + m); if (!c) process.exitCode = 1; };
const skip = (m: string) => console.log("SKIP " + m);
const auth = (t: string) => ({ "Content-Type": "application/json", Authorization: `Bearer ${t}` } as any);
const sha256hex = (s: string) => toHex(sha256(new TextEncoder().encode(s)));

async function mkAccount(tag: string) {
  const priv = newPrivKey();
  const name = `${tag}${Date.now().toString(36)}${Math.floor(Math.random() * 1e4).toString(36)}`.slice(0, 32);
  let r = await fetch(base + "/v1/account", { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name, pubkey: toHex(pubFromPriv(priv)) }) });
  if (!r.ok) throw new Error(`account ${name}: ${r.status}`);
  r = await fetch(base + "/v1/auth", { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ address: name, pubkey_hex: toHex(pubFromPriv(priv)), sig: toHex(authSign(priv, name)) }) });
  return { name, priv, token: ((await r.json()) as any).token as string };
}
const topUp = (name: string, msat: number): boolean => {
  try {
    execFileSync("python3", ["-c",
      `import sqlite3,sys; db=sqlite3.connect(sys.argv[1]); db.execute("UPDATE account SET balance_msat=balance_msat+? WHERE name=?", (${msat}, sys.argv[2])); db.commit()`,
      dbPath, name]);
    return true;
  } catch { return false; }
};

// --- Buchungen erzeugen: Kartenkauf (card_out mit Stempel + card_in beim Verkaufer) ---
const seller = await mkAccount("sts");
const buyer = await mkAccount("stb");
const cardBytes = buildCardBytes({ name: "Statement", email: "s@example.org" });
let r = await fetch(base + "/v1/profile", { method: "PUT", headers: auth(seller.token),
  body: JSON.stringify({ card_b64: cardToB64(cardBytes), sig: signCardBytes(seller.priv, cardBytes), consent: makeConsent(cardBytes), price_meur: 25 }) });
if (!r.ok) throw new Error("profile PUT " + r.status);
const canMoney = topUp(buyer.name, 5_000_000);
let bought = false;
if (canMoney) {
  r = await fetch(`${base}/v1/profile/${seller.name}/card`, { method: "POST", headers: auth(buyer.token) });
  bought = r.status === 200;
  ok(bought, `Kartenkauf als Testbuchung (${r.status})`);
} else skip("Kartenkauf (kein sqlite-Zugriff)");

// --- 401 ohne Token ---
r = await fetch(base + "/v1/statement");
ok(r.status === 401, `statement ohne Token -> 401 (${r.status})`);

// --- JSON + Hash-Kette exakt nachrechnen ---
r = await fetch(base + "/v1/statement?fmt=json", { headers: auth(buyer.token) });
const j = await r.json() as any;
ok(r.status === 200 && j.konto === buyer.name && Array.isArray(j.zeilen), "statement JSON-Grundform");
const genesis = sha256hex("bmail-statement-v1:" + buyer.name);
ok(j.genesis === genesis, "Genesis = sha256('bmail-statement-v1:'+konto) — client-seitig nachgerechnet");
let prev = genesis, chainOk = j.zeilen.length > 0;
for (const x of j.zeilen) {
  const canon = `${x.id}|${x.ts}|${x.art}|${x.waehrung}|${x.msat}|${x.eur_micro ?? ""}|${x.kurs_ts ?? ""}|${x.kurs_quelle ?? ""}|${x.kurs_meur_per_btc ?? ""}|${x.referenz ?? ""}`;
  if (x.prev_hash !== prev || x.hash !== sha256hex(prev + canon)) { chainOk = false; break; }
  prev = x.hash;
}
ok(chainOk && prev === j.kopf, `Hash-Kette ueber ${j.zeilen.length} Zeilen gueltig (Kopf erreicht)`);
if (bought) {
  const co = j.zeilen.find((x: any) => x.art === "card_out");
  ok(!!co && co.eur_micro < 0 && co.kurs_quelle !== undefined, `card_out-Zeile mit EUR-Stempel (${co?.eur_micro} µEUR, quelle=${co?.kurs_quelle})`);
}

// --- from-Filter: Ausgabe leer, Kopf bleibt derselbe ---
const r2 = await fetch(base + `/v1/statement?fmt=json&from=${Math.floor(Date.now() / 1000) + 3600}`, { headers: auth(buyer.token) });
const j2 = await r2.json() as any;
ok(j2.zeilen.length === 0 && j2.kopf === j.kopf, "from in der Zukunft: 0 Zeilen, Kopf identisch (Kette laeuft durch)");

// --- CSV ---
r = await fetch(base + "/v1/statement?fmt=csv", { headers: auth(buyer.token) });
const csvTxt = await r.text();
const lines = csvTxt.trim().split("\n");
ok(r.status === 200 && lines[0].startsWith("# bmail-statement,v1,konto="), "CSV-Kopfzeile mit Konto");
ok(csvTxt.includes("prev_hash,hash") && csvTxt.includes("LND-Onchain"), "CSV: Ketten-Spalten + LND-Hinweis");
ok(lines.length === 3 + j.zeilen.length, `CSV-Zeilenzahl = Kopf(2)+Header(1)+${j.zeilen.length} Daten`);

// --- Betreiber-Statement ---
r = await fetch(base + "/v1/relay/statement");
ok(r.status === 403, `operator ohne Secret -> 403 (${r.status})`);
r = await fetch(base + "/v1/relay/statement?fmt=json", { headers: { "X-Relay-Secret": relaySecret } as any });
const op = await r.json() as any;
ok(r.status === 200 && Array.isArray(op.zeilen), `operator mit Secret -> 200 (${r.status})`);
if (bought) {
  const fee = op.zeilen.filter((x: any) => x.art === "card_fee" && x.konto === buyer.name);
  ok(fee.length === 1 && fee[0].msat > 0, `card_fee-Zeile des Testkaufs sichtbar (${fee[0]?.msat} msat)`);
  let opPrev = sha256hex("bmail-operator-v1:" + op.relay);
  const opChain = op.zeilen.every((x: any) => {
    const canon = `${x.quelle}|${x.id}|${x.ts}|${x.konto}|${x.art}|${x.msat}|${x.eur_micro ?? ""}|${x.kurs_ts ?? ""}|${x.kurs_quelle ?? ""}|${x.kurs_meur_per_btc ?? ""}|${x.referenz ?? ""}`;
    const good = x.prev_hash === opPrev && x.hash === sha256hex(opPrev + canon);
    opPrev = x.hash;
    return good;
  });
  ok(opChain && opPrev === op.kopf, "Operator-Hash-Kette gueltig");
}

console.log("EXITCODE", process.exitCode || 0);
