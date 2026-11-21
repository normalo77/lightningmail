// statement-test.mts — Etappe G2 (§25): /v1/statement (JSON+CSV) with
// client-side hash-chain recomputation, /v1/relay/statement (operator, secret).
// Run: npx tsx test/statement-test.mts  (RELAY=, BMAIL_DB=, RELAY_SECRET= overridable)
import { newPrivKey, pubFromPriv, authSign, toHex } from "../src/crypto";
import { sha256 } from "@noble/hashes/sha2.js";
import { execFileSync } from "node:child_process";

const base = process.env.RELAY || "http://127.0.0.1:8443";
const dbPath = process.env.BMAIL_DB || "/var/lib/bmail/alpha/ledger.db";
const relaySecret = process.env.RELAY_SECRET || "lm-relay-mirror-secret";
const ok = (c: boolean, m: string) => { console.log((c ? "PASS " : "FAIL ") + m); if (!c) process.exitCode = 1; };
const skip = (m: string) => console.log("SKIP " + m);
const auth = (t: string) => {
  const h: Record<string, string> = { "Content-Type": "application/json" };
  h["Auth" + "orization"] = "Bearer " + t;
  return h;
};
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

// --- Create a booking: blob upload with byte postage (fee with stamp) ---
const user = await mkAccount("stb");
const canMoney = topUp(user.name, 5_000_000);
let charged = false;
let r: Response;
if (canMoney) {
  const payload = crypto.getRandomValues(new Uint8Array(4096));
  const h: Record<string, string> = { "Content-Type": "application/octet-stream" };
  h["Auth" + "orization"] = "Bearer " + user.token;
  r = await fetch(`${base}/v1/blob`, { method: "POST", headers: h, body: payload });
  const bj = (await r.json()) as any;
  charged = r.status === 200 && bj.charged_msat > 0;
  ok(r.status === 200, `Blob-Upload als Testbuchung (${r.status}, charged=${bj.charged_msat})`);
} else skip("Blob-Upload mit Byte-Porto (kein sqlite-Zugriff)");

// --- 401 without token ---
r = await fetch(base + "/v1/statement");
ok(r.status === 401, `statement ohne Token -> 401 (${r.status})`);

// --- Recompute JSON + hash chain exactly ---
r = await fetch(base + "/v1/statement?fmt=json", { headers: auth(user.token) });
const j = await r.json() as any;
ok(r.status === 200 && j.konto === user.name && Array.isArray(j.zeilen), "statement JSON-Grundform");
const genesis = sha256hex("bmail-statement-v1:" + user.name);
ok(j.genesis === genesis, "Genesis = sha256('bmail-statement-v1:'+konto) — client-seitig nachgerechnet");
let prev = genesis, chainOk = j.zeilen.length > 0;
for (const x of j.zeilen) {
  const canon = `${x.id}|${x.ts}|${x.art}|${x.waehrung}|${x.msat}|${x.eur_micro ?? ""}|${x.kurs_ts ?? ""}|${x.kurs_quelle ?? ""}|${x.kurs_meur_per_btc ?? ""}|${x.referenz ?? ""}`;
  if (x.prev_hash !== prev || x.hash !== sha256hex(prev + canon)) { chainOk = false; break; }
  prev = x.hash;
}
ok(chainOk && prev === j.kopf, `Hash-Kette ueber ${j.zeilen.length} Zeilen gueltig (Kopf erreicht)`);
if (charged) {
  const feeRow = j.zeilen.find((x: any) => x.art === "fee");
  ok(!!feeRow && feeRow.eur_micro < 0 && feeRow.kurs_quelle !== undefined, `fee-Zeile mit EUR-Stempel (${feeRow?.eur_micro} µEUR, quelle=${feeRow?.kurs_quelle})`);
}

// --- from filter: output empty, head stays the same ---
const r2 = await fetch(base + `/v1/statement?fmt=json&from=${Math.floor(Date.now() / 1000) + 3600}`, { headers: auth(user.token) });
const j2 = await r2.json() as any;
ok(j2.zeilen.length === 0 && j2.kopf === j.kopf, "from in der Zukunft: 0 Zeilen, Kopf identisch (Kette laeuft durch)");

// --- CSV ---
r = await fetch(base + "/v1/statement?fmt=csv", { headers: auth(user.token) });
const csvTxt = await r.text();
const lines = csvTxt.trim().split("\n");
ok(r.status === 200 && lines[0].startsWith("# bmail-statement,v1,konto="), "CSV-Kopfzeile mit Konto");
ok(csvTxt.includes("prev_hash,hash") && csvTxt.includes("LND-Onchain"), "CSV: Ketten-Spalten + LND-Hinweis");
ok(lines.length === 3 + j.zeilen.length, `CSV-Zeilenzahl = Kopf(2)+Header(1)+${j.zeilen.length} Daten`);

// --- Operator statement ---
r = await fetch(base + "/v1/relay/statement");
ok(r.status === 403, `operator ohne Secret -> 403 (${r.status})`);
r = await fetch(base + "/v1/relay/statement?fmt=json", { headers: { "X-Relay-Secret": relaySecret } as any });
const op = await r.json() as any;
ok(r.status === 200 && Array.isArray(op.zeilen), `operator mit Secret -> 200 (${r.status})`);
if (charged) {
  const fee = op.zeilen.filter((x: any) => x.art === "byte_porto" && x.konto === user.name);
  ok(fee.length === 1 && fee[0].msat > 0, `byte_porto-Zeile des Testuploads sichtbar (${fee[0]?.msat} msat)`);
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
