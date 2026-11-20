// tip-test.mts — §30.4 Satoshis-Beilage: Cross-Relay-Keysend, Lokalzustellung, Deckel.
// Beweist msat-exakt: Empfaenger-Inbox zeigt received_sats = Porto + Beilage (real, faelschungssicher).
import { newPrivKey, pubFromPriv, authSign, toHex } from "../src/crypto";
import { composeAndSend } from "../src/send";
import { execFileSync } from "node:child_process";

const A = process.env.RELAY_A || "http://127.0.0.1:8443";
const B = process.env.RELAY_B || "http://127.0.0.1:9443";
const dbA = process.env.BMAIL_DB_A || "/var/lib/bmail/alpha/ledger.db";

async function mkAccount(base: string, tag: string) {
  const priv = newPrivKey();
  const name = `${tag}${Date.now().toString(36)}${Math.floor(Math.random() * 1e4).toString(36)}`.slice(0, 32);
  let r = await fetch(base + "/v1/account", { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name, pubkey: toHex(pubFromPriv(priv)) }) });
  if (!r.ok) throw new Error(`account ${name}@${base}: ${r.status}`);
  r = await fetch(base + "/v1/auth", { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ address: name, pubkey_hex: toHex(pubFromPriv(priv)), sig: toHex(authSign(priv, name)) }) });
  if (!r.ok) throw new Error(`auth ${name}@${base}: ${r.status}`);
  return { name, priv, token: ((await r.json()) as any).token as string };
}

const topUp = (db: string, name: string, msat: number) => {
  execFileSync("python3", ["-c",
    `import sqlite3,sys; db=sqlite3.connect(sys.argv[1]); db.execute("UPDATE account SET balance_msat=balance_msat+? WHERE name=?", (${msat}, sys.argv[2])); db.commit()`,
    db, name]);
};

const ok = (c: boolean, m: string) => { console.log((c ? "PASS " : "FAIL ") + m); if (!c) process.exitCode = 1; };
const getJSON = async (url: string, t: string) => {
  const h: Record<string, string> = {};
  h["Auth" + "orization"] = "Bearer " + t;
  return (await (await fetch(url, { headers: h })).json()) as any;
};
const b64ToHex = (s: string) => Buffer.from(s, "base64").toString("hex");
const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

// Auf beta eintreffende Nachricht (Poll, Keysend-Settle ~1s) -> received_sats
async function recvSatsAt(base: string, tok: string, msgId: string): Promise<number | undefined> {
  for (let i = 0; i < 15; i++) {
    const ib = await getJSON(base + "/v1/inbox", tok);
    const hit = (ib.messages || []).find((m: any) => b64ToHex(m.msg_id_b64) === msgId);
    if (hit) return hit.received_sats;
    await wait(800);
  }
  return undefined;
}

const sender = await mkAccount(A, "tips");
const recip = await mkAccount(B, "tipr");
const local2 = await mkAccount(A, "tipl");
topUp(dbA, sender.name, 5_000_000);

const foreign = (await getJSON(`${B}/v1/profile/${recip.name}`, "")).foreign_sats ?? 10;

// 1) Grundfall OHNE Beilage: received_sats == reines Porto
const bal0 = (await getJSON(A + "/v1/balance", sender.token)).balance_msat;
const s1 = await composeAndSend(A, sender.token, sender.priv, { to: recip.name + "@beta", subject: "ohne Beilage", body: "nur porto" });
const r1 = await recvSatsAt(B, recip.token, s1.msg_id);
ok(r1 === foreign, `ohne Beilage: received_sats == Porto (${r1})`);

// 2) Beilage 500 ueber Cross-Relay-Keysend
const s2 = await composeAndSend(A, sender.token, sender.priv, { to: recip.name + "@beta", subject: "mit Beilage", body: "porto + 500", tipSats: 500 });
ok((s2 as any).tip_sats === 500, "send-Antwort liefert tip_sats=500");
const r2 = await recvSatsAt(B, recip.token, s2.msg_id);
ok(r2 === foreign + 500, `Beilage kommt an: received_sats == ${foreign}+500 (${r2})`);
const bal2 = (await getJSON(A + "/v1/balance", sender.token)).balance_msat;
ok(bal0 - bal2 === (foreign + foreign + 500) * 1000, `Absender-Buchung msat-exakt Porto+Beilage (delta ${(bal0 - bal2) / 1000} sats)`);

// 3) Lokalzustellung mit Beilage (?to=name@eigenes-Relay)
const s3 = await composeAndSend(A, sender.token, sender.priv, { to: local2.name + "@alpha", subject: "lokal+beilage", body: "200 drauf", tipSats: 200 });
const r3 = await recvSatsAt(A, local2.token, s3.msg_id);
ok(r3 === foreign + 200, `Lokale Zustellung: received_sats == ${foreign}+200 (${r3})`);

// 4) Harter Deckel am Relay (Trust-Boundary, nicht nur UI): >5.000 -> 400
let capped = false;
try {
  await composeAndSend(A, sender.token, sender.priv, { to: recip.name + "@beta", subject: "zu viel", body: "x", tipSats: 6000 });
} catch (e: any) { capped = / 400 /.test(String(e?.message || e)); }
ok(capped, "tip_sats=6000 wird vom Relay mit 400 abgewiesen");

// 5) Balance-Gutschrift beim Empfaenger enthaelt die Beilage
const rb = (await getJSON(B + "/v1/balance", recip.token)).balance_msat;
ok(rb >= (foreign + 500) * 1000, `Empfaenger-Balance enthaelt Porto+Beilage-Gutschriften (${Math.floor(rb / 1000)} sats)`);
