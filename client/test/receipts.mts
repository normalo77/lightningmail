// receipts.mts — Headless-E2E Etappe 6b (CONCEPT §23): ✓✓ bei Client-Abruf.
// Kette: gisela@alpha sendet -> bernd@beta ruft Inbox ab -> beta stempelt +
// spiegelt an alpha -> giselas /v1/receipts liefert msg_id.
// Lauf: cd client/ && npx tsx test/receipts.mts   (systemd-Relays + regtest-LND muessen laufen)
import { readFileSync } from "node:fs";
import { parseSec1PEM, pubFromPriv, authSign, toHex } from "../src/crypto";
import { composeAndSend } from "../src/send";

const A = "http://127.0.0.1:8443"; // alpha (gisela)
const B = "http://127.0.0.1:9443"; // beta  (bernd)
const load = (n: string) => parseSec1PEM(readFileSync(`/root/lightningmail/client/app/public/keys/${n}.key`, "utf8"));

async function tok(base: string, name: string): Promise<string> {
  const priv = load(name);
  const r = await fetch(base + "/v1/auth", { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ address: name, pubkey_hex: toHex(pubFromPriv(priv)), sig: toHex(authSign(priv, name)) }) });
  if (!r.ok) throw new Error(`auth ${name}@${base}: ${r.status} ${await r.text()}`);
  return ((await r.json()) as any).token;
}
const ok = (c: boolean, m: string) => { console.log((c ? "PASS " : "FAIL ") + m); if (!c) process.exitCode = 1; };
const getJSON = async (url: string, t: string) => (await (await fetch(url, { headers: { Authorization: `Bearer ${t}` } })).json()) as any;
const b64ToHex = (s: string) => Buffer.from(s, "base64").toString("hex");

const tG = await tok(A, "gisela"), tB = await tok(B, "bernd");

// 1) Gisela sendet an bernd@beta
const { msg_id } = await composeAndSend(A, tG, load("gisela"), { to: "bernd", subject: "Receipt-Test", body: "ein haken, zwei haken" });
ok(!!msg_id, `send ok msg_id=${msg_id.slice(0, 12)}…`);

// 2) Vor Abruf: noch kein ✓✓
let rc = await getJSON(A + "/v1/receipts", tG);
ok(!(rc.receipts || []).some((x: any) => x.msg_id === msg_id), "vor Empfanger-Abruf kein ✓✓ (✓-Stufe)");

// 3) Bernd ruft Inbox auf beta ab -> Stempel + Mirror nach alpha
// (keysend-Settle + Ingest dauern ~1s → Polling statt Sofort-Abruf)
let inbox: any = null, found = false;
for (let i = 0; i < 15 && !found; i++) {
  inbox = await getJSON(B + "/v1/inbox", tB);
  found = (inbox.messages || []).some((m: any) => b64ToHex(m.msg_id_b64) === msg_id);
  if (!found) { ok(true, `warte auf Zustellung… (${i + 1}s)`); await new Promise((r) => setTimeout(r, 1000)); }
}
ok(found, "Bernd sieht die Nachricht");
await new Promise((r) => setTimeout(r, 1500)); // async-Mirror abwarten

// 4) Gisela sieht ✓✓
rc = await getJSON(A + "/v1/receipts", tG);
const hit = (rc.receipts || []).find((x: any) => x.msg_id === msg_id);
ok(!!hit, "nach Abruf: ✓✓ bei Gisela (cross-relay gemirrort)");
if (hit) ok(hit.ts > 1_700_000_000, `ts plausibel (${hit.ts})`);

// 5) Doppelter Abruf bleibt folgenlos (kein zweiter Eintrag)
await getJSON(B + "/v1/inbox", tB);
await new Promise((r) => setTimeout(r, 800));
rc = await getJSON(A + "/v1/receipts", tG);
ok((rc.receipts || []).filter((x: any) => x.msg_id === msg_id).length === 1, "Dedup: genau ein Receipt-Eintrag");
