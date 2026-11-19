// receipts.mts — Headless-E2E Etappe 6b (CONCEPT §23): ✓✓ bei Client-Abruf.
// Kette: sender@alpha sendet -> recip@beta ruft Inbox ab -> beta stempelt +
// spiegelt an alpha -> senders /v1/receipts liefert msg_id.
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

const sender = await mkAccount(A, "rcps");
const recip = await mkAccount(B, "rcpr");
topUp(dbA, sender.name, 5_000_000);

// 1) sender@alpha sendet an recip@beta (ohne dass recip auf alpha angelegt ist -> Peer-Föderation!)
const { msg_id } = await composeAndSend(A, sender.token, sender.priv, { to: recip.name + "@beta", subject: "Receipt-Test", body: "ein haken, zwei haken" });
ok(!!msg_id, `send ok msg_id=${msg_id.slice(0, 12)}…`);

// 2) Vor Abruf: noch kein ✓✓
let rc = await getJSON(A + "/v1/receipts", sender.token);
ok(!(rc.receipts || []).some((x: any) => x.msg_id === msg_id), "vor Empfanger-Abruf kein ✓✓ (✓-Stufe)");

// 3) recip ruft Inbox auf beta ab -> Stempel + Mirror nach alpha
let inbox: any = null, found = false;
for (let i = 0; i < 15 && !found; i++) {
  inbox = await getJSON(B + "/v1/inbox", recip.token);
  found = (inbox.messages || []).some((m: any) => b64ToHex(m.msg_id_b64) === msg_id);
  if (!found) await new Promise((r) => setTimeout(r, 800));
}
ok(found, "Empfaenger sieht die Nachricht");
await new Promise((r) => setTimeout(r, 1200));

// 4) sender sieht ✓✓
rc = await getJSON(A + "/v1/receipts", sender.token);
const hit = (rc.receipts || []).find((x: any) => x.msg_id === msg_id);
ok(!!hit, "nach Abruf: ✓✓ beim Absender (cross-relay gemirrort)");
if (hit) ok(hit.ts > 1_700_000_000, `ts plausibel (${hit.ts})`);

// 5) Doppelter Abruf bleibt folgenlos (kein zweiter Eintrag)
await getJSON(B + "/v1/inbox", recip.token);
await new Promise((r) => setTimeout(r, 800));
rc = await getJSON(A + "/v1/receipts", sender.token);
ok((rc.receipts || []).filter((x: any) => x.msg_id === msg_id).length === 1, "Dedup: genau ein Receipt-Eintrag");
