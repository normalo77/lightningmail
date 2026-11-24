// Etappe TL e2e: timelock post against running relayd (regtest alpha).
// Proves: TS envelope tag 0x0B -> Go decode -> mailbox.hold_until -> inbox
// filter -> release. Run on dev-relay: BMAIL_DB=/var/lib/bmail/alpha/ledger.db npx tsx test/tl-hold-test.mts
import { execSync } from "node:child_process";
import { newPrivKey, pubFromPriv, authSign, toHex } from "../src/crypto";
import { composeAndSend } from "../src/send";

const base = process.env.RELAY || "http://127.0.0.1:8443";
const db = process.env.BMAIL_DB || "/var/lib/bmail/alpha/ledger.db";
const ok = (c: boolean, m: string) => { console.log((c ? "PASS " : "FAIL ") + m); if (!c) process.exit(1); };
const post = (path: string, body: any) => fetch(base + path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function mkAccount(): Promise<{ name: string; priv: Uint8Array; token: string }> {
  const priv = newPrivKey();
  const name = "tl" + Date.now().toString(36) + Math.floor(Math.random() * 1e4).toString(36);
  const r = await post("/v1/account", { name, pubkey: toHex(pubFromPriv(priv)) });
  ok(r.status === 200, `account ${name} created (${r.status})`);
  const a = await post("/v1/auth", { address: name, pubkey_hex: toHex(pubFromPriv(priv)), sig: toHex(authSign(priv, name)) });
  const token = ((await a.json()) as any).token;
  ok(!!token, `auth ${name}`);
  return { name, priv, token };
}

const inboxCount = async (token: string): Promise<number> => {
  const r = await fetch(base + "/v1/inbox", { headers: { Authorization: `Bearer ${token}` } });
  const j = (await r.json()) as any;
  return (j.messages || []).length;
};

// Direct sqlite probe (python3 — CT has no sqlite3 CLI). Named bindings via
// env vars (single quotes must never enter the shell string). Returns "[(1,)]".
const sql = (q: string, params: Record<string, string> = {}): string =>
  execSync(`python3 -c 'import sqlite3,os; c=sqlite3.connect(${JSON.stringify(db)}); b={k.lower():v for k,v in os.environ.items() if k.startswith("P")}; print(c.execute(${JSON.stringify(q)}, b).fetchall()); c.commit()'`,
    { encoding: "utf8", env: { ...process.env, ...params } }).trim();
const sqlNum = (q: string, params: Record<string, string> = {}): number =>
  Number(sql(q, params).replace(/[^0-9]/g, "") || "-1");

const sender = await mkAccount();
const recv = await mkAccount();

// 1) Future not_before -> hidden in inbox, present in DB with hold_until>0.
const future = Math.floor(Date.now() / 1000) + 3600;
const out = await composeAndSend(base, sender.token, sender.priv, {
  to: `${recv.name}@alpha`, subject: "TL-held", body: "letter from the future", notBefore: future,
});
ok(!!out.msg_id, `send held letter msg=${String(out.msg_id).slice(0, 10)}`);
await sleep(3000); // keysend settle + ingest
ok((await inboxCount(recv.token)) === 0, "held letter NOT in inbox (hold active)");
const nowSec = Math.floor(Date.now() / 1000);
const held = sqlNum(`SELECT COUNT(*) FROM mailbox m JOIN account a ON a.id=m.account_id WHERE a.name=:p1 AND m.hold_until>CAST(:p2 AS INTEGER)`, { P1: recv.name, P2: String(nowSec) });
ok(held === 1, `DB: exactly one row with future hold_until (got ${held})`);

// 2) Release by time travel, letter surfaces.
sql(`UPDATE mailbox SET hold_until=:p1 WHERE account_id=(SELECT id FROM account WHERE name=:p2) AND hold_until>CAST(:p3 AS INTEGER)`,
  { P1: String(nowSec - 60), P2: recv.name, P3: String(nowSec) });
const r2 = await fetch(base + "/v1/inbox", { headers: { Authorization: `Bearer ${recv.token}` } });
const msgs = ((await r2.json()) as any).messages || [];
ok(msgs.length === 1, "released letter visible in inbox");

// 3) Past not_before behaves like a normal letter (visible immediately).
const out2 = await composeAndSend(base, sender.token, sender.priv, {
  to: `${recv.name}@alpha`, subject: "TL-past", body: "asof now", notBefore: Math.floor(Date.now() / 1000) - 10,
});
ok(!!out2.msg_id, "send with past not_before accepted");
await sleep(3000);
const r3 = await fetch(base + "/v1/inbox", { headers: { Authorization: `Bearer ${recv.token}` } });
ok((((await r3.json()) as any).messages || []).length === 2, "past not_before: visible immediately");

console.log("TL e2e: all checks passed");
