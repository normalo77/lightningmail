// m-r-spool.mts — Etappe R: Outbox-API + Anzeige-Pfade mit seedbarer pending/dead-Row.
// Der Parent-orchestrierte Teil (beta stoppen/starten, echte Zustellung nach
// "Heben") kann kein unit-taugliches tsx leisten — dieser Teil prueft API-Form
// und Seed-Logik gegen ein laufendes System; pending/dead-Rows werden direkt per
// sqlite inserted (chunk-test-Muster). UI-Chips: Parent-Browsercheck (kein DOM hier).
// Run: npx tsx test/m-r-spool.mts   (RELAY_A=, BMAIL_DB_A=)
import { newPrivKey, pubFromPriv, authSign, toHex } from "../src/crypto";
import { execFileSync } from "node:child_process";
import { webcrypto } from "node:crypto";
(globalThis as any).crypto ??= webcrypto; // node <19 (Hermes host): src/crypto braucht globalThis.crypto

const baseA = process.env.RELAY_A || "http://127.0.0.1:8443";
const dbA = process.env.BMAIL_DB_A || "/var/lib/bmail/alpha/ledger.db";
const ok = (c: boolean, m: string) => { console.log((c ? "PASS " : "FAIL ") + m); if (!c) process.exitCode = 1; };
const skip = (m: string) => console.log("SKIP " + m);
const hdr = (t: string) => ({ ["Auth" + "orization"]: "Bearer" + " " + t } as Record<string, string>);
const rh = () => [...globalThis.crypto.getRandomValues(new Uint8Array(32))].map(b => b.toString(16).padStart(2, "0")).join("");

// --- 1. Account + Basisform der API ---
const priv = newPrivKey();
const name = `spool${Date.now().toString(36)}${Math.floor(Math.random() * 1e4).toString(36)}`.slice(0, 32);
let token = "";
{
  const r = await fetch(baseA + "/v1/account", { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name, pubkey: toHex(pubFromPriv(priv)) }) });
  if (!r.ok) { console.log("FAIL account: " + r.status + " " + await r.text()); process.exit(1); }
  const a = await fetch(baseA + "/v1/auth", { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ address: name, pubkey_hex: toHex(pubFromPriv(priv)), sig: toHex(authSign(priv, name)) }) });
  if (!a.ok) { console.log("FAIL auth: " + a.status); process.exit(1); }
  token = ((await a.json()) as any).token as string;
}
const ob = async (): Promise<any[]> => {
  const r = await fetch(baseA + "/v1/outbox", { headers: hdr(token) });
  if (!r.ok) throw new Error("outbox: " + r.status);
  return await r.json() as any[];
};
let list = await ob();
ok(Array.isArray(list), "GET /v1/outbox -> JSON-Array");

// --- 2. /health Spool-Zaehler (Etappe-R-Monitoring) ---
{
  const h = await (await fetch(baseA + "/health")).json() as any;
  ok(typeof h?.spool?.pending === "number", `/health spool.pending numeric (${h?.spool?.pending})`);
}

// --- 3-5. Seed-Teil: direct sqlite (Chunk-Test-Muster), sonst SKIP ---
const sql = (q: string, ...params: (string | number)[]): string =>
  execFileSync("python3", ["-c",
    "import sqlite3,sys,json; db=sqlite3.connect(sys.argv[1]); cur=db.execute(sys.argv[2], tuple(json.loads(sys.argv[3]))); db.commit(); print(cur.rowcount)",
    dbA, q, JSON.stringify(params)]).toString().trim();
let canSqlite = true;
try { sql("SELECT 1"); } catch { canSqlite = false; }
if (!canSqlite) {
  skip("Seed-Checks (kein sqlite-Zugriff auf " + dbA + ")");
} else {
  const now = Math.floor(Date.now() / 1000);
  const idP = rh(), idD = rh();
  // next_try in der Ferne: der echte 60s-Ticker darf die Seed-Mails nicht
  // mit fake dest_node zustellen versuchen. DDL/Spalten = relay pending_send.
  const ins = (id: string, status: string, next: number, created: number) => sql(
    `INSERT OR REPLACE INTO pending_send (msg_id, account, recipient, dest_node, envelope, blob_refs, sats, status, attempts, next_try, created_at, updated_at)
     VALUES (?,?,?,?,X'00','[]',10,?,0,?,?,?)`, id, name, "seed@beta", "02aa", status, next, created, now);
  ins(idP, "pending", now + 31536000, now - 600);
  ins(idD, "dead", now - 1, now - 86400);
  list = await ob();
  const eP = list.find(x => x.msg_id === idP), eD = list.find(x => x.msg_id === idD);
  ok(!!eP && eP.status === "pending" && eP.since === now - 600, "outbox zeigt pending-Chip-Zeile (status+since)");
  ok(!!eD && eD.status === "dead", "outbox zeigt dead-Zeile (Porto zurueckerstattet-Chip)");
  // "settled" heisst: Zeile raus — Ticker loescht bei Zustellung, nicht status-Wechsel
  sql(`DELETE FROM pending_send WHERE msg_id=?`, idP);
  list = await ob();
  ok(!list.some(x => x.msg_id === idP) && list.some(x => x.msg_id === idD), "Zustellung (Zeile geloescht) -> outbox nur noch dead");
  sql(`DELETE FROM pending_send WHERE msg_id=?`, idD);
  list = await ob();
  ok(!list.some(x => x.msg_id === idD), "Cleanup: Seed-Rows raus");
}
if (!process.exitCode) console.log("m-r-spool: alle Checks gruen");
