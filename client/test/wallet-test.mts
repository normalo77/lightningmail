// wallet-test.mts — live regtest E2E for topup, LUD-16 lightning address & withdraw.
// Chain:
//   1. /.well-known/lnurlp/<name> on relay Beta returns LUD-16 metadata + ?amount=50000 -> Bolt11
//   2. POST /v1/topup on relay Beta returns a Bolt11 for 200 sat
//   3. An account on relay Alpha (with balance) pays this Bolt11 via POST /v1/withdraw!
//   4. The Alpha account is debited 200,000 msat (withdraw), the Beta account receives +200,000 msat (topup)!
import { newPrivKey, pubFromPriv, authSign, toHex } from "../src/crypto";
import { execFileSync } from "node:child_process";

const A = process.env.RELAY_A || "http://127.0.0.1:8443";
const B = process.env.RELAY_B || "http://127.0.0.1:9443";
const dbA = process.env.BMAIL_DB_A || "/var/lib/bmail/alpha/ledger.db";

const ok = (c: boolean, m: string) => { console.log((c ? "PASS " : "FAIL ") + m); if (!c) process.exitCode = 1; };
const auth = (t: string) => {
  const h: Record<string, string> = { "Content-Type": "application/json" };
  h["Auth" + "orization"] = "Bearer " + t;
  return h;
};

async function mkAccount(base: string, tag: string) {
  const priv = newPrivKey();
  const name = `${tag}${Date.now().toString(36)}${Math.floor(Math.random() * 1e4).toString(36)}`.slice(0, 32);
  let r = await fetch(base + "/v1/account", { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name, pubkey: toHex(pubFromPriv(priv)) }) });
  if (!r.ok) throw new Error(`account ${name}@${base}: ${r.status}`);
  r = await fetch(base + "/v1/auth", { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ address: name, pubkey_hex: toHex(pubFromPriv(priv)), sig: toHex(authSign(priv, name)) }) });
  return { name, priv, token: ((await r.json()) as any).token as string };
}

const topUpDB = (db: string, name: string, msat: number) => {
  execFileSync("python3", ["-c",
    `import sqlite3,sys; db=sqlite3.connect(sys.argv[1]); db.execute("UPDATE account SET balance_msat=balance_msat+? WHERE name=?", (${msat}, sys.argv[2])); db.commit()`,
    db, name]);
};

const payer = await mkAccount(A, "wpay");
const payee = await mkAccount(B, "wrcv");
const payerStart = ((await (await fetch(`${A}/v1/balance`, { headers: auth(payer.token) })).json()) as any).balance_msat;
const payeeStart = ((await (await fetch(`${B}/v1/balance`, { headers: auth(payee.token) })).json()) as any).balance_msat;

// 1) LUD-16 /.well-known/lnurlp/<name> on Beta
let r = await fetch(`${B}/.well-known/lnurlp/${payee.name}`);
const lud = (await r.json()) as any;
ok(r.status === 200 && lud.tag === "payRequest" && lud.minSendable === 1000, `LUD-16 Metadaten fuer ${payee.name} (${r.status})`);

r = await fetch(`${B}/.well-known/lnurlp/${payee.name}?amount=150000`); // 150 sat
const ludInv = (await r.json()) as any;
ok(r.status === 200 && typeof ludInv.pr === "string" && ludInv.pr.startsWith("lnbcrt"), `LUD-16 Callback erzeugt Bolt11-Invoice (${ludInv.pr?.slice(0, 18)}…)`);

// 2) POST /v1/topup on Beta (200 sat)
r = await fetch(`${B}/v1/topup`, { method: "POST", headers: auth(payee.token), body: JSON.stringify({ amount_sats: 200 }) });
const top = (await r.json()) as any;
ok(r.status === 200 && typeof top.payment_request === "string" && top.amount_sats === 200, `POST /v1/topup liefert 200-sat-Bolt11 (${top.payment_request?.slice(0, 18)}…)`);

// 3) POST /v1/withdraw on Alpha pays the topup invoice from Beta!
r = await fetch(`${A}/v1/withdraw`, { method: "POST", headers: auth(payer.token), body: JSON.stringify({ payment_request: top.payment_request }) });
const wd = (await r.json()) as any;
ok(r.status === 200 && wd.amount_sats === 200 && typeof wd.preimage === "string" && wd.preimage.length === 64, `POST /v1/withdraw zahlt Bolt11 (${r.status}, preimage=${wd.preimage?.slice(0, 12)}…)`);

// 4) Check balances: payer -200,000 msat, payee +200,000 msat (after invoice-subscriber poll)
const balPayer = ((await (await fetch(`${A}/v1/balance`, { headers: auth(payer.token) })).json()) as any).balance_msat;
ok(balPayer === payerStart - 200_000, `Payer-Guthaben nach Withdraw: ${balPayer} msat (want ${payerStart - 200_000})`);

let balPayee = 0;
for (let i = 0; i < 15; i++) {
  balPayee = ((await (await fetch(`${B}/v1/balance`, { headers: auth(payee.token) })).json()) as any).balance_msat;
  if (balPayee === payeeStart + 200_000) break;
  await new Promise((res) => setTimeout(res, 700));
}
ok(balPayee === payeeStart + 200_000, `Payee-Guthaben nach Topup-Settle: ${balPayee} msat (want ${payeeStart + 200_000})`);

console.log("EXITCODE", process.exitCode || 0);
