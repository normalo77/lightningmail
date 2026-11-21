// alice-bob-mailcheck.mts — the classic correspondence: alice@alpha -> bob@beta.
import { readFileSync } from "node:fs";
import { parseSec1PEM, pubFromPriv, authSign, toHex } from "../src/crypto";
import { composeAndSend } from "../src/send";

const A = "http://127.0.0.1:8443", B = "http://127.0.0.1:9443";
const ok = (c: boolean, m: string) => { console.log((c ? "PASS " : "FAIL ") + m); if (!c) process.exitCode = 1; };
const load = (n: string) => parseSec1PEM(readFileSync(`app/public/keys/${n}.key`, "utf8"));
async function tok(base: string, name: string, priv: Uint8Array) {
  const r = await fetch(base + "/v1/auth", { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ address: name, pubkey_hex: toHex(pubFromPriv(priv)), sig: toHex(authSign(priv, name)) }) });
  ok(r.ok, `auth ${name} -> ${r.status}`);
  return ((await r.json()) as any).token as string;
}
const pa = load("alice"), pb = load("bob");
const ta = await tok(A, "alice", pa), tb = await tok(B, "bob", pb);
const { msg_id } = await composeAndSend(A, ta, pa, { to: "bob", subject: "Hallo Bob", body: "alice war hier" });
ok(!!msg_id, `alice->bob send ok ${String(msg_id).slice(0, 10)}…`);
await new Promise((r) => setTimeout(r, 1500));
const ir = await fetch(B + "/v1/inbox", { headers: { Authorization: `Bearer ${tb}` } });
const inbox = (await ir.json()) as any;
ok((inbox.messages || []).length > 0, `bob inbox: ${(inbox.messages || []).length} mail(s)`);
