// m-r-live.mts — proof of Etappe R against the real regtest relays.
// Runner must STOP beta first: script sends (expects spool-pending), starts beta,
// forces next_try, waits for the ticker, and asserts exactly-once late delivery.
import { composeAndSend } from "../src/send.ts";
import { pubFromPriv, toHex, authSign, decodeEnvelope, decryptPayload, fromB64, TAG } from "../src/crypto.ts";
import { readFileSync } from "node:fs";
import { execSync } from "node:child_process";

const base = process.env.RELAY_A || "http://127.0.0.1:8443";
const baseB = process.env.RELAY_B || "http://127.0.0.1:9443";
const secrets = "/root/lightningmail/client/app/public/keys";
const ok = (c: boolean, m: string) => console.log((c ? "PASS " : "FAIL ") + m);

function pemPriv(path: string): Uint8Array {
  const b = atob(readFileSync(path, "utf8").split(/[\n-]+/).filter((l) => /^[A-Za-z0-9+/=]{20,}$/.test(l)).join(""));
  const der = Uint8Array.from(b, (c) => c.charCodeAt(0));
  for (let i = 0; i + 33 < der.length; i++)
    if (der[i] === 0x04 && der[i + 1] === 0x20) return der.slice(i + 2, i + 34); // SEC1 04 20 <priv>
  throw new Error("SEC1 priv not found in " + path);
}

async function login(b: string, name: string, priv: Uint8Array): Promise<string> {
  const j = await (await fetch(b + "/v1/auth", { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ address: name, pubkey_hex: toHex(pubFromPriv(priv)), sig: toHex(authSign(priv, name)) }) })).json() as any;
  if (!j.token) throw new Error("auth " + name + ": " + JSON.stringify(j));
  return j.token;
}

const subject = "R live spool " + Date.now();
{
  const priv = pemPriv(secrets + "/alice.key");
  const token = await login(base, "alice", priv);
  const out = await composeAndSend(base, token, priv, {
    to: "bob", subject, body: "this letter waits for beta", attachments: [], onProgress: () => {},
  } as any);
  ok(!!out.msg_id, "send answered with msg_id (" + (out.status || "200") + ")");
  ok(out.status === "pending", "status pending while beta down (" + out.status + ")");
  const h = await (await fetch(base + "/health")).json() as any;
  ok((h.spool?.pending ?? 0) >= 1, "health.spool counts the pending row");
}

execSync("systemctl unmask bmail-relay-beta"); execSync("systemctl start bmail-relay-beta");
await new Promise(r => setTimeout(r, 3000));
execSync(`python3 -c "import sqlite3; db=sqlite3.connect('/var/lib/bmail/alpha/ledger.db'); db.execute('UPDATE pending_send SET next_try=0'); db.commit()"`);
let settled = false;
for (let i = 0; i < 25; i++) {
  await new Promise(r => setTimeout(r, 3000));
  const h = await (await fetch(base + "/health")).json() as any;
  if ((h.spool?.pending ?? 1) === 0) { settled = true; break; }
}
ok(settled, "ticker delivered after beta came back (pending drained)");

{
  const bpriv = pemPriv(secrets + "/bob.key");
  const btoken = await login(baseB, "bob", bpriv);
  const j = await (await fetch(baseB + "/v1/inbox", { headers: { Authorization: "***" + btoken } })).json() as any;
  let hits = 0;
  for (const m of (j.messages || [])) {
    const env = decodeEnvelope(fromB64(m.envelope_b64));
    const aad = new Uint8Array([...env[TAG.RecipientHash], ...env[TAG.MsgID]]);
    try {
      const pt = JSON.parse(new TextDecoder().decode(decryptPayload(bpriv, env[TAG.Ephemeral]!, env[TAG.Payload]!, aad)));
      if (pt.subject === subject) hits++;
    } catch { /* foreign mail */ }
  }
  ok(hits === 1, `bob has the late letter EXACTLY once (${hits})`);
}
console.log("EXITCODE", process.exitCode || 0);
