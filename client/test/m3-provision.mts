// m3-provision.mts — throwaway desktop-evidence account on ALPHA.
// Creates the mailbox, writes an UNWRAPPED SEC1 PEM (desktop logs in without
// a passphrase dialog) and prints the account name as JSON.
import { newPrivKey, pubFromPriv, sec1PEM, toHex } from "../src/crypto";
import * as fs from "fs";

const base = process.env.RELAY || "http://127.0.0.1:8443";
const out = process.env.KEYOUT || "/tmp/m3-desktop.key";
const priv = newPrivKey();
const acct = "m3" + Date.now().toString(36);
const r = await fetch(base + "/v1/account", {
  method: "POST", headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ name: acct, pubkey: toHex(pubFromPriv(priv)) }),
});
if (!r.ok) throw new Error("account " + r.status + " " + await r.text());
fs.writeFileSync(out, sec1PEM(priv), { mode: 0o600 });
console.log(JSON.stringify({ account: acct, key: out, relay: base }));
