// alice-bob-provision.mts — idempotent: keys from app/public/keys, re-registration when needed.
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { newPrivKey, sec1PEM, parseSec1PEM, pubFromPriv, toHex, authSign } from "../src/crypto";

const targets = [
  { name: "alice", home: "http://127.0.0.1:8443", other: "http://127.0.0.1:9443" },
  { name: "bob", home: "http://127.0.0.1:9443", other: "http://127.0.0.1:8443" },
];
for (const t of targets) {
  const f = `app/public/keys/${t.name}.key`;
  let k: Uint8Array, pem: string;
  if (existsSync(f)) { pem = readFileSync(f, "utf8"); k = parseSec1PEM(pem); }
  else { k = newPrivKey(); pem = sec1PEM(k); writeFileSync(f, pem); }
  const pub = toHex(pubFromPriv(k));
  for (const [base, dom] of [[t.home, "home"], [t.other, "stub"]] as const) {
    let r = await fetch(base + "/v1/account", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: t.name, pubkey: pub }) });
    if (r.status === 409) {
      const tok = ((await (await fetch(base + "/v1/auth", { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ address: t.name, pubkey_hex: pub, sig: toHex(authSign(k, t.name)) }) })).json()) as any).token;
      const pr = await fetch(base + "/v1/admin/rekey", { method: "POST", headers: { "Content-Type": "application/json", ...(tok ? { Authorization: `Bearer ${tok}` } : {}) },
        body: JSON.stringify({ name: t.name, pubkey: pub }) });
      console.log(t.name, dom, "-> 409, rekey:", pr.status); // rekey doesn't exist -> 404/405 is fine, retry plan below
      if (!pr.ok) { console.log(t.name, dom, "REKEY_FEHLT"); continue; }
      r = await fetch(base + "/v1/account", { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: t.name, pubkey: pub }) });
      console.log(t.name, dom, "-> re-reg", r.status);
    } else console.log(t.name, dom, "->", r.status);
  }
}
