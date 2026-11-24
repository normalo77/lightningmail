import { readFileSync } from "node:fs";
import { parseSec1PEM, pubFromPriv, authSign, toHex } from "../src/crypto";
import { composeAndSend } from "../src/send";
const priv = parseSec1PEM(readFileSync("<repo>/test/e2e-home/gisela/gisela.key", "utf8"));
const base = "http://127.0.0.1:9443";
const r = await fetch(base + "/v1/auth", { method: "POST", headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ address: "gisela", pubkey_hex: toHex(pubFromPriv(priv)), sig: toHex(authSign(priv, "gisela")) }) });
if (!r.ok) { console.error("AUTH FAIL", r.status, await r.text()); process.exit(1); }
const { token } = await r.json() as any;
console.log("AUTH OK");
const att = new Uint8Array(300 * 1024); for (let i = 0; i < att.length; i++) att[i] = i & 0xff;
const out = await composeAndSend(base, token, priv, { to: "bernd@regtest", subject: "M2b: Gisela grueßt per App", body: "Diese Mail wurde von der App-Sendehardware (send.ts) gebaut und verschluesselt.", attachments: [{ name: "drei-hundert-kb.bin", bytes: att }] });
console.log("SEND OK msg_id=" + String(out.msg_id).slice(0, 16));
