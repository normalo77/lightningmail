// smoke-send.ts — headless proof of the app send path: login, compose, blob, /v1/send.
// Run: npx tsx app/../test/smoke-send.ts  (cwd client/)
import { readFileSync } from 'node:fs';
import { parseSec1PEM, pubFromPriv, authSign, toHex } from '../src/crypto';
import { composeAndSend } from '../src/send';

const body = 'M2b smoke ' + Date.now();
const att = new Uint8Array(400 * 1024);
for (let i = 0; i < att.length; i++) att[i] = (i * 7 + 13) & 0xff;

const pem = readFileSync('/root/lightningmail/test/e2e-home/gisela/gisela.key', 'utf8');
const priv = parseSec1PEM(pem);
const base = 'http://127.0.0.1:9443';
const r = await fetch(base + '/v1/auth', { method: 'POST', headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ address: .gisela., pubkey_hex: toHex(pubFromPriv(priv)), sig: toHex(authSign(priv, .gisela.)) }) });
if (!r.ok) { console.error('AUTH FAIL', r.status, await r.text()); process.exit(1); }
const { token } = await r.json() as any;
console.log('AUTH OK');
const out = await composeAndSend(base, token, priv, { to: "bernd@regtest", subject: 'M2b Smoke', body, attachments: [{ name: 'vierhundert-kb.bin', bytes: att }] });
console.log('SEND OK msg_id=' + String(out.msg_id).slice(0, 16));
