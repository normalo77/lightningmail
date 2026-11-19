// smoke-send.ts — headless Beweis des App-Sendepfads: Login, Kompose, Blob, /v1/send.
// Aufruf: npx tsx app/../test/smoke-send.ts  (cwd client/)
import { readFileSync } from 'node:fs';
import { parseSec1PEM, pubFromPriv, authSign, toHex } from '../src/crypto';
import { composeAndSend } from '../src/send';

const body = 'M2b smoke ' + Date.now();
const att = new Uint8Array(2 * 1024 * 1024);
for (let i = 0; i < att.length; i++) att[i] = (i * 7 + 13) & 0xff;

const pem = readFileSync('/root/lightningmail/test/e2e-home/bernd/bernd.key', 'utf8');
const priv = parseSec1PEM(pem);
const base = 'http://127.0.0.1:8443';
const r = await fetch(base + '/v1/auth', { method: 'POST', headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ address: 'bernd', pubkey_hex: toHex(pubFromPriv(priv)), sig: toHex(authSign(priv, 'bernd')) }) });
if (!r.ok) { console.error('AUTH FAIL', r.status, await r.text()); process.exit(1); }
const { token } = await r.json() as any;
console.log('AUTH OK');
const out = await composeAndSend(base, token, priv, { to: 'gisela', subject: 'M2b Smoke', body, attachments: [{ name: 'zwei-mb.bin', bytes: att }] });
console.log('SEND OK msg_id=' + String(out.msg_id).slice(0, 16));
