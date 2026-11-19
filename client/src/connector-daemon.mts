#!/usr/bin/env npx tsx
// connector-daemon.mts — Service-Connector als Sidecar-Daemon (CONCEPT §29,
// Etappe O): Headless-Mailbox fuer Dienste. Pollt die Inbox im Hintergrund
// (Webhook-Push pro Mail steckt bereits im ServiceConnector) und serviert eine
// lokale JSON-API auf 127.0.0.1: GET /health, GET /inbox, POST /send.
//
// Start: BMAIL_RELAY=https://relay.example.org BMAIL_ACCOUNT=service \
//        BMAIL_KEY_FILE=service.pem npx tsx src/connector-daemon.mts
// Env:   BMAIL_RELAY, BMAIL_ACCOUNT (Pflicht);
//        BMAIL_KEY_FILE = SEC1-PEM oder LMKEY1-Wrap (+ BMAIL_KEY_PASSPHRASE)
//        oder BMAIL_MNEMONIC (24 BIP39-Woerter);
//        BMAIL_WEBHOOK_URL (optional), BMAIL_PORT (Default 4040),
//        BMAIL_POLL_MS (Default 5000).
import { readFileSync } from 'node:fs';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { webcrypto } from 'node:crypto';
import { ServiceConnector } from './connector';
import { parseSec1PEM } from './crypto';
import { isWrapped, unwrapKey } from './keywrap';
import { checkMnemonic, keyFromMnemonic } from './bip39';

// Node 18 ohne --experimental-global-webcrypto: src/crypto.ts braucht globalThis.crypto
if (!globalThis.crypto) (globalThis as any).crypto = webcrypto;

function loadPrivKey(): Uint8Array {
  const mn = process.env.BMAIL_MNEMONIC;
  if (mn) {
    const norm = checkMnemonic(mn);
    if (!norm) throw new Error('BMAIL_MNEMONIC ist keine gueltige BIP39-Mnemonic');
    return keyFromMnemonic(norm);
  }
  const file = process.env.BMAIL_KEY_FILE;
  if (!file) throw new Error('BMAIL_KEY_FILE oder BMAIL_MNEMONIC erforderlich');
  const text = readFileSync(file, 'utf8');
  const pem = isWrapped(text) ? unwrapKey(text, process.env.BMAIL_KEY_PASSPHRASE ?? '') : text;
  return parseSec1PEM(pem);
}

const relayUrl = process.env.BMAIL_RELAY;
const account = process.env.BMAIL_ACCOUNT;
if (!relayUrl || !account) {
  console.error('BMAIL_RELAY und BMAIL_ACCOUNT erforderlich');
  process.exit(2);
}
const port = Number(process.env.BMAIL_PORT || 4040);
const pollMs = Number(process.env.BMAIL_POLL_MS || 5000);

const connector = new ServiceConnector({
  relayUrl, account, privKey: loadPrivKey(),
  webhookUrl: process.env.BMAIL_WEBHOOK_URL || undefined,
});

// Start-Login; bei Relay-Ausfall nicht sterben — pollOnce() loggt selbst neu ein.
try {
  await connector.login();
  console.log(`login ok: ${account} @ ${relayUrl}`);
} catch (e) {
  console.error('login fehlgeschlagen (Poll-Loop retryt):', e);
}

let polling = false;
setInterval(async () => {
  if (polling) return; // kein Ueberlappen langsamer Polls
  polling = true;
  try {
    const mail = await connector.pollOnce();
    if (mail.length) console.log(`${mail.length} Mail(s) gepollt, lastSeq=${connector.lastSeq}`);
  } catch (e) {
    console.error('poll:', e);
  } finally {
    polling = false;
  }
}, pollMs);

const json = (res: ServerResponse, code: number, body: unknown) => {
  res.writeHead(code, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(body));
};
const readBody = (req: IncomingMessage) => new Promise<string>((ok, fail) => {
  let s = '';
  req.on('data', (d) => { s += d; });
  req.on('end', () => ok(s));
  req.on('error', fail);
});

createServer(async (req, res) => {
  const path = new URL(req.url ?? '/', 'http://127.0.0.1').pathname;
  try {
    if (req.method === 'GET' && path === '/health') return json(res, 200, { ok: true, account });
    if (req.method === 'GET' && path === '/inbox') {
      return json(res, 200, { messages: await connector.pollOnce() });
    }
    if (req.method === 'POST' && path === '/send') {
      const b = JSON.parse(await readBody(req) || '{}');
      if (!b.to || typeof b.subject !== 'string' || typeof b.body !== 'string') {
        return json(res, 400, { error: 'erwartet {"to","subject","body","signup"?}' });
      }
      return json(res, 200, await connector.sendMail(b.to, b.subject, b.body, !!b.signup));
    }
    json(res, 404, { error: 'not found' });
  } catch (e: any) {
    json(res, 502, { error: String(e?.message ?? e) });
  }
}).listen(port, '127.0.0.1', () => {
  console.log(`connector-daemon: API auf 127.0.0.1:${port}, poll alle ${pollMs} ms`);
});
