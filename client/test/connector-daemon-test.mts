// connector-daemon-test.mts — Selbstcheck des Service-Connector-Daemons (Etappe O):
// Fake-Relay (auth/profile/send) hochfahren, Daemon per tsx spawnen, lokale
// JSON-API pruefen: GET /health, GET /inbox, POST /send.
// Ablauf: npx tsx test/connector-daemon-test.mts   (aus client/)
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { webcrypto } from 'node:crypto';
import { newPrivKey, pubFromPriv, sec1PEM, toHex } from '../src/crypto';

// Node 18 ohne --experimental-global-webcrypto: src/crypto.ts braucht globalThis.crypto
if (!globalThis.crypto) (globalThis as any).crypto = webcrypto;

const ok = (c: boolean, m: string) => {
  console.log((c ? 'PASS ' : 'FAIL ') + m);
  if (!c) process.exitCode = 1;
};
const clientRoot = new URL('..', import.meta.url).pathname;
const recipientPub = toHex(pubFromPriv(newPrivKey()));

// --- Fake-Relay: nur was der Daemon-Pfad wirklich aufruft ---
let authCalls = 0, sendCalls = 0;
const relay = createServer((req, res) => {
  const url = new URL(req.url ?? '/', 'http://x');
  const out = (code: number, body: unknown) => {
    res.writeHead(code, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(body));
  };
  if (req.method === 'POST' && url.pathname === '/v1/auth') { authCalls++; return out(200, { token: 'tok123' }); }
  if (req.method === 'GET' && url.pathname === '/v1/inbox') return out(200, { messages: [] });
  if (req.method === 'GET' && url.pathname.startsWith('/v1/profile/')) return out(200, { pubkey: recipientPub, foreign_sats: 10 });
  if (req.method === 'POST' && url.pathname === '/v1/send') {
    sendCalls++;
    req.resume();
    return out(200, { msg_id: 'fake-msg-id', to: url.searchParams.get('to') });
  }
  out(404, { error: 'unexpected ' + url.pathname });
});
await new Promise<void>((r) => relay.listen(0, '127.0.0.1', r));
const relayPort = (relay.address() as any).port;

// --- Daemon spawnen ---
const dir = mkdtempSync(join(tmpdir(), 'bmail-daemon-'));
const keyFile = join(dir, 'svc.pem');
writeFileSync(keyFile, sec1PEM(newPrivKey()));
const apiPort = 14000 + Math.floor(Math.random() * 1000);
const daemon = spawn(join(clientRoot, 'node_modules/.bin/tsx'), [join(clientRoot, 'src/connector-daemon.mts')], {
  cwd: clientRoot,
  env: {
    ...process.env,
    BMAIL_RELAY: `http://127.0.0.1:${relayPort}`,
    BMAIL_ACCOUNT: 'svc',
    BMAIL_KEY_FILE: keyFile,
    BMAIL_PORT: String(apiPort),
    BMAIL_POLL_MS: '300',
  },
  stdio: ['ignore', 'pipe', 'pipe'],
});
let daemonOut = '';
daemon.stdout.on('data', (d) => { daemonOut += d; });
daemon.stderr.on('data', (d) => { daemonOut += d; });

const base = `http://127.0.0.1:${apiPort}`;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
async function waitForHealth(tries = 60): Promise<any> {
  for (let i = 0; i < tries; i++) {
    try {
      const r = await fetch(base + '/health');
      if (r.ok) return await r.json();
    } catch { /* Daemon startet noch (tsx-Compile) */ }
    await sleep(500);
  }
  throw new Error('daemon /health nicht erreichbar; Output:\n' + daemonOut);
}

try {
  const h = await waitForHealth();
  ok(h?.ok === true && h?.account === 'svc', `GET /health -> {ok:true, account:"svc"}`);
  ok(authCalls >= 1, 'Daemon hat sich via ServiceConnector.login() angemeldet');

  const inbox = await (await fetch(base + '/inbox')).json() as any;
  ok(Array.isArray(inbox?.messages) && inbox.messages.length === 0, 'GET /inbox -> {messages:[]} (Fake-Relay leer)');

  const send = await fetch(base + '/send', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ to: 'user@relay.example', subject: 'Hi', body: 'Hello' }),
  });
  const sent = await send.json() as any;
  ok(send.status === 200 && sent?.msg_id === 'fake-msg-id', `POST /send -> 200 {msg_id:"${sent?.msg_id}"}`);
  ok(sendCalls === 1, 'POST /send lief ueber connector.sendMail -> Fake-Relay /v1/send');

  const bad = await fetch(base + '/send', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ to: 'x' }),
  });
  ok(bad.status === 400, 'POST /send ohne subject/body -> 400');

  const nf = await fetch(base + '/nope');
  ok(nf.status === 404, 'unbekannte Route -> 404');

  await sleep(800); // Hintergrund-Poll muss ohne Crash laufen (BMAIL_POLL_MS=300)
  ok((await (await fetch(base + '/health')).json() as any)?.ok === true, 'Hintergrund-Poll-Loop laeuft stabil');
} catch (e) {
  ok(false, String(e));
} finally {
  daemon.kill();
  relay.close();
}
console.log('EXITCODE', process.exitCode || 0);
