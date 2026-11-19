// TS-Client-Interop: liest giselas Inbox via Relay-API, decrypted envelope, holt Blob.
import { readFileSync } from 'node:fs';
import { sha256 } from '@noble/hashes/sha2.js';
import { parseSec1PEM, pubFromPriv, authSign, toHex, decodeEnvelope, decryptPayload, TAG, blobCount, blobRef, fromB64 } from '../src/crypto';

const BETA = process.env.BETA_URL!; const HOME = process.env.GISELA_HOME!;
const EXPECT_BODY = process.env.EXPECT_BODY!; const EXPECT_SHA = process.env.EXPECT_SHA!;

async function main() {
  const priv = parseSec1PEM(readFileSync(`${HOME}/gisela.key`, 'utf8'));
  const pub = pubFromPriv(priv);
  const sig = authSign(priv, 'gisela');
  const auth = await fetch(`${BETA}/v1/auth`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ address: 'gisela', pubkey_hex: toHex(pub), sig: toHex(sig) }) });
  if (auth.status !== 200) { console.error('auth http', auth.status, await auth.text()); process.exit(1); }
  const { token } = await auth.json() as any;
  if (!token) { console.error('no token'); process.exit(1); }
  console.log('PASS 1: auth (echter TS BIP340+HMAC-Signaturpfad gegen Go-Relay)');

  const inbox = await (await fetch(`${BETA}/v1/inbox`, { headers: { Authorization: `Bearer ${token}` } })).json() as any;
  const msgs = inbox.messages ?? [];
  if (!msgs.length) { console.error('inbox leer'); process.exit(1); }
  const m = msgs[msgs.length - 1];
  const env = decodeEnvelope(fromB64(m.envelope_b64));
  const aad = new Uint8Array(64); aad.set(env[TAG.RecipientHash], 0); aad.set(env[TAG.MsgID], 32);
  const pt = decryptPayload(priv, env[TAG.Ephemeral], env[TAG.Payload], aad);
  const payload = JSON.parse(new TextDecoder().decode(pt));
  if (payload.subject !== 'Interop Test') { console.error('subject mismatch:', payload.subject); process.exit(1); }
  if (payload.body !== EXPECT_BODY) { console.error('body mismatch'); process.exit(1); }
  console.log('PASS 2: envelope decoded + ECIES/XChaCha20-Payload entschlüsselt (subject+body OK)');

  const n = blobCount(env[TAG.BlobRefs]); if (n !== 1) { console.error('blob_refs count', n); process.exit(1); }
  const ref = toHex(blobRef(env[TAG.BlobRefs], 0));
  if (ref !== EXPECT_SHA) { console.error('blob ref != sha', ref); process.exit(1); }
  const r = await fetch(`${BETA}/v1/blob/${ref}`, { headers: { Authorization: `Bearer ${token}` } });
  if (r.status !== 200) { console.error('blob fetch http', r.status); process.exit(1); }
  const buf = new Uint8Array(await r.arrayBuffer());
  const got = toHex(sha256(buf));
  if (got !== EXPECT_SHA || buf.length !== 1048576) { console.error('blob mismatch', got, buf.length); process.exit(1); }
  console.log('PASS 3: 1-MB-Blob geladen, sha256 identisch (' + got.slice(0, 16) + '...)');
  console.log('TS-INTEROP: ALL PASS');
}
main().catch(e => { console.error(e); process.exit(1); });
