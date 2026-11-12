// send.ts — Envelope-Bau & Versand, DOM-frei (DOM-app und Smoke-Test teilen diesen Pfad).
// Spiegelt relay/internal/envelope encode() + lmcli send bytegenau.
import { sha256 } from '@noble/hashes/sha2.js';
import { schnorr } from '@noble/curves/secp256k1.js';
import { toHex, fromHex, pubFromPriv, encryptPayload, TAG, u8 } from './crypto';

const rnd = (n: number): Uint8Array => {
  const b = new Uint8Array(n);
  globalThis.crypto.getRandomValues(b);
  return b;
};

const field = (tag: number, val: Uint8Array): Uint8Array => {
  const l = new Uint8Array(2);
  l[0] = (val.length >> 8) & 0xff; l[1] = val.length & 0xff;
  return new Uint8Array([tag, ...l, ...val]);
};
const u64 = (v: number): Uint8Array => {
  const b = new Uint8Array(8);
  let x = BigInt(v);
  for (let i = 7; i >= 0; i--) { b[i] = Number(x & 0xffn); x >>= 8n; }
  return b;
};
const cat = (...xs: Uint8Array[]): Uint8Array => {
  const out = new Uint8Array(xs.reduce((a, x) => a + x.length, 0));
  let o = 0; for (const x of xs) { out.set(x, o); o += x.length; }
  return out;
};

export interface EnvBuild {
  recipientHash: Uint8Array; msgID: Uint8Array; blobRefs: Uint8Array[];
  senderPub: Uint8Array; timestamp: number; payload: Uint8Array; ephPub: Uint8Array;
  signature?: Uint8Array;
}

export function encodeEnvelope(e: EnvBuild, includeSig: boolean): Uint8Array {
  const parts: Uint8Array[] = [new Uint8Array([0x4c, 0x4d, 0x31, 0x01])];
  parts.push(field(TAG.RecipientHash, e.recipientHash));
  parts.push(field(TAG.MsgID, e.msgID));
  if (e.blobRefs.length > 0) {
    const val: Uint8Array[] = [new Uint8Array([e.blobRefs.length])];
    for (const r of e.blobRefs) val.push(r);
    parts.push(field(TAG.BlobRefs, cat(...val)));
  }
  parts.push(field(TAG.SenderPubkey, e.senderPub));
  if (includeSig && e.signature) parts.push(field(TAG.Signature, e.signature));
  parts.push(field(TAG.Timestamp, u64(e.timestamp)));
  parts.push(field(TAG.Payload, e.payload));
  parts.push(field(TAG.Ephemeral, e.ephPub));
  return cat(...parts);
}

export interface ComposeOpts {
  to: string; subject: string; body: string;
  attachments?: { name: string; bytes: Uint8Array }[];
}

// kompletter Pfad: blob-uploads, profil, verschluesseln, signieren, POST /v1/send
export async function composeAndSend(
  base: string, token: string, priv: Uint8Array, opts: ComposeOpts
): Promise<{ msg_id: string }> {
  const blobRefs: Uint8Array[] = [];
  const attList: { sha256: string; name: string; size: number }[] = [];
  for (const a of opts.attachments ?? []) {
    const r = await fetch(`${base}/v1/blob`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
      body: a.bytes as BodyInit,
    });
    if (!r.ok) throw new Error(`blob upload ${a.name}: ${r.status} ${await r.text()}`);
    const j = await r.json() as any;
    blobRefs.push(fromHex(j.sha256_hex));
    attList.push({ sha256: j.sha256_hex, name: a.name, size: a.bytes.length });
  }

  const recip = opts.to.split('@')[0];
  const pr = await fetch(`${base}/v1/profile/${recip}`, { headers: { Authorization: `Bearer ${token}` } });
  if (!pr.ok) throw new Error(`profile: ${pr.status} ${await pr.text()}`);
  const recvPub = fromHex(((await pr.json()) as any).pubkey);

  const msgID = rnd(32);
  const recipientHash = new Uint8Array(sha256(recvPub));
  const aad = cat(recipientHash, msgID);
  const payloadJson = new TextEncoder().encode(JSON.stringify({
    subject: opts.subject, body: opts.body, headers: {}, attachments: attList,
  }));
  const { eph, sealed } = encryptPayload(recvPub, payloadJson, aad);

  const env: EnvBuild = {
    recipientHash, msgID, blobRefs,
    senderPub: pubFromPriv(priv),
    timestamp: Math.floor(Date.now() / 1000),
    payload: sealed, ephPub: eph,
  };
  const signing = encodeEnvelope(env, false);
  env.signature = schnorr.sign(new Uint8Array(sha256(signing)), priv);
  const wire = encodeEnvelope(env, true);

  const sr = await fetch(`${base}/v1/send`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/octet-stream' },
    body: wire as BodyInit,
  });
  if (!sr.ok) throw new Error(`send: ${sr.status} ${await sr.text()}`);
  const out = await sr.json() as any;
  out.msg_id ??= toHex(msgID);
  return out;
}
