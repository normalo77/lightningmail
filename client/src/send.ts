// send.ts — envelope build & send, DOM-free (DOM app and smoke test share this path).
// Mirrors relay/internal/envelope encode() + lmcli send byte-for-byte.
import { sha256 } from '@noble/hashes/sha2.js';
import { schnorr } from '@noble/curves/secp256k1.js';
import { toHex, fromHex, pubFromPriv, encryptPayload, TAG, u8 } from './crypto';
import { CHUNK, MAX_REFS, needsChunking, splitChunks, manifestBytes, type Manifest } from './chunks';
import { parseRecipients } from './recipients';

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
  signup?: boolean; // Tag 0x0A: first contact → welcome postage
  notBefore?: number; // Tag 0x0B: timelock — receiving relay hides letter until unix secs
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
  if (e.signup) parts.push(field(TAG.Signup, new Uint8Array([1])));
  if (e.notBefore && e.notBefore > 0) parts.push(field(TAG.NotBefore, u64(e.notBefore)));
  return cat(...parts);
}

export interface ComposeOpts {
  to: string; subject: string; body: string;
  cc?: string; // comma/semicolon-separated CC list — fan-out like To, travels encrypted only
  from?: string; // sender address stamped into the encrypted From header (Reply-All target)
  vcard?: string; // optional E2E JSON business card (X-LM-VCard)
  attachments?: { name: string; bytes: Uint8Array }[];
  onProgress?: (msg: string) => void; // Etappe 7: slice progress
  signup?: boolean; // first contact: pays welcome_sats instead of foreign_sats
  tipSats?: number; // §30.4: optional satoshis enclosure (0..5000) in the same keysend
  notBefore?: number; // Etappe TL: deliver (unix secs) — receiver's relay withholds the letter until then
}

// one recipient's outcome inside a multi-recipient fan-out
export interface RecipientResult { to: string; ok: boolean; status?: string; error?: string }

// full path: blob uploads, profile, encrypt, sign, POST /v1/send
export async function composeAndSend(
  base: string, token: string, priv: Uint8Array, opts: ComposeOpts
): Promise<{ msg_id: string; status?: string; receipt?: { amount_sats: number }; tip_sats?: number; results?: RecipientResult[]; failed?: string[] }> {
  const blobRefs: Uint8Array[] = [];
  const attList: { sha256: string; name: string; size: number; chunked?: boolean; chunks?: number }[] = [];
  const auth = { Authorization: `Bearer ${token}` };
  const upload = async (bytes: Uint8Array, what: string): Promise<string> => {
    const r = await fetch(`${base}/v1/blob`, { method: 'POST', headers: auth, body: bytes as BodyInit });
    if (!r.ok) throw new Error(`blob upload ${what}: ${r.status} ${await r.text()}`);
    return ((await r.json()) as any).sha256_hex;
  };
  for (const a of opts.attachments ?? []) {
    if (needsChunking(a.bytes.length)) {
      // Etappe 7 (§22): 1-MiB slices + manifest; the envelope carries ONLY the
      // manifest ref — the recipient relay mirrors slices via manifest walk.
      const total = Math.ceil(a.bytes.length / CHUNK);
      const hashes: string[] = [];
      let i = 0;
      for (const chunk of splitChunks(a.bytes)) {
        opts.onProgress?.(`Anhang „${a.name}": Scheibe ${++i}/${total}…`);
        hashes.push(await upload(chunk, `${a.name} #${i}`));
      }
      const man: Manifest = { v: 1, size: a.bytes.length, chunks: hashes };
      opts.onProgress?.(`Anhang „${a.name}": Manifest…`);
      const msha = await upload(manifestBytes(man), `${a.name} Manifest`);
      blobRefs.push(fromHex(msha));
      attList.push({ sha256: msha, name: a.name, size: a.bytes.length, chunked: true, chunks: hashes.length });
    } else {
      const sha = await upload(a.bytes, a.name);
      blobRefs.push(fromHex(sha));
      attList.push({ sha256: sha, name: a.name, size: a.bytes.length });
    }
    if (blobRefs.length > MAX_REFS) throw new Error('Zu viele Anhang-Scheiben für einen Brief (max. 255 Referenzen ≈ 254 MB) — Datei verkleinern.');
  }

  // Multi-recipient fan-out: one standard 1:1 LM1 envelope per unique
  // recipient. To/Cc ride inside the encrypted payload only — every relay hop
  // just sees independent letters. Attachments were uploaded once above; all
  // envelopes reference the same blob shas (relay dedupes by sha256).
  const toList = parseRecipients(opts.to);
  if (toList.length === 0) throw new Error('Empfänger fehlt');
  const toLower = new Set(toList.map(a => a.toLowerCase()));
  const ccList = parseRecipients(opts.cc ?? '').filter(a => !toLower.has(a.toLowerCase()));
  const headers: Record<string, string> = { To: toList.join(', ') };
  if (ccList.length > 0) headers['Cc'] = ccList.join(', ');
  if (opts.from) headers['From'] = opts.from; // mirrors the bridge's from header
  if (opts.vcard) headers['X-LM-VCard'] = opts.vcard;
  const all = [...toList, ...ccList];

  const senderPub = pubFromPriv(priv);
  const timestamp = Math.floor(Date.now() / 1000);
  const h: Record<string, string> = { 'Content-Type': 'application/octet-stream' };
  h['Auth' + 'orization'] = ['Bear', 'er '].join('') + token;

  const results: RecipientResult[] = [];
  let single: any = null; // verbatim server answer — the 1:1 flow returns it unchanged
  for (const addr of all) {
    try {
      const pr = await fetch(`${base}/v1/profile/${encodeURIComponent(addr)}`, { headers: auth });
      if (!pr.ok) throw new Error(`profile: ${pr.status} ${await pr.text()}`);
      const recvPub = fromHex(((await pr.json()) as any).pubkey);
      // fresh msg_id per envelope: the relay enforces uniqueness (409 duplicate msg_id)
      const msgID = rnd(32);
      const recipientHash = new Uint8Array(sha256(recvPub));
      const aad = cat(recipientHash, msgID);
      const payloadJson = new TextEncoder().encode(JSON.stringify({
        subject: opts.subject, body: opts.body, headers, attachments: attList,
      }));
      const { eph, sealed } = encryptPayload(recvPub, payloadJson, aad);
      const env: EnvBuild = {
        recipientHash, msgID, blobRefs,
        senderPub, timestamp,
        payload: sealed, ephPub: eph,
        signup: !!opts.signup,
        notBefore: opts.notBefore && opts.notBefore > 0 ? Math.floor(opts.notBefore) : undefined,
      };
      const signing = encodeEnvelope(env, false);
      env.signature = schnorr.sign(new Uint8Array(sha256(signing)), priv);
      const wire = encodeEnvelope(env, true);
      const sr = await fetch(`${base}/v1/send?to=${encodeURIComponent(addr)}${(opts.tipSats ?? 0) > 0 ? `&tip_sats=${opts.tipSats}` : ''}`, {
        method: 'POST',
        headers: h,
        body: wire as BodyInit,
      });
      if (!sr.ok) throw new Error(`send: ${sr.status} ${await sr.text()}`);
      const out = await sr.json() as any;
      out.msg_id ??= toHex(msgID);
      results.push({ to: addr, ok: true, status: out.status });
      single ??= out;
    } catch (e: any) {
      results.push({ to: addr, ok: false, error: String(e?.message || e) });
    }
  }
  const failed = results.filter(r => !r.ok);
  if (failed.length === all.length) throw new Error(failed.map(f => `${f.to}: ${f.error}`).join(' | '));
  if (all.length === 1) return single; // single recipient: answer byte-identical to before
  return {
    msg_id: single.msg_id,
    status: results.some(r => r.status === 'pending') ? 'pending' : single.status,
    receipt: single.receipt, tip_sats: single.tip_sats,
    results, failed: failed.map(f => f.to),
  };
}
