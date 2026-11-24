// m9b-manifest-only.mts — protocol fix 21.11.: the envelope carries ONLY the
// manifest ref; the recipient relay mirrors slices via the manifest walk.
// Run: npx tsx test/m9b-manifest-only.mts
//   RELAY_A=/RELAY_B= overridable; balance via python3-sqlite (BMAIL_DB_A),
//   account pattern copied from chunk-test.mts (the Etappe-7 e2e test).
import { sha256 } from '@noble/hashes/sha2.js';
import { schnorr } from '@noble/curves/secp256k1.js';
import { randomBytes } from 'node:crypto';
import { execFileSync } from "node:child_process";
import { newPrivKey, pubFromPriv, authSign, toHex, fromHex, decodeEnvelope, decryptPayload, encryptPayload, fromB64, TAG, blobCount, blobRef } from "../src/crypto";
import { composeAndSend, encodeEnvelope, type EnvBuild } from "../src/send";
import { parseManifest, reassemble, CHUNK } from "../src/chunks";

const baseA = process.env.RELAY_A || "http://127.0.0.1:8443";
const baseB = process.env.RELAY_B || "http://127.0.0.1:9443";
const dbA = process.env.BMAIL_DB_A || "/var/lib/bmail/alpha/ledger.db";
const ok = (c: boolean, m: string) => { console.log((c ? "PASS " : "FAIL ") + m); if (!c) process.exitCode = 1; };
const skip = (m: string) => console.log("SKIP " + m);
const auth = (t: string): any => { const h: Record<string, string> = {}; h['Auth' + 'orization'] = 'Bearer ' + t; return h; };
const rnd = (n: number): Uint8Array => { const b = new Uint8Array(n); globalThis.crypto.getRandomValues(b); return b; };
const digest = (b: Uint8Array): string => toHex(sha256(b));

async function mkAccount(base: string, tag: string) {
  const priv = newPrivKey();
  const name = `${tag}${Date.now().toString(36)}${Math.floor(Math.random() * 1e4).toString(36)}`.slice(0, 32);
  const r = await fetch(base + "/v1/account", { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name, pubkey: toHex(pubFromPriv(priv)) }) });
  if (!r.ok) throw new Error(`account ${name}: ${r.status} ${await r.text()}`);
  const a = await fetch(base + "/v1/auth", { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ address: name, pubkey_hex: toHex(pubFromPriv(priv)), sig: toHex(authSign(priv, name)) }) });
  return { name, priv, token: ((await a.json()) as any).token as string, base };
}
const topUp = (db: string, name: string, msat: number): boolean => {
  try {
    execFileSync("python3", ["-c",
      `import sqlite3,sys; db=sqlite3.connect(sys.argv[1]); db.execute("UPDATE account SET balance_msat=balance_msat+? WHERE name=?", (${msat}, sys.argv[2])); db.commit()`,
      db, name]);
    return true;
  } catch { return false; }
};

const sender = await mkAccount(baseA, "m9b");
const recip = await mkAccount(baseB, "m9b");
// Stub world (like chunk-test): the recipient must exist on BOTH relays with the same key.
{
  const rr = await fetch(baseA + "/v1/account", { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name: recip.name, pubkey: toHex(pubFromPriv(recip.priv)) }) });
  if (!rr.ok && rr.status !== 409) throw new Error("recip auf A registrieren: " + rr.status);
}
console.log(`sender=${sender.name}@A recip=${recip.name}@B`);
if (!topUp(dbA, sender.name, 50_000_000)) skip("Guthaben-Topup ohne sqlite — Sends koennen an Porto/Byte-Porto scheitern");

const getBlobB = async (sha: string): Promise<{ status: number; bytes?: Uint8Array }> => {
  const r = await fetch(`${baseB}/v1/blob/${sha}`, { headers: auth(recip.token) });
  if (!r.ok) return { status: r.status };
  return { status: r.status, bytes: new Uint8Array(await r.arrayBuffer()) };
};
async function fetchInboxB(min = 1): Promise<any> {
  for (let i = 0; i < 30; i++) { // keysend settle + mirror walk over 12 slices takes a moment
    const j = await (await fetch(baseB + "/v1/inbox", { headers: auth(recip.token) })).json() as any;
    const msgs = j.messages || []; // /v1/inbox is DESC: msgs[0] = newest
    if (msgs.length >= min) return msgs[0];
    await new Promise(res => setTimeout(res, 700));
  }
  return null;
}

// --- Beweis 1-3: 12 MB crypto-random attachment, manifest-only envelope ---
const big = new Uint8Array(randomBytes(12 * 1024 * 1024)); // node-crypto, NOT periodic
const bigHex = digest(big);
{
  const out = await composeAndSend(baseA, sender.token, sender.priv, {
    to: recip.name, subject: "m9b manifest-only", body: "12 MiB in 1-MiB-Scheiben",
    attachments: [{ name: "big.bin", bytes: big }], onProgress: () => {},
  });
  ok(!!out.msg_id, `Send 12 MiB ok (${out.msg_id?.slice(0, 10)}…)`);
  const msg = await fetchInboxB();
  if (!msg) ok(false, "Inbox B: Nachricht angekommen");
  else {
    const env = decodeEnvelope(fromB64(msg.envelope_b64));
    const nRefs = blobCount(env[TAG.BlobRefs]!);
    ok(nRefs === 1, `Beweis 2: Envelope traegt genau 1 Blob-Ref (Manifest), ist ${nRefs}`);
    const aad = new Uint8Array([...env[TAG.RecipientHash], ...env[TAG.MsgID]]);
    const pt = JSON.parse(new TextDecoder().decode(decryptPayload(recip.priv, env[TAG.Ephemeral]!, env[TAG.Payload]!, aad)));
    const att = pt.attachments?.[0];
    ok(!!att && att.chunked === true && att.chunks === 12, `Payload-Attachment chunked: 12 Scheiben (${att?.chunks})`);
    ok(toHex(blobRef(env[TAG.BlobRefs]!, 0)) === att?.sha256,
      "Envelope-Ref == Manifest-sha aus Payload-Attachment");
    const manRes = await getBlobB(att.sha256);
    if (manRes.status !== 200 || !manRes.bytes) { ok(false, `Manifest auf B: ${manRes.status}`); }
    else {
      const man = parseManifest(manRes.bytes);
      const rebuilt = await reassemble(async (sha) => {
        const r = await getBlobB(sha);
        if (!r.bytes) throw new Error("blob " + r.status);
        return r.bytes;
      }, man);
      ok(rebuilt.length === big.length && digest(rebuilt) === bigHex, `Beweis 1: bob laedt 12 MiB bytegleich (sha256 ${bigHex.slice(0, 12)}…)`);
      const pick = [0, Math.floor(man.chunks.length / 2), man.chunks.length - 1]; // Beweis 3: 3 beliebige Scheiben
      for (const i of pick) {
        const r = await getBlobB(man.chunks[i]);
        ok(r.status === 200 && r.bytes?.length === (i === man.chunks.length - 1 ? big.length - (i) * CHUNK : CHUNK),
          `Beweis 3: Slice ${i + 1}/12 auf B gespiegelt (HTTP ${r.status})`);
      }
    }
  }
}

// --- Beweis 4: legacy Multi-Ref-Envelope (alter Client: 3 Einzel-Refs, kein Manifest) ---
{
  const parts = [0, 1, 2].map(() => new Uint8Array(randomBytes(500_000)));
  const shas: string[] = [];
  for (const p of parts) {
    const r = await fetch(`${baseA}/v1/blob`, { method: "POST", headers: auth(sender.token), body: p as BodyInit });
    if (!r.ok) throw new Error(`legacy upload: ${r.status}`);
    shas.push(((await r.json()) as any).sha256_hex);
  }
  const recvPub = pubFromPriv(recip.priv);
  const recipientHash = new Uint8Array(sha256(recvPub));
  const msgID = rnd(32);
  const aad = new Uint8Array([...recipientHash, ...msgID]);
  const payloadJson = new TextEncoder().encode(JSON.stringify({
    subject: "legacy multi-ref", body: "1,5 MiB in 3 Einzel-Blobs (Vor-Manifest-Format)", headers: {},
    attachments: shas.map((s, i) => ({ sha256: s, name: `p${i}.bin`, size: parts[i].length })),
  }));
  const { eph, sealed } = encryptPayload(recvPub, payloadJson, aad);
  const env: EnvBuild = { recipientHash, msgID, blobRefs: shas.map(fromHex), senderPub: pubFromPriv(sender.priv),
    timestamp: Math.floor(Date.now() / 1000), payload: sealed, ephPub: eph };
  const signing = encodeEnvelope(env, false);
  env.signature = schnorr.sign(new Uint8Array(sha256(signing)), sender.priv);
  const sr = await fetch(`${baseA}/v1/send?to=${encodeURIComponent(recip.name)}`, {
    method: "POST", headers: { "Content-Type": "application/octet-stream", ...auth(sender.token) },
    body: encodeEnvelope(env, true) as BodyInit });
  ok(sr.ok, `legacy Send mit 3 Refs ok (${sr.status})`);
  const msg = await fetchInboxB(2); // legacy mail is the newest of the two
  if (!msg) ok(false, "legacy: Nachricht in Inbox B");
  else {
    const lenv = decodeEnvelope(fromB64(msg.envelope_b64));
    ok(blobCount(lenv[TAG.BlobRefs]!) === 3, `legacy: 3 Refs bleiben decode-bar (ist ${blobCount(lenv[TAG.BlobRefs]!)})`);
    let all = true;
    for (let i = 0; i < 3; i++) {
      const r = await getBlobB(shas[i]);
      if (r.status !== 200 || digest(r.bytes!) !== digest(parts[i])) all = false;
    }
    ok(all, "legacy: alle 3 Blobs auf B zugestellt und bytegleich");
  }
}

console.log("EXITCODE", process.exitCode || 0);
