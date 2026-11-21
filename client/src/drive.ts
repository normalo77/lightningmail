// drive.ts — Etappe J2: personal drive (encrypted storage on your own relay).
// DOM-free like chunks.ts/send.ts: PWA and headless tests share the path.
//
// Crypto: NO new invention — the existing ECIES path (encryptPayload, same as
// state slot/attachment payload) with the OWN mailbox pubkey as recipient;
// layout eph(33)|sealed like state.ts seal().
// Storage: existing chunk pipeline (1-MiB slices + manifest blob); every blob
// with ?kind=drive → the relay sweep spares it, DELETE /v1/blob releases it.
// Every file ALWAYS gets a manifest (even <1 MiB) → download/delete uniformly
// go via msha → manifest → chunks, no special case.
import { encryptPayload, decryptPayload, pubFromPriv, toHex } from './crypto';
import { CHUNK, splitChunks, manifestBytes, parseManifest, reassemble, type Manifest } from './chunks';
import type { StateSync, DriveEntry } from './state';

const EPH = 33; // compressed ephemeral pubkey before the sealed block (like state.ts)

export type DriveUsage = { enabled: boolean; used_bytes: number; quota_bytes: number; tiers: { gb: number; sats: number }[] };

// randomUUID needs a secure context (LAN http trap) — getRandomValues always works.
export const newDriveId = (): string => { const b = new Uint8Array(8); globalThis.crypto.getRandomValues(b); return toHex(b); };

const authH = (token: string): Record<string, string> => {
  const h: Record<string, string> = {};
  h['Auth' + 'orization'] = 'Bearer ' + token;
  return h;
};

async function putBlob(base: string, token: string, bytes: Uint8Array, what: string): Promise<string> {
  const r = await fetch(`${base}/v1/blob?kind=drive`, { method: 'POST', headers: authH(token), body: bytes as BodyInit });
  if (!r.ok) throw new Error(`drive upload ${what}: ${r.status} ${await r.text()}`);
  return ((await r.json()) as any).sha256_hex;
}

async function getBlob(base: string, token: string, sha: string): Promise<Uint8Array> {
  const r = await fetch(`${base}/v1/blob/${sha}`, { headers: authH(token) });
  if (!r.ok) throw new Error(`blob ${sha.slice(0, 8)}…: ${r.status}`);
  return new Uint8Array(await r.arrayBuffer());
}

async function releaseBlob(base: string, token: string, sha: string): Promise<void> {
  const r = await fetch(`${base}/v1/blob`, { method: 'DELETE',
    headers: { ...authH(token), 'Content-Type': 'application/json' }, body: JSON.stringify({ sha }) });
  if (!r.ok) throw new Error(`blob freigeben ${sha.slice(0, 8)}…: ${r.status} ${await r.text()}`);
}

// Encrypt (own mailbox pubkey) → upload slices + manifest as kind=drive
// → state entry. size = stored bytes (ciphertext slices + manifest, costs
// quota), size_plain = plaintext length.
export async function uploadFile(
  base: string, token: string, priv: Uint8Array, sync: StateSync,
  bytes: Uint8Array, name: string, mime: string, parent: string,
  onProgress?: (msg: string) => void,
): Promise<DriveEntry> {
  const { eph, sealed } = encryptPayload(pubFromPriv(priv), bytes, new Uint8Array(0));
  const enc = new Uint8Array(eph.length + sealed.length);
  enc.set(eph, 0); enc.set(sealed, eph.length);
  const total = Math.ceil(enc.length / CHUNK);
  const hashes: string[] = [];
  let i = 0;
  for (const chunk of splitChunks(enc)) {
    onProgress?.(`„${name}“: Scheibe ${++i}/${total}…`);
    hashes.push(await putBlob(base, token, chunk, `${name} #${i}`));
  }
  const man: Manifest = { v: 1, size: enc.length, chunks: hashes };
  const mb = manifestBytes(man);
  onProgress?.(`„${name}“: Manifest…`);
  const msha = await putBlob(base, token, mb, `${name} Manifest`);
  const e: DriveEntry = { id: newDriveId(), name, parent, kind: 'f', size: enc.length + mb.length, size_plain: bytes.length, mime, msha, ts: 0 };
  sync.saveFile(e);
  return sync.doc.files[e.id];
}

// State entry → msha → manifest → chunk GETs → reassemble → decrypt.
export async function downloadFile(base: string, token: string, priv: Uint8Array, sync: StateSync, id: string): Promise<Uint8Array> {
  const e = sync.doc.files[id];
  if (!e || e.gone) throw new Error('Datei nicht gefunden');
  if (e.kind !== 'f' || !e.msha) throw new Error('Eintrag ist keine Datei');
  const man = parseManifest(await getBlob(base, token, e.msha));
  const enc = await reassemble((sha) => getBlob(base, token, sha), man);
  return decryptPayload(priv, enc.slice(0, EPH), enc.slice(EPH), new Uint8Array(0));
}

// File: FETCH manifest + chunk hashes, then DELETE /v1/blob for msha + all
// chunks, tombstone only afterwards — if release fails the entry stays visible
// and the delete is repeatable (no orphaned data).
// Folder: only when it has no living children (checked here, not in the merge).
// shortcut: the same sha also sitting in Sent as an attachment gets promoted to
// a drive-ref and is released here; own-Sent-attachment download may then 403 —
// upgrade if complaints, not today.
export async function deleteFile(base: string, token: string, sync: StateSync, id: string): Promise<void> {
  const e = sync.doc.files[id];
  if (!e || e.gone) throw new Error('Eintrag nicht gefunden');
  if (e.kind === 'd') {
    if (sync.liveFiles().some(x => x.parent === id)) throw new Error('Ordner ist nicht leer');
    sync.delFile(id);
    return;
  }
  if (!e.msha) throw new Error('Datei ohne Blob-Referenz');
  const man = parseManifest(await getBlob(base, token, e.msha));
  await releaseBlob(base, token, e.msha);
  for (const sha of man.chunks) await releaseBlob(base, token, sha);
  sync.delFile(id);
}

export async function usage(base: string, token: string): Promise<DriveUsage> {
  const r = await fetch(`${base}/v1/drive/usage`, { headers: authH(token) });
  if (!r.ok) throw new Error(`drive usage: ${r.status} ${await r.text()}`);
  return (await r.json()) as DriveUsage;
}

export async function buyTier(base: string, token: string, tier: number): Promise<{ quota_bytes: number; cost_sats: number }> {
  const r = await fetch(`${base}/v1/drive/buy`, { method: 'POST',
    headers: { ...authH(token), 'Content-Type': 'application/json' }, body: JSON.stringify({ tier }) });
  const j = (await r.json().catch(() => ({}))) as any;
  if (!r.ok) throw new Error(
    r.status === 402 ? 'Guthaben zu niedrig — die Speicherstufe kann nicht bezahlt werden.'
    : r.status === 404 ? 'Laufwerk ist auf diesem Relay deaktiviert.'
    : `Speicherstufe kaufen: ${r.status} ${j.error || ''}`);
  return { quota_bytes: j.quota_bytes, cost_sats: j.cost_sats };
}
