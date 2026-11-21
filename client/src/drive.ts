// drive.ts — Etappe J2: persönliches Laufwerk (verschlüsselter Speicher am eigenen
// Relay). DOM-frei wie chunks.ts/send.ts: PWA und Headless-Tests teilen den Pfad.
//
// Krypto: KEINE neue Erfindung — der bestehende ECIES-Pfad (encryptPayload, wie
// State-Slot/Anhang-Payload) mit der EIGENEN Mailbox-Pubkey als Empfänger;
// Layout eph(33)|sealed wie state.ts seal().
// Ablage: bestehende Chunk-Pipeline (1-MiB-Scheiben + Manifest-Blob), jeder Blob
// mit ?kind=drive → Relay-Sweep verschont ihn, DELETE /v1/blob gibt ihn frei.
// Jede Datei bekommt IMMER ein Manifest (auch <1 MiB) → Download/Löschen laufen
// einheitlich über msha → Manifest → Chunks, kein Sonderfall.
import { encryptPayload, decryptPayload, pubFromPriv, toHex } from './crypto';
import { CHUNK, splitChunks, manifestBytes, parseManifest, reassemble, type Manifest } from './chunks';
import type { StateSync, DriveEntry } from './state';

const EPH = 33; // komprimierter Ephemeral-Pubkey vor dem Sealed-Block (wie state.ts)

export type DriveUsage = { enabled: boolean; used_bytes: number; quota_bytes: number; tiers: { gb: number; sats: number }[] };

// randomUUID braucht Secure Context (LAN-http-Falle) — getRandomValues geht immer.
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

// Verschlüsseln (eigene Mailbox-Pubkey) → Scheiben + Manifest als kind=drive hochladen
// → State-Eintrag. size = gespeicherte Bytes (Chiffre+Scheiben+Manifest, kostet
// Quota), size_plain = Klartextlänge.
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

// State-Eintrag → msha → Manifest → Chunk-GETs → reassemble → entschlüsseln.
export async function downloadFile(base: string, token: string, priv: Uint8Array, sync: StateSync, id: string): Promise<Uint8Array> {
  const e = sync.doc.files[id];
  if (!e || e.gone) throw new Error('Datei nicht gefunden');
  if (e.kind !== 'f' || !e.msha) throw new Error('Eintrag ist keine Datei');
  const man = parseManifest(await getBlob(base, token, e.msha));
  const enc = await reassemble((sha) => getBlob(base, token, sha), man);
  return decryptPayload(priv, enc.slice(0, EPH), enc.slice(EPH), new Uint8Array(0));
}

// Datei: Manifest + Chunk-Hashes HOLEN, dann DELETE /v1/blob für msha + alle
// Chunks, erst danach der Tombstone — schlägt die Freigabe fehl, bleibt der
// Eintrag sichtbar und das Löschen ist wiederholbar (kein Daten-Waisenstand).
// Ordner: nur wenn keine lebenden Kinder (Prüfung hier, nicht im Merge).
// shortcut: gleiche sha, die auch als Anhang in Sent steckt, wird durch die
// Promotion-Regel zur drive-ref und hier freigegeben; own-Sent-Attachment-Download
// kann danach 403 sein — upgraden wenn Complaints, nicht heute.
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
