// chunks.ts — Etappe 7 (§22): huge attachments as 1-MiB slices + manifest.
// DOM-free: PWA and headless tests share the path.
//
// Model: each slice is its own blob (sha256-addressed = dedup across
// mails/accounts); the manifest {v,size,chunks[hex…]} is itself a blob.
// Since 21.11. the envelope carries ONLY the manifest ref — the recipient
// relay mirrors the slices by walking the manifest (spec 6.4/6.5). Refs are
// capped at 255 per letter (count = 1 byte in the envelope) → ~254 MB ceiling;
// the real limit is the account quota.
export const CHUNK = 1024 * 1024;
export const MAX_REFS = 255;

export type Manifest = { v: 1; size: number; chunks: string[] }; // chunks = sha256-hex, order = file order

export const needsChunking = (size: number): boolean => size > CHUNK;

export function* splitChunks(b: Uint8Array): Generator<Uint8Array> {
  for (let o = 0; o < b.length; o += CHUNK) yield b.slice(o, o + CHUNK);
}

export const manifestBytes = (m: Manifest): Uint8Array => new TextEncoder().encode(JSON.stringify(m));

export function parseManifest(b: Uint8Array): Manifest {
  const m = JSON.parse(new TextDecoder().decode(b)) as Manifest;
  if (!m || m.v !== 1 || !Array.isArray(m.chunks) || typeof m.size !== 'number') throw new Error('ungültiges Manifest');
  return m;
}

// reassemble: fetch slices in order and concatenate; length check against
// the manifest (partial downloads surface instead of silently corrupting).
export async function reassemble(fetchBlob: (sha: string) => Promise<Uint8Array>, m: Manifest): Promise<Uint8Array> {
  const out = new Uint8Array(m.size);
  let o = 0;
  for (const sha of m.chunks) {
    const c = await fetchBlob(sha);
    if (o + c.length > m.size) throw new Error('reassemble: Scheibe größer als Rest');
    out.set(c, o);
    o += c.length;
  }
  if (o !== m.size) throw new Error(`reassemble: ${o} von ${m.size} Bytes`);
  return out;
}
