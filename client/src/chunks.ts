// chunks.ts — Etappe 7 (§22): riesige Anhänge als 1-MiB-Scheiben + Manifest.
// DOM-frei: PWA und Headless-Tests teilen den Pfad.
//
// Modell: jede Scheibe ist ein eigener Blob (sha256-adressiert = Dedup über
// Mails/Konten), das Manifest {v,size,chunks[hex…]} ist selbst ein Blob.
// ALLE Hashes (Scheiben + Manifest) gehen ins Envelope-blob_refs — ACL und
// Relay-Mirror (spec 6.4) funktionieren unverändert. Refs sind auf 255 pro
// Brief gedeckelt (count = 1 Byte im Envelope) → ~254 MB Obergrenze;
// die echte Grenze ist die Konto-Quota.
export const CHUNK = 1024 * 1024;
export const MAX_REFS = 255;

export type Manifest = { v: 1; size: number; chunks: string[] }; // chunks = sha256-hex, Reihenfolge = Datei-Reihenfolge

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

// reassemble: Scheiben der Reihe nach holen und zusammenfügen; Längenprüfung
// gegen das Manifest ( halbe Downloads fallen auf, statt still zu korrumpern).
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
