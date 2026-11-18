// directory.ts — Etappe B: oeffentliches Adressbuch (CONCEPT §21, spec §7d).
// DOM-frei: PWA (main.ts) und Headless-Tests (test/directory.mts) teilen den Pfad.
//
// Die Karte ist eine clientseitig gefilterte Projektion der Adressbuch-Felder,
// signiert mit dem Mailbox-Key (BIP340 ueber sha256 der exakten JSON-Bytes).
// Der Server sieht nur diese Bytes + gdpr1-Consent; Key-Aufloesung bleibt
// gratis, die Karte kostet (Server-Fee + Kontaktpreis, Dedup pro card_hash).
import { schnorr, sha256, toHex, fromHex, verifySchnorr } from './crypto';

// Feldmenge = Etappe-A-Adressbuch (ABFIELDS in main.ts) — Reihenfolge fest,
// damit JSON.stringify deterministisch bleibt (card_hash-Stabilitaet).
export const CARD_FIELDS = [
  'name', 'given', 'org', 'title', 'url', 'cell', 'phone', 'fax',
  'email', 'addr', 'lnaddr', 'btc', 'crypto', 'pubkey', 'pgp', 'note',
] as const;
export type CardField = (typeof CARD_FIELDS)[number];
export type Card = Partial<Record<CardField, string>>;

export type Consent = { v: 'gdpr1'; ts: number; fields: string[]; purpose: 'directory' };

const enc = new TextEncoder();
const dec = new TextDecoder();
const authHeaders = (tok: string): Record<string, string> => {
  const h: Record<string, string> = { 'Content-Type': 'application/json' };
  h[('Auth' + 'orization') as string] = 'Bearer ' + tok;
  return h;
};

// Kanonische Karten-Bytes: nur nichtleere Felder, feste Schluesselreihenfolge.
export function buildCardBytes(fields: Card): Uint8Array {
  const o: Record<string, string> = {};
  for (const k of CARD_FIELDS) {
    const v = fields[k];
    if (typeof v === 'string' && v.trim()) o[k] = v.trim();
  }
  if (!Object.keys(o).length) throw new Error('Karte ist leer — mindestens ein Feld ausfuellen');
  return enc.encode(JSON.stringify(o));
}

export const cardHash = (b: Uint8Array): string => toHex(sha256(b));

export function signCardBytes(priv: Uint8Array, b: Uint8Array): string {
  return toHex(schnorr.sign(new Uint8Array(sha256(b)), priv));
}

export function verifyCard(pub33Hex: string, b: Uint8Array, sigHex: string): boolean {
  return verifySchnorr(fromHex(pub33Hex), b, fromHex(sigHex));
}

export const cardToB64 = (b: Uint8Array): string => btoa(String.fromCharCode(...b));
export const cardFromB64 = (s: string): Uint8Array =>
  Uint8Array.from(atob(s.replace(/\s/g, '')), (c) => c.charCodeAt(0));

export function makeConsent(cardBytes: Uint8Array): Consent {
  const fields = Object.keys(JSON.parse(dec.decode(cardBytes)) as Record<string, string>);
  return { v: 'gdpr1', ts: Math.floor(Date.now() / 1000), fields, purpose: 'directory' };
}

// --- Relay-API (spec §7d) ---

export type LookupEntry = {
  address: string; pubkey: string; foreign_sats: number; contact_sats: number;
  has_card?: boolean; card_hash?: string; price_meur?: number; fee_meur?: number;
  total_meur?: number; total_msat?: number; purchased?: boolean;
  rate?: { meur_per_btc: number; ts: number; src: string };
};

export type CardPayload = {
  address: string; pubkey: string; card_b64: string; sig: string; card_hash: string;
  consent: Consent; price_meur: number; purchased: boolean;
  paid?: { total_meur: number; seller_meur: number; fee_meur: number; total_msat?: number;
           seller_msat?: number; currency?: string; fresh?: boolean; free?: boolean;
           rate?: { meur_per_btc: number; ts: number; src: string } };
};

export async function lookupAddress(base: string, addr: string): Promise<LookupEntry> {
  const r = await fetch(`${base}/v1/profile/${encodeURIComponent(addr.split('@')[0])}`);
  if (!r.ok) throw new Error(`lookup: ${r.status} ${await r.text()}`);
  return (await r.json()) as LookupEntry;
}

export async function putProfile(
  base: string, tok: string, priv: Uint8Array, fields: Card, priceMEur?: number,
): Promise<{ card_hash: string; price_meur: number }> {
  const b = buildCardBytes(fields);
  const body = JSON.stringify({
    card_b64: cardToB64(b),
    sig: signCardBytes(priv, b),
    consent: makeConsent(b),
    ...(priceMEur !== undefined ? { price_meur: priceMEur } : {}),
  });
  const r = await fetch(base + '/v1/profile', { method: 'PUT', headers: authHeaders(tok), body });
  if (!r.ok) throw new Error(`profile PUT: ${r.status} ${await r.text()}`);
  return await r.json();
}

export async function delProfile(base: string, tok: string): Promise<void> {
  const r = await fetch(base + '/v1/profile', { method: 'DELETE', headers: authHeaders(tok) });
  if (!r.ok) throw new Error(`profile DELETE: ${r.status} ${await r.text()}`);
}

// fetchCard: GET (gekauft/own → 200, sonst 402-Angebot im Fehler).
export async function fetchCard(base: string, tok: string, addr: string): Promise<CardPayload> {
  const r = await fetch(`${base}/v1/profile/${encodeURIComponent(addr.split('@')[0])}/card`,
    { headers: authHeaders(tok) });
  if (!r.ok) throw new Error(`card GET: ${r.status} ${await r.text()}`);
  return (await r.json()) as CardPayload;
}

export type CardOffer = { error: string; card_hash: string; total_meur: number; seller_meur: number; fee_meur: number; total_msat?: number };

// cardOffer: 402-Preisangebot lesen (null wenn kein Angebot, z. B. 404/410).
export async function cardOffer(base: string, tok: string, addr: string): Promise<{ status: number; offer: CardOffer | null }> {
  const r = await fetch(`${base}/v1/profile/${encodeURIComponent(addr.split('@')[0])}/card`,
    { headers: authHeaders(tok) });
  if (r.status === 402) return { status: 402, offer: (await r.json()) as CardOffer };
  if (r.ok) return { status: 200, offer: null };
  return { status: r.status, offer: null };
}

export async function buyCard(base: string, tok: string, addr: string): Promise<CardPayload> {
  const r = await fetch(`${base}/v1/profile/${encodeURIComponent(addr.split('@')[0])}/card`,
    { method: 'POST', headers: authHeaders(tok) });
  if (!r.ok) throw new Error(`card buy: ${r.status} ${await r.text()}`);
  return (await r.json()) as CardPayload;
}

// cardFields: Karten-Bytes → Kontakt-Feldteil (fuer Adressbuch-Übernahme).
export function cardFields(payload: CardPayload): Card {
  return JSON.parse(dec.decode(cardFromB64(payload.card_b64))) as Card;
}
