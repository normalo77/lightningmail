// bip39.ts — Etappe 6d (CONCEPT §27): 24-Wort-Recovery, Seed im Browser,
// Wortquiz zur Bestätigung. DOM-frei: Wizard (main.ts) und Tests teilen den Pfad.
//
// Wortliste: englisch = die kanonische BIP39-Liste (Standard in Hardware-
// Wallets; eine offizielle deutsche Liste existiert nicht).
//
// Ableitung: seed64 = PBKDF2(mnemonic) via @scure/bip39, dann
// priv = sha256(seed || "bmail-mailbox-v1" || counter) mit Rejection bis < n.
// shortcut: 1 Seed = 1 Mailbox-Key, kein BIP32-Pfad — fremde Wallets finden
// den Key nicht (Recovery nur hier); Multi-Account/Index-Ableitung bei Bedarf,
// die Wortliste und der Seed bleiben dann kompatibel.
import { generateMnemonic, mnemonicToSeedSync, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { u8, validScalar } from './crypto';

const INFO = u8('bmail-mailbox-v1');

export function newMnemonic(): string {
  return generateMnemonic(wordlist, 256); // 256 Bit Entropie = 24 Woerter
}

// checkMnemonic: normalisiert (klein, Komma/Leerraum) und prueft Checksumme.
// Rueckgabe: normierte Mnemonic oder null.
export function checkMnemonic(raw: string): string | null {
  const norm = raw.trim().toLowerCase().split(/[\s,;]+/).filter(Boolean).join(' ');
  return validateMnemonic(norm, wordlist) ? norm : null;
}

export function keyFromMnemonic(mn: string, passphrase = ''): Uint8Array {
  const seed = mnemonicToSeedSync(mn, passphrase); // 64 B, PBKDF2-HMAC-SHA512
  for (let i = 0; i < 256; i++) {
    const h = sha256(new Uint8Array([...seed, ...INFO, i]));
    if (validScalar(h)) return h;
  }
  throw new Error('key derivation failed'); // praktisch unmöglich
}

// --- Wortquiz (Bestätigung, dass das Backup existiert) ---

// quizPositions: n zufällige, aufsteigende Wort-Positionen (0-basiert).
export function quizPositions(mn: string, n = 3): number[] {
  const total = mn.split(' ').length;
  const set = new Set<number>();
  while (set.size < Math.min(n, total)) set.add(Math.floor(Math.random() * total));
  return [...set].sort((a, b) => a - b);
}

// quizOptions: richtige Antwort + 3 Ablenker aus der Wortliste, gemischt.
export function quizOptions(mn: string, pos: number): string[] {
  const words = mn.split(' ');
  const correct = words[pos];
  const opts = new Set<string>([correct]);
  while (opts.size < 4) opts.add(wordlist[Math.floor(Math.random() * wordlist.length)]);
  const arr = [...opts];
  for (let i = arr.length - 1; i > 0; i--) { // Fisher-Yates
    const j = Math.floor(Math.random() * (i + 1));
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}
