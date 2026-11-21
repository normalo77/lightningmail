// bip39.ts — Etappe 6d (CONCEPT §27): 24-word recovery, seed in the browser,
// word quiz as confirmation. DOM-free: wizard (main.ts) and tests share the path.
//
// Wordlist: english = the canonical BIP39 list (hardware-wallet standard;
// no official German list exists).
//
// Derivation: seed64 = PBKDF2(mnemonic) via @scure/bip39, then
// priv = sha256(seed || "bmail-mailbox-v1" || counter) with rejection until < n.
// shortcut: 1 seed = 1 mailbox key, no BIP32 path — foreign wallets cannot find
// the key (recovery only here); add multi-account/index derivation if needed,
// the wordlist and seed stay compatible.
import { generateMnemonic, mnemonicToSeedSync, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { u8, validScalar } from './crypto';

const INFO = u8('bmail-mailbox-v1');

export function newMnemonic(): string {
  return generateMnemonic(wordlist, 256); // 256 bits of entropy = 24 words
}

// checkMnemonic: normalizes (lowercase, comma/whitespace) and verifies the checksum.
// Returns the normalized mnemonic or null.
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
  throw new Error('key derivation failed'); // practically impossible
}

// --- Word quiz (confirms the backup exists) ---

// quizPositions: n random ascending word positions (0-based).
export function quizPositions(mn: string, n = 3): number[] {
  const total = mn.split(' ').length;
  const set = new Set<number>();
  while (set.size < Math.min(n, total)) set.add(Math.floor(Math.random() * total));
  return [...set].sort((a, b) => a - b);
}

// quizOptions: correct answer + 3 decoys from the wordlist, shuffled.
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
