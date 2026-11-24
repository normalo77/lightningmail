// recipients.ts — To/CC list parsing + Reply-All, DOM-free (app and tests share this).
// Canonical form: addresses joined with ", " inside the encrypted payload
// headers["To"] / headers["Cc"] — a relay never sees the CC list.

// parseRecipients splits a comma/semicolon-separated address field, trims
// whitespace and drops empties. Dedupe is case-insensitive, first-seen order
// wins (mail addresses are case-insensitive by convention).
export function parseRecipients(field: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const part of (field || '').split(/[,;]/)) {
    const a = part.trim();
    if (!a) continue;
    const k = a.toLowerCase();
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(a);
  }
  return out;
}

// uniqueRecipients merges To + CC into the fan-out list: To first, then CC
// addresses not already in To.
export function uniqueRecipients(to: string, cc: string): string[] {
  const toList = parseRecipients(to);
  const lower = new Set(toList.map(a => a.toLowerCase()));
  return [...toList, ...parseRecipients(cc).filter(a => !lower.has(a.toLowerCase()))];
}

// isSelf matches an address against the own account, which the PWA knows as a
// bare name ("alice") — compare both the full address and the local part.
const isSelf = (addr: string, self: string): boolean => {
  if (!self) return false;
  const a = addr.toLowerCase(), s = self.toLowerCase();
  return a === s || a.split('@')[0] === s.split('@')[0];
};

export interface ReplyAllTargets { to: string[]; cc: string[] }

// replyAll collects original sender + all To/Cc addresses, removes self, and
// puts the sender into To with everyone else in CC (sender first, no dupes).
export function replyAll(sender: string, toHdr: string, ccHdr: string, self: string): ReplyAllTargets {
  const candidates = uniqueRecipients(
    [sender.trim(), ...parseRecipients(toHdr)].filter(Boolean).join(', '), ccHdr);
  const rest = candidates.filter(a => !isSelf(a, self));
  const from = sender.trim();
  const to = from && !isSelf(from, self) ? [from] : (rest.length ? [rest[0]] : []);
  const cc = rest.filter(a => !to.some(t => t.toLowerCase() === a.toLowerCase()));
  return { to, cc };
}
