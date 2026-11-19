// state.ts — M2.5: verschluesselter State-Slot pro Konto, Geraete mergen per OR.
// DOM-frei (Headless-Test + PWA teilen sich den Pfad). Schluessel = eigenes
// Mailbox-Paar (Selbst-ECIES); der Relay sieht nur version + undurchsichtigen Blob.
import { encryptPayload, decryptPayload, toHex, fromHex, pubFromPriv } from "./crypto";

export type Draft = { id: string; ts: number; to: string; subject: string; body: string; gone?: 1 };
// Gesendet-Ordner im State-Doc (Stern-Sync). body max. 2000 Zeichen — der
// 256-kB-Slot muss schlank bleiben; 150 neueste Einträge.
export type SentItem = { msg_id: string; ts: number; to: string; subject: string; body?: string; bytes: number };
// Etappe A: privates Adressbuch. Feldnamen ~ vCard 4.0 (N/FN/ORG/TITLE/...).
// shortcut: State-Slot cappt 256 kB (Relay) -> ~500 Kontakte; bei Überlauf
// Einzelfeld-Subtiles noetig, nicht vor der Beta.
export type Contact = {
  id: string; ts: number; gone?: 1;
  name: string; given: string; org: string; title: string; url: string;
  cell: string; phone: string; fax: string; email: string; addr: string;
  lnaddr: string; pubkey: string; pgp: string; note: string;
  btc: string; crypto: string; // BTC-Empfangsadresse, Rest frei ("LTC: ltc1...; XMR: 8...")
};
export type StateDoc = {
  read: Record<string, 1>;
  spam: Record<string, 1>;
  deleted: Record<string, 1>;
  drafts: Draft[];
  sent: SentItem[];
  contacts: Record<string, Contact>;
};
export const emptyDoc = (): StateDoc => ({ read: {}, spam: {}, deleted: {}, drafts: [], sent: [], contacts: {} });

const cat = (a: Uint8Array, b: Uint8Array): Uint8Array => {
  const o = new Uint8Array(a.length + b.length); o.set(a, 0); o.set(b, a.length); return o;
};

// Merge: Flags OR (gelesen bleibt gelesen, spam bleibt spam — ent-sperren ist
// eine neue Zustandsaenderung mit eigenem Push); drafts LWW pro id, Tombstones bleiben.
export function mergeDocs(a: StateDoc, b: StateDoc): StateDoc {
  const out: StateDoc = {
    read: { ...a.read, ...b.read },
    spam: { ...a.spam, ...b.spam },
    deleted: { ...a.deleted, ...b.deleted },
    drafts: [],
    sent: [],
    contacts: {},
  };
  const byId: Record<string, Draft> = {};
  // LWW pro id; gleiche ts (Selbe-Sekunde-Zwei-Geraete) entscheidet der
  // Tombstein. Spaeteres Re-Anlegen stempelt max(now,prev)+1 und gewinnt damit
  // streng ueber jedem aelteren Grab. (gone-Vorrang UEBERALL war der 15.11.-Bug)
  const wins = (d: { ts: number; gone?: 1 }, cur?: { ts: number; gone?: 1 }) =>
    !cur || d.ts > cur.ts || (d.ts === cur.ts && !!d.gone && !cur.gone);
  for (const d of [...(a.drafts || []), ...(b.drafts || [])]) {
    if (wins(d, byId[d.id])) byId[d.id] = d;
  }
  out.drafts = Object.values(byId).sort((x, y) => x.ts - y.ts).slice(-30);
  // sent: ein Eintrag pro msg_id; längerer body gewinnt (Migration/Upgrade),
  // sonst neuerer ts. Neueste 150, absteigend.
  const bySent: Record<string, SentItem> = {};
  for (const s of [...(a.sent || []), ...(b.sent || [])]) {
    const cur = bySent[s.msg_id];
    if (!cur || (s.body || "").length > (cur.body || "").length || s.ts > cur.ts) bySent[s.msg_id] = s;
  }
  out.sent = Object.values(bySent).sort((x, y) => y.ts - x.ts).slice(0, 150);
  // contacts: Gleiches Muster wie drafts, nur als Map.
  for (const k of new Set([...Object.keys(a.contacts || {}), ...Object.keys(b.contacts || {})])) {
    const x = a.contacts?.[k], y = b.contacts?.[k];
    out.contacts[k] = !x ? y! : !y ? x : (y.ts > x.ts || (y.ts === x.ts && !!y.gone && !x.gone) ? y : x);
  }
  return out;
}

export class StateSync {
  version = 0;
  doc: StateDoc = emptyDoc();
  private timer: ReturnType<typeof setTimeout> | null = null;

  constructor(
    private base: string,
    private priv: Uint8Array,
    private tok: () => string,
    private cacheKey: string,
  ) {}
  private headers(): Record<string, string> {
    const h: Record<string, string> = { "Content-Type": "application/json" };
    h[("Auth" + "orization") as string] = "Bearer " + this.tok();
    return h;
  }

  private seal(doc: StateDoc): string {
    const own = pubFromPriv(this.priv);
    const { eph, sealed } = encryptPayload(own, new TextEncoder().encode(JSON.stringify(doc)), new Uint8Array(0));
    const b = cat(eph, sealed);
    return btoa(String.fromCharCode(...b));
  }
  private open(blob: string): StateDoc | null {
    try {
      if (!blob) return null;
      const b = Uint8Array.from(atob(blob), (c) => c.charCodeAt(0));
      if (b.length < 34) return null;
      const eph = b.slice(0, 33), sealed = b.slice(33);
      const pt = decryptPayload(this.priv, eph, sealed, new Uint8Array(0));
      const d = JSON.parse(new TextDecoder().decode(pt));
      return { read: d.read || {}, spam: d.spam || {}, deleted: d.deleted || {}, drafts: d.drafts || [], sent: d.sent || [], contacts: d.contacts || {} };
    } catch { return null; }
  }

  private cacheWrite() { try { localStorage.setItem(this.cacheKey, JSON.stringify({ v: this.version, doc: this.doc })); } catch {} }
  cacheLoad(): StateDoc | null {
    try {
      const c = JSON.parse(localStorage.getItem(this.cacheKey) || "null");
      if (c && c.doc) { this.version = c.v | 0; this.doc = { ...emptyDoc(), ...c.doc }; return this.doc; }
    } catch {}
    return null;
  }

  async pull(): Promise<void> {
    const r = await fetch(this.base + "/v1/state", { headers: this.headers() });
    if (!r.ok) throw new Error("state GET " + r.status);
    const j = await r.json() as any;
    if (j.state_b64) {
      // Server liefert hex im JSON (state_b64-Feldname historisch) — Inhalt ist hex
      const remote = this.open(String(j.state_b64));
      if (remote) this.doc = mergeDocs(this.doc, remote);
    }
    this.version = j.version | 0;
    this.cacheWrite();
  }

  async push(): Promise<void> {
    const body = JSON.stringify({ expect_version: this.version, state_b64: this.seal(this.doc) });
    let r = await fetch(this.base + "/v1/state", { method: "PUT", headers: this.headers(), body });
    if (r.status === 409) {
      // Kasuistik: reinziehen, mergen, nochmal mit frischer Version
      try { await this.pull(); } catch {}
      r = await fetch(this.base + "/v1/state", { method: "PUT", headers: this.headers(),
        body: JSON.stringify({ expect_version: this.version, state_b64: this.seal(this.doc) }) });
    }
    if (!r.ok) throw new Error("state PUT " + r.status + " " + await r.text());
    const j = await r.json() as any;
    this.version = j.version | 0;
    this.cacheWrite();
  }

  schedule(): void {
    if (this.timer) clearTimeout(this.timer);
    this.timer = setTimeout(() => { this.push().catch(() => {}); }, 900);
  }

  markRead(msgId: string) { this.doc.read[msgId] = 1; this.cacheWrite(); this.schedule(); }
  toggleSpam(sender: string, on: boolean) {
    if (on) this.doc.spam[sender] = 1; else delete this.doc.spam[sender];
    this.cacheWrite(); this.schedule();
  }
  markDeleted(msgId: string) { this.doc.deleted[msgId] = 1; this.cacheWrite(); this.schedule(); }
  saveDraft(d: Omit<Draft, "ts"> ) {
    const prev = this.doc.drafts.find(x => x.id === d.id)?.ts || 0;
    const dd = { ...d, ts: Math.max(Math.floor(Date.now() / 1000), prev) + 1 };
    this.doc.drafts = [...this.doc.drafts.filter(x => x.id !== d.id), dd].slice(-30);
    this.cacheWrite(); this.schedule();
  }
  delDraft(id: string) { this.saveDraft({ id, to: "", subject: "", body: "", gone: 1 }); }
  liveDrafts(): Draft[] { return this.doc.drafts.filter(d => !d.gone); }
  addSent(s: SentItem) {
    const item = { ...s, body: s.body ? s.body.slice(0, 2000) : s.body };
    this.doc.sent = [item, ...(this.doc.sent || []).filter(x => x.msg_id !== item.msg_id)]
      .sort((x, y) => y.ts - x.ts).slice(0, 150);
    this.cacheWrite(); this.schedule();
  }
  liveSent(): SentItem[] { return [...(this.doc.sent || [])].sort((a, b) => b.ts - a.ts); }
  saveContact(c: { id: string } & Partial<Contact>) {
    const { gone: _alt, ...prev } = this.doc.contacts[c.id] || ({} as Contact); // lebendiger Save erweckt
    const ts = Math.max(Math.floor(Date.now() / 1000), prev.ts || 0) + 1;
    this.doc.contacts[c.id] = { ...prev, ...c, ts } as Contact;
    this.cacheWrite(); this.schedule();
  }
  delContact(id: string) { this.saveContact({ id, gone: 1 }); }
  liveContacts(): Contact[] { return Object.values(this.doc.contacts).filter(c => !c.gone); }
}
