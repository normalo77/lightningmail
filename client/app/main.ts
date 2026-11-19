// main.ts — DOM-Leim für die lightningmail v0.1 PWA (M2c). Logik lebt in src/crypto + src/send.
import { parseSec1PEM, pubFromPriv, authSign, toHex, fromB64, decodeEnvelope, decryptPayload, TAG, blobCount, blobRef, sec1PEM, schnorr, sha256 } from '../src/crypto';
import { newMnemonic, checkMnemonic, keyFromMnemonic, quizPositions, quizOptions } from '../src/bip39';
import { parseManifest, reassemble } from '../src/chunks';
import { composeAndSend } from '../src/send';
import { StateSync, type Contact } from '../src/state';
import { wrapKey, unwrapKey, isWrapped, wrapKeyPRF, unwrapKeyPRF } from '../src/keywrap';
let pendingWrap = '';


// Buffer shim: noble-Bibliotheken referenzieren Node-APIs auch im Browser
(globalThis as any).Buffer ??= class extends Uint8Array {
  static from(x: any, _enc?: string): Uint8Array {
    if (typeof x === "string") {
      if (_enc === "base64") return Uint8Array.from(atob(x.replace(/\s+/g, "")), (c) => c.charCodeAt(0));
      if (_enc === "hex") {
        const h = x.replace(/[^0-9a-fA-F]/g, "");
        const b = new Uint8Array(h.length >> 1);
        for (let i = 0; i < b.length; i++) b[i] = parseInt(h.substr(i * 2, 2), 16);
        return b;
      }
      return new TextEncoder().encode(x);
    }
    if (x instanceof Uint8Array) return new Uint8Array(x);
    if (Array.isArray(x)) return new Uint8Array(x);
    throw new Error("Buffer.from: unsupported " + typeof x);
  }
  static isBuffer(): boolean { return true; }
  static alloc(n: number): Uint8Array { return new Uint8Array(n); }
  static concat(list: Uint8Array[]): Uint8Array {
    const out = new Uint8Array(list.reduce((a, x) => a + x.length, 0));
    let o = 0; for (const x of list) { out.set(x, o); o += x.length; }
    return out;
  }
  toString(enc?: string): string {
    const self = this as unknown as Uint8Array;
    if (enc === "hex") return [...self].map((b) => b.toString(16).padStart(2, "0")).join("");
    if (enc === "base64") return btoa(String.fromCharCode(...self));
    return new TextDecoder().decode(self);
  }
};

const $ = (id: string) => document.getElementById(id)!;
let base = '/relay-b', token = '', priv: Uint8Array | null = null, acct = '';
let msgs: MsgRow[] = [];
let receipts: Record<string, number> = {}; // msg_id(hex) -> ✓✓-Zeitstempel (Etappe 6b)
let sel = -1, folder: 'in' | 'spam' | 'out' | 'dra' | 'new' | 'ab' | 'ums' = 'in';
let pemCache = '';
// Auto-Login: erfolgreicher Login merkt sich Schluessel+Konto+Relay im Geraetespeicher
// Session-Speicher: Der entschlüsselte Private Key liegt im Browser nur noch im
// flüchtigen sessionStorage (wird beim Schließen des Browserfensters oder beim
// Klick auf "Abmelden" gelöscht). Auf Android übernimmt der Hardware-Keystore
// (AndroidNative.saveVault/loadVault) die persistente Versiegelung.
const AUTO_KEY = 'lm_autologin', NOAUTO_KEY = 'lm_noauto';
const loadAuto = (): { acct: string; base: string; pem: string } | null => {
  try {
    // Migration: falls aus einer älteren Sitzung noch ein Klartext-Key in localStorage lag,
    // einmalig in sessionStorage umziehen und sofort aus localStorage tilgen.
    const legacy = localStorage.getItem(AUTO_KEY);
    if (legacy) {
      sessionStorage.setItem(AUTO_KEY, legacy);
      localStorage.removeItem(AUTO_KEY);
    }
    const v = JSON.parse(sessionStorage.getItem(AUTO_KEY) || 'null');
    return v && typeof v.pem === 'string' && v.pem && v.acct && v.base ? v : null;
  } catch { return null; }
};
let sync: StateSync | null = null;
let draftId = '';
let healthCache: any = null; // Etappe 7: /health (Byte-Porto-Preis + Kurs) für die Compose-Schätzung
// IdP (§21/§29): OIDC-Login-Modus — ?oidc=<issuer>&sid=… verwandelt die PWA
// in die „Sign in with lightningmail"-Seite (Login wie üblich, dann Consent).
const oidcQ = new URLSearchParams(location.search);
const oidcRelay = oidcQ.get('oidc'), oidcSid = oidcQ.get('sid');
let abSel = '', abEdit = '', abQ = ''; // Adressbuch (Etappe A)
const spamKey = () => `lm_spam_${base.slice(1)}_${acct}`;
const spamSet = (): Set<string> => sync ? new Set(Object.keys(sync.doc.spam)) : new Set(JSON.parse(localStorage.getItem(spamKey()) || '[]'));
const spamAdd = (k: string) => { if (sync) sync.toggleSpam(k, true); else { const x = [...spamSet()]; x.push(k); localStorage.setItem(spamKey(), JSON.stringify(x)); } };
const spamDel = (k: string) => { if (sync) sync.toggleSpam(k, false); else { const x = new Set(spamSet()); x.delete(k); localStorage.setItem(spamKey(), JSON.stringify([...x])); } };

// Gesendet-Ordner: localStorage als Geraete-Fallback, Synchronisierung via StateSync.sent (Stern-Sync)
type MsgRow = { seq: number; msgId: string; subject: string; body: string; sender: string; pub: string; ts: number; signup?: boolean; atts: { sha256: string; name: string; chunked?: boolean }[] };
type SentRow = { ts: number; to: string; subject: string; msg_id: string; bytes: number; body?: string };
const sentKey = () => `lm_out_${base.slice(1)}_${acct}`;
const sentList = (): SentRow[] => {
  const byMsgId: Record<string, SentRow> = {};
  for (const r of (sync?.liveSent() || []) as SentRow[]) byMsgId[r.msg_id] = r;
  for (const r of JSON.parse(localStorage.getItem(sentKey()) || '[]')) byMsgId[r.msg_id] ??= r;
  return Object.values(byMsgId).sort((a, b) => b.ts - a.ts);
};
const sentPush = (r: SentRow) => {
  const l = JSON.parse(localStorage.getItem(sentKey()) || '[]'); l.unshift(r);
  localStorage.setItem(sentKey(), JSON.stringify(l.slice(0, 200)));
  if (sync) sync.addSent(r);
};

const ERRDE: Record<number, string> = {
  400: 'Die Anwendung hat einen unverständlichen Brief gebaut (400).',
  401: 'Sitzung abgelaufen — bitte neu anmelden.',
  402: 'Guthaben zu niedrig — das Porto kann nicht bezahlt werden.',
  404: 'Empfänger in diesem Relay nicht gefunden.',
  409: 'Diese Nachricht ist bereits raus (doppelte msg_id verhindert Doppelposting).',
  413: 'Speicherplatz der Mailbox voll.',
  502: 'Lightning-Pfad gerade dicht (Kanal?) — später erneut versuchen.',
  500: 'Serverfehler — Details in den Relay-Logs.',
};
const errText = (st: number, raw = '') => `${ERRDE[st] || 'Fehler ' + st}` + (raw && !ERRDE[st] ? ': ' + raw.slice(0, 80) : '');

async function api(path: string, init?: RequestInit) {
  const h: Record<string, string> = { ...((init?.headers as Record<string, string>) || {}) };
  h['Auth' + 'orization'] = 'Bearer ' + token;
  const r = await fetch(base + path, { ...init, headers: h });
  if (r.status === 401 && token) { token = ''; $('nav-out').click(); }
  return r;
}

async function login(pem: string) {
  acct = $('l-acct').value.trim(); base = $('l-relay').value;
  healthCache = null; // Relay-Wechsel → Byte-Porto-Preise neu ziehen
  priv = parseSec1PEM(pem);
  const sig = authSign(priv, acct);
  const r = await fetch(base + '/v1/auth', { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ address: acct, pubkey_hex: toHex(pubFromPriv(priv)), sig: toHex(sig) }) });
  if (!r.ok) {
    $('l-err').textContent = r.status === 401
      ? 'Konto-Name passt nicht zum geladenen Schlüssel (oder Key nicht registriert).'
      : errText(r.status, await r.text());
    return;
  }
  token = ((await r.json()) as any).token;
  localStorage.removeItem(AUTO_KEY);
  // Auf Android nur im Hardware-Keystore speichern; im Browser nur in sessionStorage (Tab-Lebensdauer)
  if ((window as any).AndroidNative?.saveVault) {
    try { (window as any).AndroidNative.saveVault(JSON.stringify({ acct, base, pem })); } catch { /* Tresor ist Komfort */ }
    sessionStorage.setItem(AUTO_KEY, JSON.stringify({ acct, base, pem }));
  } else {
    sessionStorage.setItem(AUTO_KEY, JSON.stringify({ acct, base, pem }));
  }
  localStorage.removeItem(NOAUTO_KEY);
  $('login').classList.add('hidden'); $('app').classList.remove('hidden');
  const bp = $('btn-passkey');
  if (bp && (passkeyAvailable() || !!(window as any).AndroidNative?.requestBiometricAuth)) {
    bp.style.display = '';
    bp.onclick = passkeyRegister;
  }
  const kw = $('btn-keywrap'); if (kw) { kw.style.display = ''; kw.onclick = () => {
    const p1 = prompt('Passphrase fuer die Key-Datei (min. 8 Zeichen):'); if (!p1) return;
    if (p1 !== prompt('zur Kontrolle erneut eingeben:')) { alert('Passphrases stimmen nicht ueberein'); return; }
    try {
      const blob = new Blob([wrapKey(pemCache, p1)], { type: 'text/plain' });
      const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
      a.download = `lightningmail-${acct}.lmkey`; a.click();
    } catch (e: any) { alert(e.message); }
  }; }
  $('who').textContent = `${acct}@${base.startsWith('/') ? location.hostname : base.slice(1)} · `;
  sync = new StateSync(base, priv, () => token, `lm_state_${base.slice(1)}_${acct}`);
  sync.cacheLoad();
  for (const k of JSON.parse(localStorage.getItem(spamKey()) || '[]')) sync.doc.spam[k] = 1;
  // Migration: lokale Gesendet-Einträge ins State-Doc überführen (Stern-Sync)
  for (const s of JSON.parse(localStorage.getItem(sentKey()) || '[]'))
    if (!sync.liveSent().some(x => x.msg_id === s.msg_id)) sync.addSent(s);
  try { await sync.pull(); } catch { /* ohne State-Slot laeuft die UI aus dem Cache */ }
  await refresh();
  if (oidcRelay && oidcSid) oidcFlow(); // IdP-Modus: nach Login direkt zum Consent
}

async function refreshBalance() {
  const br = await api('/v1/balance');
  if (!br.ok) { $('balance').textContent = errText(br.status); return; }
  const bal = await br.json() as any;
  $('balance').textContent = `Guthaben: ${Math.floor((bal.balance_msat || 0) / 1000)} sats`;
}

// Etappe 6b: ✓✓-Receipts des eigenen Kontos laden (Gesendet-Ordner)
async function fetchReceipts() {
  try {
    const r = await api('/v1/receipts');
    if (r.ok) for (const x of (((await r.json()) as any).receipts || [])) receipts[x.msg_id] = x.ts;
  } catch { /* Receipts sind Komfort, kein Fehlerfall */ }
}

async function refresh() {
  await refreshBalance();
  await fetchReceipts();
  const ir = await api('/v1/inbox');
  if (!ir.ok) { msgs = []; $('list').innerHTML = `<div class="meta" style="padding:12px">${errText(ir.status)}</div>`; return; }
  const inbox = await ir.json() as any;
  msgs = [];
  for (const m of (inbox.messages || [])) {
    try {
      const env = decodeEnvelope(fromB64(m.envelope_b64));
      const aad = new Uint8Array([...env[TAG.RecipientHash], ...env[TAG.MsgID]]);
      const pt = decryptPayload(priv!, env[TAG.Ephemeral], env[TAG.Payload], aad);
      const p = JSON.parse(new TextDecoder().decode(pt));
      const atts = (p.attachments || []).map((a: any) => ({ sha256: a.sha256, name: a.name, chunked: !!a.chunked }));
      const refs = env[TAG.BlobRefs] ? Array.from({ length: blobCount(env[TAG.BlobRefs]) }, (_, i) => toHex(blobRef(env[TAG.BlobRefs]!, i))) : [];
      msgs.push({ seq: m.seq, msgId: toHex(env[TAG.MsgID]), subject: p.subject, body: p.body, sender: toHex(env[TAG.SenderPubkey]).slice(0, 12), pub: toHex(env[TAG.SenderPubkey]), ts: m.received_at, signup: !!(env[TAG.Signup] && env[TAG.Signup][0] === 1), atts: atts.length ? atts : refs.map((r, i) => ({ sha256: r, name: `anhang-${i + 1}` })) });
    } catch (e: any) { (window as any).__decodeErr = String(e && e.stack || e); }
  }
  render();
  const un = visible().filter(m => !(sync && sync.doc.read[m.msgId])).length;
  $('nav-in').textContent = folder === 'in' && un ? `Posteingang (${un})` : 'Posteingang';
}

function visible() {
  const sp = spamSet();
  return msgs.filter(m => !(sync && sync.doc.deleted[m.msgId]))
             .filter(m => folder === 'spam' ? sp.has(m.sender) : !sp.has(m.sender));
}

function render() {
  if (folder === 'new') { renderCompose(); $('list').innerHTML = ''; return; }
  if (folder === 'ab') { renderAB(); return; }
  if (folder === 'ums') { renderUms(); return; }
  if (folder === 'out') { renderSent(); return; }
  if (folder == 'dra') { renderDrafts(); return; }
  const list = visible().slice().reverse();
  $('list').innerHTML = list.map(m => `<div class="row ${m.seq === sel ? 'sel' : ''}" data-seq="${m.seq}">
    <div class="subj" ${sync && sync.doc.read[m.msgId] ? 'style="font-weight:400;color:#8a8271"' : ''}>${m.signup ? '[🔑 Registrierung] ' : ''}${esc(m.subject)}</div>
    <div class="meta">${esc(m.sender)}… · ${new Date(m.ts * 1000).toLocaleString('de')} ${m.atts.length ? '📎' : ''}</div></div>`).join('') ||
    '<div class="meta" style="padding:12px">— leer —</div>';
  document.querySelectorAll('#list .row').forEach(el =>
    el.addEventListener('click', () => { sel = +el.getAttribute('data-seq')!; const mm = msgs.find(x => x.seq === sel); if (mm && sync) { sync.markRead(mm.msgId); } render(); renderDetail(); }));
  if (sel >= 0 && list.some(m => m.seq === sel)) renderDetail(); else $('detail').innerHTML = '<p class="meta">Message wählen.</p>';
}

function renderSent() {
  const l = sentList();
  const tick = (id: string) => receipts[id]
    ? `<span style="color:var(--accent)" title="Empfänger hat abgerufen ${new Date(receipts[id] * 1000).toLocaleString('de')}">✓✓</span>`
    : `<span title="zugestellt (Porto am Empfänger-Relay settled) — auf Empfänger-Abruf wartend">✓</span>`;
  $('list').innerHTML = l.map((s, i) => `<div class="row ${i === sel ? 'sel' : ''}" data-si="${i}">
    <div class="subj">${esc(s.subject)}</div>
    <div class="meta">→ ${esc(s.to)} · ${new Date(s.ts * 1000).toLocaleString('de')} · ${(s.bytes / 1024).toFixed(0)} kB ${tick(s.msg_id)}</div></div>`).join('') ||
    '<div class="meta" style="padding:12px">— nichts gesendet —</div>';
  document.querySelectorAll('#list .row').forEach(el => el.addEventListener('click', () => {
    sel = +el.getAttribute('data-si')!; const s = sentList()[sel];
    $('detail').innerHTML = `<div class="card"><div class="subj" style="font-size:17px">${esc(s.subject)}</div>
      <div class="meta">An ${esc(s.to)} · ${new Date(s.ts * 1000).toLocaleString('de')}<br>msg_id ${esc(s.msg_id.slice(0, 16))}… · Porto bezahlt</div>
      ${s.body ? `<pre style="white-space:pre-wrap;font:inherit;margin:14px 0">${esc(s.body)}</pre>` : ''}
      <p class="meta">${receipts[s.msg_id]
        ? `✓✓ vom Empfänger abgerufen: ${new Date(receipts[s.msg_id] * 1000).toLocaleString('de')}`
        : '✓ zugestellt (am Empfänger-Relay) — warte auf Abruf durch den Empfänger'}</p>
      <p class="meta">Synchronisiert verschlüsselt über dein Relay zwischen all deinen Geräten (Stern-Sync).</p></div>`;
  }));
}

function renderDrafts() {
  const l = sync ? sync.liveDrafts().slice().reverse() : [];
  $('list').innerHTML = l.map((d) => `<div class="row" data-did="${d.id}">
    <div class="subj">${esc(d.subject || '(ohne Betreff)')}</div>
    <div class="meta">→ ${esc(d.to || '?')} · ${new Date(d.ts * 1000).toLocaleString('de')}</div></div>`).join('') ||
    '<div class="meta" style="padding:12px">— keine Entwürfe —</div>';
  document.querySelectorAll('#list .row').forEach(el => el.addEventListener('click', () => {
    const d = (sync?.liveDrafts() || []).find(x => x.id === el.getAttribute('data-did'));
    if (!d) return;
    draftId = d.id; folder = 'new'; mark(); render();
    setTimeout(() => {
      ($('c-to') as HTMLInputElement).value = d.to; ($('c-subj') as HTMLInputElement).value = d.subject;
      ($('c-body') as HTMLTextAreaElement).value = d.body;
    }, 0);
  }));
  $('detail').innerHTML = '<p class="meta">Entwurf anklicken zum Weiterbearbeiten — Entwürfe synchronisieren zwischen Geräten.</p>';
}

function esc(s: string) { return (s || '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]!)); }

// Anhang-Cache in IndexedDB: einmal geöffnete Blobs überleben lokal dauerhaft —
// auch nachdem der Relay-Sweep (Erstdownload + 7 Tage) sie serverseitig löscht.
const idbOpen = (): Promise<IDBDatabase> => new Promise((res, rej) => {
  const rq = indexedDB.open('lightningmail_blobs', 1);
  rq.onupgradeneeded = () => rq.result.createObjectStore('blobs');
  rq.onsuccess = () => res(rq.result);
  rq.onerror = () => rej(rq.error);
});
async function idbGetBlob(sha: string): Promise<Uint8Array | null> {
  try {
    const db = await idbOpen();
    return await new Promise((res) => {
      const rq = db.transaction('blobs').objectStore('blobs').get(sha);
      rq.onsuccess = () => res((rq.result as Uint8Array) || null);
      rq.onerror = () => res(null);
    });
  } catch { return null; }
}
async function idbPutBlob(sha: string, bytes: Uint8Array): Promise<void> {
  try {
    const db = await idbOpen();
    await new Promise<void>((res) => {
      const tx = db.transaction('blobs', 'readwrite');
      tx.objectStore('blobs').put(bytes, sha);
      tx.oncomplete = () => res();
      tx.onerror = () => res();
    });
  } catch { /* Cache ist Komfort, kein Fehlerfall */ }
}

function renderDetail() {
  const m = msgs.find(x => x.seq === sel)!;
  const sp = spamSet().has(m.sender);
  const cn = contactFor(m.pub);
  $('detail').innerHTML = `<div class="card">
    <div class="subj" style="font-size:17px">${m.signup ? '[🔑 Registrierung] ' : ''}${esc(m.subject)}</div>
    <div class="meta">Von ${cn ? esc(abLabel(cn)) : esc(m.sender) + '…'} · ${new Date(m.ts * 1000).toLocaleString('de')}</div>
    <pre style="white-space:pre-wrap;font:inherit;margin:14px 0">${esc(m.body)}</pre>
    ${m.atts.map(a => `<span class="attach" data-sha="${a.sha256}" data-name="${esc(a.name)}" data-chunked="${a.chunked ? 1 : 0}">↓ ${esc(a.name)}${a.chunked ? ' 📦' : ''}</span>`).join('')}
    <div class="classify">Absender:
      <button id="cl-spam" class="${sp ? 'on' : ''}">${sp ? 'unerwünscht' : 'als unerwünscht markieren'}</button>
      ${sp ? '<button id="cl-un">zurück nach Posteingang</button>' : ''}
      <button id="cl-del">löschen</button>
      ${cn ? '' : '<button id="cl-ab">als Kontakt speichern</button>'}
    </div></div>`;
  document.querySelectorAll('.attach').forEach(el => el.addEventListener('click', async () => {
    // Etappe 7: chunked Anhänge erst aus Manifest + Scheiben zusammensetzen.
    // IndexedDB-Cache hat Vorrang: bedient den Anhang sofort und dauerhaft,
    // selbst wenn das Relay den Blob längst gesweept hat.
    const sha = el.getAttribute('data-sha')!, fname = el.getAttribute('data-name')!;
    const save = (blob: Blob) => {
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a'); a.href = url; a.download = fname; a.click();
    };
    try {
      const cached = await idbGetBlob(sha);
      if (cached) { save(new Blob([cached as BlobPart])); return; }
      let bytes: Uint8Array;
      if (el.getAttribute('data-chunked') === '1') {
        const mr = await api(`/v1/blob/${sha}`);
        if (!mr.ok) { alert(errText(mr.status)); return; }
        const man = parseManifest(new Uint8Array(await mr.arrayBuffer()));
        bytes = await reassemble(async (s) => {
          const rr = await api(`/v1/blob/${s}`);
          if (!rr.ok) throw new Error(errText(rr.status));
          return new Uint8Array(await rr.arrayBuffer());
        }, man);
      } else {
        const r = await api(`/v1/blob/${sha}`);
        if (!r.ok) { alert(errText(r.status)); return; }
        bytes = new Uint8Array(await r.arrayBuffer());
      }
      await idbPutBlob(sha, bytes);
      save(new Blob([bytes as BlobPart]));
    } catch (e: any) { alert('Download: ' + String(e?.message || e).slice(0, 120)); }
  }));
  $('cl-spam').onclick = () => { sp ? spamDel(m.sender) : spamAdd(m.sender); render(); };
  if ($('cl-un')) $('cl-un').onclick = () => { spamDel(m.sender); render(); };
  if ($('cl-ab')) $('cl-ab').onclick = () => { abSeed = { pubkey: m.pub }; folder = 'ab'; abEdit = 'new'; abSel = ''; mark(); render(); };
  $('cl-del').onclick = () => { if (sync) { sync.markDeleted(m.msgId); sync.push().catch(() => {}); } sel = -1; render(); };
}

// --- Etappe A: Adressbuch (90er-Mailclient: Toolbar, Kontaktliste, Eigenschaften-Fenster) ---
const abLabel = (c: Contact) => [c.name, c.given].filter(Boolean).join(", ") || c.lnaddr || c.email || "(ohne Namen)";
const contactFor = (pub: string) => sync?.liveContacts().find(c => c.pubkey && c.pubkey === pub);
const newId = () => Date.now().toString(36) + Math.random().toString(36).slice(2, 6); // randomUUID braucht Secure-Context, wir laufen LAN-http
let abSeed: Partial<Contact> = {};
const ABFIELDS: [keyof Contact, string][] = [
  ['name', 'Nachname'], ['given', 'Vorname'], ['org', 'Firma'], ['title', 'Position'],
  ['url', 'Webseite'], ['cell', 'Mobil'], ['phone', 'Festnetz'], ['fax', 'Fax'],
  ['email', 'E-Mail'], ['addr', 'Adresse'], ['lnaddr', 'Lightning-Adresse'],
  ['btc', 'BTC-Adresse'], ['crypto', 'Andere Coins (frei)'],
  ['pubkey', 'Mailbox-Pubkey'], ['pgp', 'PGP-Key (optional)'], ['note', 'Notiz'],
];

function renderAB() {
  $('list').innerHTML = `<div class="abbar">
      <button id="ab-new">Neu…</button><button id="ab-del">Entfernen</button><button id="ab-exp">Export…</button>
      <input id="ab-q" placeholder="Suchen" value="${esc(abQ)}" style="flex:1;min-width:70px"></div>
    <div id="abrows"></div>`;
  const all = sync ? sync.liveContacts() : [];
  const drawRows = () => {
    const q = abQ.trim().toLowerCase();
    const list = all
      .filter(c => !q || [c.name, c.given, c.org, c.title, c.lnaddr, c.email, c.cell, c.phone].join(" ").toLowerCase().includes(q))
      .sort((x, y) => abLabel(x).localeCompare(abLabel(y), "de"));
    $('abrows').innerHTML = list.map(c => `<div class="row ${c.id === abSel ? 'sel' : ''}" data-cid="${c.id}">
      <div class="subj">${esc(abLabel(c))}</div>
      <div class="meta">${esc([c.org, c.lnaddr || c.email].filter(Boolean).join(" · "))}</div></div>`).join('') ||
      '<div class="meta" style="padding:12px">— keine Kontakte —</div>';
    document.querySelectorAll('#abrows .row[data-cid]').forEach(el => {
      el.addEventListener('click', () => { abSel = el.getAttribute('data-cid')!; abEdit = ''; renderAB(); });
      el.addEventListener('dblclick', () => { abSel = el.getAttribute('data-cid')!; abEdit = abSel; abSeed = {}; renderAB(); });
    });
  };
  drawRows();
  ($('ab-q') as HTMLInputElement).addEventListener('input', (ev) => { abQ = (ev.target as HTMLInputElement).value; drawRows(); });
  $('ab-new').onclick = () => { abEdit = 'new'; abSel = ''; abSeed = {}; renderAB(); };
  $('ab-del').onclick = () => {
    const c = all.find(x => x.id === abSel); if (!c || !sync) return;
    if (!confirm(`Kontakt „${abLabel(c)}“ aus dem Adressbuch entfernen?`)) return;
    sync.delContact(c.id); abSel = ''; abEdit = ''; renderAB();
  };
  $('ab-exp').onclick = () => exportVcf(all);

  if (abEdit) { renderABForm(); return; }
  const c = all.find(x => x.id === abSel);
  $('detail').innerHTML = c
    ? `<div class="window" style="max-width:64ch"><div class="title-bar"><div class="title-bar-text">Eigenschaften — ${esc(abLabel(c))}</div></div>
       <div class="window-body"><div class="abform">` +
      ABFIELDS.filter(([k]) => String((c as any)[k] || '') !== '').map(([k, l]) =>
        `<label>${l}</label><div style="white-space:pre-wrap;font-size:12px">${esc(String(c[k]))}</div>`).join('') +
      `</div><p style="margin:10px 0 0"><button id="ab-prop">Eigenschaften…</button> <button id="ab-mail">Nachricht senden</button></p></div></div>`
    : '<p class="meta">Kontakt auswählen — oder „Neu…“ klicken. Das Adressbuch synchronisiert zwischen deinen Geräten.</p>';
  if (c && $('ab-prop')) $('ab-prop').onclick = () => { abEdit = c.id; abSeed = {}; renderAB(); };
  if (c && $('ab-mail')) $('ab-mail').onclick = () => {
    folder = 'new'; draftId = ''; mark(); render();
    setTimeout(() => { ($('c-to') as HTMLInputElement).value = c.lnaddr || c.email; }, 0);
  };
}

function renderABForm() {
  const cur: Partial<Contact> = abEdit === 'new' ? { id: '', ...abSeed } : (sync?.doc.contacts[abEdit] || {});
  const fld = (k: keyof Contact, l: string) => `<label>${l}</label>` +
    (k === 'pgp' || k === 'addr' || k === 'note'
      ? `<textarea id="abf-${k}" rows="3">${esc(String(cur[k] || ''))}</textarea>`
      : `<input id="abf-${k}" value="${esc(String(cur[k] || ''))}">`);
  $('detail').innerHTML = `<div class="window" style="max-width:64ch"><div class="title-bar"><div class="title-bar-text">${abEdit === 'new' ? 'Neuer Kontakt' : 'Kontakt bearbeiten'}</div></div>
    <div class="window-body"><form id="ab-form" class="abform">${ABFIELDS.map(([k, l]) => fld(k, l)).join('')}
    <div></div><div><button type="submit">OK</button> <button type="button" id="ab-cancel">Abbrechen</button></div>
    </form></div></div>`;
  $('ab-cancel').onclick = () => { abEdit = ''; abSeed = {}; renderAB(); };
  $('ab-form').onsubmit = (ev) => {
    ev.preventDefault();
    if (!sync) { alert('Ohne Sync kein Adressbuch — neu anmelden.'); return; }
    const id = abEdit === 'new' ? newId() : abEdit;
    const patch: Record<string, string> = {};
    for (const [k] of ABFIELDS) patch[k] = (document.getElementById('abf-' + k) as HTMLInputElement).value.trim();
    sync.saveContact({ id, ...patch } as { id: string } & Partial<Contact>);
    abEdit = ''; abSel = id; abSeed = {}; renderAB();
  };
}

function exportVcf(list: Contact[]) {
  const line = (k: string, v: string) => v ? `${k}:${v.replace(/\r?\n/g, '\\n')}\r\n` : '';
  const vcf = list.map(c => 'BEGIN:VCARD\r\nVERSION:3.0\r\n' +
    ((c.name || c.given) ? line('N', [c.name, c.given].join(';')) : '') + line('FN', abLabel(c)) +
    line('ORG', c.org) + line('TITLE', c.title) + line('URL', c.url) +
    line('TEL;CELL', c.cell) + line('TEL;WORK', c.phone) + line('TEL;FAX', c.fax) +
    line('EMAIL', c.email) + line('ADR;POSTAL', ';;;;;;' + (c.addr || '').replace(/\r?\n/g, ';')) +
    (c.lnaddr ? 'X-LIGHTNING:' + c.lnaddr + '\r\n' : '') +
    (c.btc ? 'X-BTC:' + c.btc + '\r\n' : '') +
    line('X-CRYPTO', c.crypto) +
    line('NOTE', c.note) + 'END:VCARD\r\n').join('');
  const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([vcf], { type: 'text/vcard' }));
  a.download = 'adressbuch.vcf'; a.click();
}

function openPicker(cb: (addrs: string[]) => void) {
  const all = (sync?.liveContacts() || []).filter(c => c.lnaddr || c.email)
    .sort((x, y) => abLabel(x).localeCompare(abLabel(y), 'de'));
  const ov = document.createElement('div');
  ov.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.3);display:flex;align-items:center;justify-content:center;z-index:50';
  ov.innerHTML = `<div class="window" style="width:430px;max-width:92vw"><div class="title-bar"><div class="title-bar-text">Adressbuch — Empfänger wählen</div></div>
    <div class="window-body" style="padding:8px"><div style="max-height:300px;overflow:auto;background:#fff;border:1px solid var(--border);border-radius:7px">` +
    (all.length ? all.map(c => `<label style="display:block;padding:3px 6px;font-size:12px;font-weight:400"><input type="checkbox" value="${esc(c.lnaddr || c.email)}"> ${esc(abLabel(c))} <span class="meta">${esc(c.lnaddr || c.email)}</span></label>`).join('')
      : '<div class="meta" style="padding:8px">Keine Adresse in den Kontakten — Adressbuch zuerst füllen.</div>') +
    `</div><div style="margin-top:8px;text-align:right"><button id="pk-ok">OK</button> <button id="pk-x">Abbrechen</button></div></div></div>`;
  document.body.appendChild(ov);
  (ov.querySelector('#pk-x') as HTMLElement).onclick = () => ov.remove();
  (ov.querySelector('#pk-ok') as HTMLElement).onclick = () => {
    cb([...ov.querySelectorAll('input:checked')].map(x => (x as HTMLInputElement).value).filter(Boolean));
    ov.remove();
  };
}

// Foto-Kompression: längste Kante 1600px, JPEG q0.82; wenn teurer als Original -> Original
async function shrinkImage(file: File): Promise<{ bytes: Uint8Array; name: string; note: string }> {
  const raw = new Uint8Array(await file.arrayBuffer());
  try {
    const bmp = await createImageBitmap(file);
    const scale = Math.min(1, 1600 / Math.max(bmp.width, bmp.height));
    if (scale >= 1 && raw.length < 400_000) return { bytes: raw, name: file.name, note: '' };
    const cv = document.createElement('canvas');
    cv.width = Math.round(bmp.width * scale); cv.height = Math.round(bmp.height * scale);
    (cv.getContext('2d') as CanvasRenderingContext2D).drawImage(bmp, 0, 0, cv.width, cv.height);
    const blob: Blob = await new Promise((res) => cv.toBlob((b) => res(b as Blob), 'image/jpeg', 0.82));
    const out = new Uint8Array(await blob.arrayBuffer());
    if (out.length >= raw.length) return { bytes: raw, name: file.name, note: '' };
    const name = file.name.replace(/\.[a-z0-9]+$/i, '') + '.jpg';
    return { bytes: out, name, note: `komprimiert ${Math.round(raw.length / 1024)}→${Math.round(out.length / 1024)} kB` };
  } catch { return { bytes: raw, name: file.name, note: '(Bild nicht lesbar — Original)' }; }
}

async function renderCompose() {
  $('detail').innerHTML = `<div class="card"><form class="compose" id="cform">
    <div style="display:flex;gap:6px"><input id="c-to" placeholder="An: name@domain" required style="flex:1"><button type="button" id="c-ab" title="Aus Adressbuch">📇</button></div>
    <input id="c-subj" placeholder="Betreff" required>
    <textarea id="c-body" placeholder="Nachricht…"></textarea>
    <input type="file" id="c-file" multiple>
    <label style="font-size:13px;color:var(--faint)"><input type="checkbox" id="c-orig"> Original senden (Fotos sonst auf 1600px JPEG komprimiert)</label>
    <label style="font-size:13px;color:var(--faint)"><input type="checkbox" id="c-signup"> Als Dienst-Registrierung senden (Tag 0x0A, zahlt Porto-Vorschuss)</label>
    <div id="portofuss" class="meta">Empfänger wählen — Porto und Fingerprint erscheinen hier.</div>
    <div><button type="submit">Senden</button> <button type="button" id="c-save">Als Entwurf speichern</button> <span id="c-msg" class="meta"></span></div>
  </form></div>`;

  const lookup = async () => {
    const name = $('c-to').value.trim().split('@')[0]; if (!name) return;
    const r = await fetch(`${base}/v1/profile/${name}`);
    const el = $('portofuss'); if (!el) return;
    if (!r.ok) { el.textContent = errText(r.status); return; }
    const p = await r.json() as any;
    const fp = String(p.pubkey || '');
    el.textContent = `Empfänger-Key ${fp.slice(0, 6)}…${fp.slice(-4)} · Porto ${p.foreign_sats} sats (Porto-Vorschuss: ${p.welcome_sats ?? p.foreign_sats * 3} sats)` +
      (fp.slice(0, 2) === '02' || fp.slice(0, 2) === '03' ? '' : ' · WARNUNG: seltsamer Key');
  };
  $('c-to').addEventListener('change', lookup);
  // Etappe I (§28): Deep-Link ?an=<adresse>&signup=1 → Dienst-Registrierung vorbefüllen
  const cq = new URLSearchParams(location.search);
  if (cq.get('signup') === '1' || cq.get('an')) {
    ($('c-signup') as HTMLInputElement).checked = true;
    const an = cq.get('an');
    if (an) { ($('c-to') as HTMLInputElement).value = an; lookup(); }
  }
  $('c-ab').onclick = () => openPicker((addrs) => {
    if (!addrs.length) return;
    const el = $('c-to') as HTMLInputElement;
    el.value = [el.value.trim(), ...addrs].filter(Boolean).join(', ');
    el.dispatchEvent(new Event('change'));
  });
  $('c-file').addEventListener('change', async () => {
    const fs = [...($('c-file') as any).files] as File[];
    const el = $('portofuss') as HTMLElement;
    if (!fs.length) { el.textContent = 'Empfänger wählen — Porto und Fingerprint erscheinen hier.'; return; }
    // Etappe 7: Byte-Porto-Schätzung aus /health (Preis + Tageskurs)
    let cost = '';
    try {
      healthCache ??= await fetch(base + '/health').then(r => r.json());
      const h = healthCache;
      if (h?.byte_porto_meur_per_mb > 0 && h?.rate_meur_per_btc > 0) {
        const totalBytes = fs.reduce((s, f) => s + f.size, 0);
        const x1000 = Math.ceil(totalBytes * h.byte_porto_meur_per_mb * 1000 / 1048576);
        const msat = Math.ceil(x1000 * 1e8 / h.rate_meur_per_btc);
        cost = ` · Byte-Porto ≈ ${Math.ceil(msat / 1000)} sats (${(h.byte_porto_meur_per_mb / 10).toLocaleString('de')} ct/MiB; Fotos ggf. kleiner nach Kompression)`;
      }
    } catch { /* Schätzung ist Komfort, kein Fehlerfall */ }
    el.textContent = `${fs.length} Anhang: ` + fs.map(f => `${f.name} (${f.size > 1048576 ? (f.size / 1048576).toFixed(1) + ' MB' : Math.round(f.size / 1024) + ' kB'})`).join(', ') + cost;
  });

  $('c-save').onclick = () => {
    if (!sync) { $('c-msg').textContent = '✗ ohne Sync keine Entwürfe'; return; }
    if (!draftId) draftId = Date.now().toString(36) + Math.random().toString(36).slice(2, 6); // randomUUID braucht Secure-Context, wir laufen LAN-http
    sync.saveDraft({ id: draftId, to: $('c-to').value, subject: $('c-subj').value, body: $('c-body').value });
    $('c-msg').textContent = '✓ Entwurf gespeichert (synchronisiert).';
  };
  $('cform').onsubmit = async (ev) => {
    ev.preventDefault();
    if (!token || !priv) { $('c-msg').textContent = '✗ nicht angemeldet'; return; }
    $('c-msg').textContent = 'sende…';
    try {
      const files = [...($('c-file') as any).files] as File[];
      const orig = ($('c-orig') as HTMLInputElement).checked;
      const atts: { name: string; bytes: Uint8Array }[] = [];
      for (const f of files) {
        if (!orig && f.type.startsWith('image/')) {
          const s = await shrinkImage(f);
          atts.push({ name: s.name, bytes: s.bytes });
          if (s.note) $('c-msg').textContent = s.note + ' …';
        } else atts.push({ name: f.name, bytes: new Uint8Array(await f.arrayBuffer()) });
      }
      const total = atts.reduce((a, x) => a + x.bytes.length, 0);
      const out = await composeAndSend(base, token, priv!, { to: ($('c-to') as HTMLInputElement).value, subject: ($('c-subj') as HTMLInputElement).value, body: ($('c-body') as HTMLTextAreaElement).value, attachments: atts, signup: ($('c-signup') as HTMLInputElement).checked,
        onProgress: (m) => { const e = $('c-msg'); if (e) e.textContent = m; } });
      sentPush({ ts: Math.floor(Date.now() / 1000), to: ($('c-to') as HTMLInputElement).value, subject: ($('c-subj') as HTMLInputElement).value, msg_id: String(out.msg_id || ''), bytes: total, body: ($('c-body') as HTMLTextAreaElement).value.slice(0, 2000) });
      if (draftId && sync) { sync.delDraft(draftId); draftId = ''; }
      $('c-msg').textContent = '✓ gesendet (' + (out.msg_id || '').slice(0, 10) + '…)';
      await refreshBalance();
    } catch (e: any) {
      const m0 = String(e.message || e);
      const st = /: (\d{3}) /.exec(m0);
      $('c-msg').textContent = '✗ ' + (st ? errText(+st[1], m0) : m0.slice(0, 120));
    }
  };
}

async function useKey(txt: string, fname = '') {
  if (isWrapped(txt)) {
    pendingWrap = txt;
    $('l-passrow').style.display = '';
    const kr = document.getElementById('l-keyready'); if (kr) kr.style.display = 'none';
    $('l-err').textContent = (fname ? `Datei „${fname}“ geladen — ` : '') + 'bitte Passphrase eingeben und auf „🔓 OK / Anmelden" klicken.';
    setTimeout(() => ($('l-pass') as HTMLInputElement)?.focus(), 30);
    return;
  }
  pemCache = txt;
  const kr = document.getElementById('l-keyready'); if (kr) kr.style.display = '';
  const btn = document.getElementById('l-login');
  if (btn) btn.textContent = `✓ Schlüssel bereit (${($('l-acct') as HTMLInputElement).value.trim()}) — OK / Jetzt anmelden`;
  await login(txt);
}
async function tryUnwrap() {
  try {
    pemCache = unwrapKey(pendingWrap, ($('l-pass') as HTMLInputElement).value);
    const kr = document.getElementById('l-keyready'); if (kr) kr.style.display = '';
    await login(pemCache);
  }
  catch (e: any) { $('l-err').textContent = '✗ ' + e.message; }
}
if ($('l-pass')) ($('l-pass') as HTMLInputElement).onkeydown = (e) => { if (e.key === 'Enter') { e.preventDefault(); tryUnwrap(); } };
$('l-demo').onclick = async () => {
  const r = await fetch(`/keys/${$('l-acct').value.trim()}.key`);
  if (!r.ok) { $('l-err').textContent = 'Demo-Key nicht gefunden (' + $('l-acct').value.trim() + ')'; return; }
  await useKey(await r.text());
};
// --- Etappe 6d (§27): Setup-Wizard — 24-Wort-Recovery (BIP39), Schluessel im Browser,
// Wortquiz als Backup-Beweis, .lmkey-Datei OPTIONAL (Wörter sind das Haupt-Backup).
// Reihenfolge behält die ecd07eb-Lektion: Backup exists VOR der Konto-Anlage → kein Waisen-Konto.
const wizOverlay = (title: string, width = 560): { body: HTMLElement; close: () => void } => {
  const ov = document.createElement('div');
  ov.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.35);display:flex;align-items:center;justify-content:center;z-index:60;overflow:auto;padding:10px';
  ov.innerHTML = `<div class="window" style="width:${width}px;max-width:96vw;max-height:96vh;overflow:auto"><div class="title-bar"><div class="title-bar-text">${esc(title)}</div></div>
    <div class="window-body" id="wiz-body" style="padding:10px"></div></div>`;
  document.body.appendChild(ov);
  return { body: ov.querySelector('#wiz-body') as HTMLElement, close: () => ov.remove() };
};
const ERRROW = `<p id="w-err" class="meta" style="color:#8b0000"></p>`;

async function openWizard() {
  base = ($('l-relay') as HTMLSelectElement).value; // vor Login ist base noch der Default
  const mn = newMnemonic();
  const { body, close } = wizOverlay('✨ Neues lightningmail-Postfach anlegen', 540);
  const setErr = (t: string) => { const e = $('w-err'); if (e) e.textContent = t; };
  const wireCancel = () => { const x = document.getElementById('w-x'); if (x) x.onclick = close; };
  const stepsBar = (step: 1 | 2 | 3) => `<div class="wiz-steps">
    <span class="wiz-step ${step === 1 ? 'active' : 'done'}">1. Wunschadresse</span>
    <span class="wiz-step ${step === 2 ? 'active' : step > 2 ? 'done' : ''}">2. 24 Backup-Wörter</span>
    <span class="wiz-step ${step === 3 ? 'active' : ''}">3. Kurzer Check</span>
  </div>`;

  // Schritt 1: Wunschadresse
  const hostLabel = location.hostname || 'lightningmail.app';
  const curVal = (($('l-acct') as HTMLInputElement).value.trim() || '');
  const initName = curVal === 'alice' ? '' : curVal;
  body.innerHTML = `${stepsBar(1)}
    <div style="background:#fff7dc;border:1.5px solid #f4b71a;border-radius:8px;padding:10px 12px;margin-bottom:12px;font-size:0.9em">
      ⚡ <b>10.000 Test-Satoshis Startguthaben</b> inklusive — kein Passwort, keine E-Mail-Bestätigung, sofort startklar.
    </div>
    <label for="w-name">Dein gewünschter Kontoname (2–32 Zeichen, a–z, 0–9, . _ -)</label>
    <div style="display:flex;align-items:center;gap:6px;margin-top:4px">
      <input id="w-name" value="${esc(initName)}" placeholder="z. B. satoshi" autocapitalize="none" autocomplete="off" style="flex:1;font-weight:700;font-size:1.05em">
      <span style="font-weight:700;color:var(--muted);white-space:nowrap">@${esc(hostLabel)}</span>
    </div>
    ${ERRROW}
    <div class="row" style="margin-top:14px">
      <button id="w-next" type="button" style="flex:2;padding:11px 16px">Weiter zu deinen 24 Wörtern →</button>
      <button id="w-x" type="button">Abbrechen</button>
    </div>`;
  wireCancel();
  setTimeout(() => ($('w-name') as HTMLInputElement)?.focus(), 30);
  const goStep2 = () => {
    const nm = ($('w-name') as HTMLInputElement).value.trim().toLowerCase();
    if (!/^[a-z0-9][a-z0-9._-]{1,31}$/.test(nm)) { setErr('Bitte 2–32 kleine Zeichen wählen (a-z, 0-9, Punkt, Unterstrich oder Bindestrich).'); return; }
    ($('l-acct') as HTMLInputElement).value = nm;
    stepWords(nm);
  };
  $('w-next').onclick = goStep2;
  ($('w-name') as HTMLInputElement).onkeydown = (e) => { if (e.key === 'Enter') { e.preventDefault(); goStep2(); } };

  // Schritt 2: die 24 Wörter
  function stepWords(nm: string) {
    const words = mn.split(' ');
    body.innerHTML = `${stepsBar(2)}
      <p class="meta" style="margin:0 0 6px">Für <b>${esc(nm)}@${esc(hostLabel)}</b> wurde direkt auf deinem Gerät dieser Schlüssel aus 24 Wörtern erzeugt:</p>
      <div class="seed-grid">
        ${words.map((w, i) => `<span class="seed-word"><b>${i + 1}.</b> ${esc(w)}</span>`).join('')}
      </div>
      <div style="display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;margin:10px 0">
        <button id="w-copy" type="button" style="flex:0 0 auto">📋 24 Wörter kopieren</button>
        <span class="meta" style="color:var(--danger);flex:1;min-width:200px">⚠ Dein einziges Backup bei Geräteverlust (der Server kennt deinen Schlüssel nicht).</span>
      </div>
      <label style="display:flex;align-items:center;gap:8px;background:var(--surface-alt);padding:10px 12px;border-radius:8px;cursor:pointer;font-weight:600;margin-top:6px">
        <input type="checkbox" id="w-noted" style="width:20px;height:20px;margin:0">
        <span>Ich habe die 24 Wörter sicher notiert oder gespeichert</span>
      </label>
      ${ERRROW}
      <div class="row" style="margin-top:14px">
        <button id="w-next" type="button" disabled style="flex:2;padding:11px 16px">Weiter zum 3-Wort-Check →</button>
        <button id="w-x" type="button">Abbrechen</button>
      </div>`;
    wireCancel();
    $('w-copy').onclick = async () => {
      try { await navigator.clipboard.writeText(mn); $('w-copy').textContent = '✓ Kopiert!'; }
      catch { setErr('Kopieren nicht erlaubt — Wörter bitte manuell notieren.'); }
    };
    ($('w-noted') as HTMLInputElement).onchange = (ev) => { ($('w-next') as HTMLButtonElement).disabled = !(ev.target as HTMLInputElement).checked; };
    $('w-next').onclick = () => stepQuiz(nm);
  }

  // Schritt 3: Wortquiz -> legt nach dem 3. richtigen Wort sofort das Konto an
  function stepQuiz(nm: string) {
    const words = mn.split(' ');
    const qs = quizPositions(mn, 3);
    let done = 0;
    body.innerHTML = `${stepsBar(3)}
      <p class="meta" style="margin:0 0 10px">Tippe zur kurzen Kontrolle die 3 gesuchten Wörter an — danach öffnet sich dein Postfach sofort:</p>
      ${qs.map((p, qi) => `<div class="quiz-card">
        <div style="font-weight:700;font-size:0.9em;margin-bottom:6px">Welches ist Wort <span style="color:var(--navy)">#${p + 1}</span>?</div>
        <div class="row" id="wq-${qi}" style="margin-top:0">${quizOptions(mn, p).map(o => `<button type="button" data-w="${esc(o)}">${esc(o)}</button>`).join('')}</div>
      </div>`).join('')}
      ${ERRROW}
      <div class="row" style="margin-top:12px">
        <button id="w-next" type="button" disabled style="flex:2;padding:11px 16px">🚀 Postfach jetzt eröffnen</button>
        <button id="w-back" type="button">← Wörter nochmal zeigen</button>
        <button id="w-x" type="button">Abbrechen</button>
      </div>`;
    wireCancel();
    $('w-back').onclick = () => stepWords(nm);

    async function createAccountNow() {
      const btn = $('w-next') as HTMLButtonElement;
      btn.disabled = true;
      btn.textContent = '⏳ Postfach wird angelegt…';
      setErr('');
      const pem = sec1PEM(keyFromMnemonic(mn));
      const r = await fetch(base + '/v1/account', { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: nm, pubkey: toHex(pubFromPriv(parseSec1PEM(pem))) }) });
      if (!r.ok) {
        const t = await r.text();
        btn.disabled = false;
        btn.textContent = '🚀 Postfach jetzt eröffnen';
        setErr(/reserv/i.test(t) ? `„${nm}" ist ein reservierter Name.`
          : r.status === 409 ? `Name „${nm}“ ist auf diesem Relay schon vergeben — bitte anderen Namen wählen.` : errText(r.status, t));
        return;
      }
      pemCache = pem; close();
      await login(pem);
    }

    $('w-next').onclick = createAccountNow;

    qs.forEach((p, qi) => {
      document.querySelectorAll(`#wq-${qi} button`).forEach(btn => {
        btn.addEventListener('click', () => {
          const b = btn as HTMLElement;
          if (b.dataset.done) return;
          if (b.getAttribute('data-w') === words[p]) {
            b.dataset.done = '1';
            b.style.background = '#bbf7d0';
            b.style.borderColor = '#16a34a';
            b.style.color = '#064e3b';
            document.querySelectorAll(`#wq-${qi} button`).forEach(x => { (x as HTMLButtonElement).disabled = true; });
            setErr('');
            if (++done === qs.length) {
              ($('w-next') as HTMLButtonElement).disabled = false;
              createAccountNow();
            }
          } else {
            b.style.background = '#fecaca';
            setErr('Nicht ganz — schau kurz auf deine 24 Wörter (oder klicke auf „← Wörter nochmal zeigen").');
          }
        });
      });
    });
  }
}

// Recovery: 24 Wörter → Key-Ableitung im Browser → Login (Server sieht nur den Pubkey)
function openRestore() {
  const { body, close } = wizOverlay('Konto wiederherstellen — 24 Wörter', 480);
  body.innerHTML = `<p class="meta">Backup-Wörter eingeben — der Schlüssel wird hier im Browser abgeleitet. Kontoname muss zum Relay-Konto passen.</p>
    <label>Kontoname</label><input id="r-name" value="${esc(($('l-acct') as HTMLInputElement).value.trim())}">
    <label>24 Wörter (BIP39)</label><textarea id="r-words" rows="4" style="width:100%"></textarea>
    ${ERRROW}
    <div class="row"><button id="r-go">Wiederherstellen</button><button id="w-x">Abbrechen</button></div>`;
  $('w-x').onclick = close;
  $('r-go').onclick = async () => {
    const nm = ($('r-name') as HTMLInputElement).value.trim().toLowerCase();
    const mn = checkMnemonic(($('r-words') as HTMLTextAreaElement).value);
    if (!mn) { $('w-err').textContent = 'Wörter ungültig — 24 BIP39-Wörter erwartet (Checksumme passt nicht).'; return; }
    if (!/^[a-z0-9][a-z0-9._-]{1,31}$/.test(nm)) { $('w-err').textContent = 'Kontoname ungültig.'; return; }
    const pem = sec1PEM(keyFromMnemonic(mn));
    ($('l-acct') as HTMLInputElement).value = nm;
    pemCache = pem; close();
    await login(pem);
    if (!token) $('l-err').textContent = 'Wiederherstellung fehlgeschlagen — passen Name und Wörter zu einem Konto auf diesem Relay?';
  };
}
$('l-signup').onclick = openWizard;
if ($('l-words')) $('l-words').onclick = openRestore;
$('l-file').onchange = async (ev: Event) => {
  const f = (ev.target as any).files[0]; if (!f) return;
  // Kontoname aus Dateinamen: lightningmail-<acct>.lmkey bzw. <acct>.key/.pem
  const m = /^(?:lightningmail-)?([a-z0-9][a-z0-9._-]{1,31})\.(?:lmkey|key|pem)$/i.exec(f.name);
  if (m) ($('l-acct') as HTMLInputElement).value = m[1].toLowerCase();
  const lbl = document.getElementById('l-file-lbl');
  if (lbl) lbl.textContent = '📂 ' + f.name;
  await useKey(await f.text(), f.name);
};
$('l-login').onclick = async () => {
  if (!pemCache) { $('l-err').textContent = 'Erst Schluessel laden (Demo-Knopf oder Datei).'; return; }
  await login(pemCache);
};

// --- Etappe 6: Passkey/WebAuthn-Login + Registrierung (CONCEPT §21) ---
const passkeyAvailable = (): boolean => window.isSecureContext && !!(window as any).PublicKeyCredential;

const b64u = (buf: ArrayBuffer | Uint8Array): string => {
  const b = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  return btoa(String.fromCharCode(...b)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};
const b64uDec = (s: string): Uint8Array => {
  const p = s.replace(/-/g, '+').replace(/_/g, '/');
  return Uint8Array.from(atob(p + '='.repeat((4 - (p.length % 4)) % 4)), (c) => c.charCodeAt(0));
};
// Server-Options (JSON, b64url) -> WebAuthn-API (ArrayBuffer-Felder)
const decodeOpts = (o: any): any => {
  o.challenge = b64uDec(o.challenge).slice().buffer;
  if (o.user?.id) o.user.id = b64uDec(o.user.id).slice().buffer;
  for (const c of o.excludeCredentials || []) c.id = b64uDec(c.id).slice().buffer;
  for (const c of o.allowCredentials || []) c.id = b64uDec(c.id).slice().buffer;
  // PRF-Salt kommt base64url vom Server, die WebAuthn-API will ArrayBuffer
  // (prf.eval.first IST der Salt, kein .salt-Unterfeld)
  const ev = o.extensions?.prf?.eval;
  if (ev) for (const k of ['first', 'second']) {
    if (typeof ev[k] === 'string') ev[k] = b64uDec(ev[k]).slice().buffer;
  }
  return o;
};
// Credential-Response -> JSON fuer go-webauthn (b64url, leere Felder weg)
const cred2json = (c: any): any => {
  const r: any = { clientDataJSON: b64u(c.response.clientDataJSON) };
  for (const f of ['attestationObject', 'authenticatorData', 'signature', 'userHandle'] as const) {
    const v = (c.response as any)[f]; if (v) r[f] = b64u(v);
  }
  if (c.response.getTransports) r.transports = c.response.getTransports();
  return { id: c.id, rawId: b64u(c.rawId), type: c.type, response: r, clientExtensionResults: {} };
};

if (!passkeyAvailable() && !(window as any).AndroidNative?.requestBiometricAuth) {
  const lp = $('l-passkey') as HTMLButtonElement;
  lp.disabled = true; lp.title = 'Passkeys brauchen HTTPS (Secure Context) oder die Android-App';
}

// Hilfsfunktion für den nativen Android-Fingerabdruck-Dialog (BiometricPrompt)
function androidBiometricAuth(): Promise<boolean> {
  return new Promise((resolve) => {
    const an = (window as any).AndroidNative;
    if (!an?.requestBiometricAuth) { resolve(false); return; }
    (window as any).onNativeBioResult = (ok: boolean, err: string) => {
      if (!ok && err) $('l-err').textContent = '✗ Fingerabdruck: ' + err;
      resolve(!!ok);
    };
    an.requestBiometricAuth();
  });
}

async function passkeyLogin() {
  $('l-err').textContent = '';
  // 1) In der Android-APK: Nativer Android-Fingerabdruck entsperrt direkt den Hardware-Keystore-Vault
  const an = (window as any).AndroidNative;
  if (an?.loadVault) {
    try {
      const nv = JSON.parse(an.loadVault() || 'null');
      if (nv && nv.pem && nv.acct && nv.base) {
        if (an.requestBiometricAuth) {
          const ok = await androidBiometricAuth();
          if (!ok) return;
        }
        ($('l-acct') as HTMLInputElement).value = nv.acct;
        ($('l-relay') as HTMLSelectElement).value = nv.base;
        pemCache = nv.pem;
        await login(nv.pem);
        return;
      }
      if (!passkeyAvailable()) {
        $('l-err').textContent = 'Noch kein Schlüssel im Android-Tresor gespeichert — bitte einmal Konto anlegen oder mit 24 Wörtern / Schlüsseldatei anmelden.';
        return;
      }
    } catch { /* Fallback auf WebAuthn */ }
  }
  acct = ($('l-acct') as HTMLInputElement).value.trim(); base = ($('l-relay') as HTMLSelectElement).value;
  if (!acct) { $('l-err').textContent = 'Kontoname eingeben.'; return; }
  try {
    const br = await fetch(base + '/v1/webauthn/login/begin', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ address: acct }) });
    const begin = await br.json().catch(() => ({}));
    if (!br.ok) { $('l-err').textContent = '✗ ' + (begin.error || errText(br.status)); return; }
    const opts = decodeOpts(begin.options.publicKey);
    const cred = await navigator.credentials.get({ publicKey: opts });
    const ext: any = (cred as any).getClientExtensionResults?.() || {};
    const prfSecret = ext.prf?.first ? new Uint8Array(ext.prf.first) : null;
    const fr = await fetch(base + '/v1/webauthn/login/finish', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ address: acct, sid: begin.sid, credential: cred2json(cred) }) });
    const fin = await fr.json().catch(() => ({}));
    if (!fr.ok) { $('l-err').textContent = '✗ ' + (fin.error || errText(fr.status)); return; }
    if (fin.wrap_prf && prfSecret) {
      pemCache = unwrapKeyPRF(fin.wrap_prf, prfSecret);
      await login(pemCache);
    } else if (fin.wrap_pass) {
      pendingWrap = fin.wrap_pass;
      $('l-passrow').style.display = '';
      $('l-err').textContent = 'Passkey bestätigt. Dieser Browser kann den Schlüssel nicht per PRF entsiegeln — bitte Passphrase eingeben und auf „🔓 OK / Anmelden" klicken.';
      setTimeout(() => ($('l-pass') as HTMLInputElement)?.focus(), 30);
    } else {
      $('l-err').textContent = '✗ Dieser Passkey hat keinen Schlüssel-Wrap. Einmal anmelden und oben über „🔑 Passkey" neu hinterlegen.';
    }
  } catch (e: any) {
    $('l-err').textContent = '✗ ' + String(e?.message || e).slice(0, 140);
  }
}
$('l-passkey').onclick = passkeyLogin;

async function passkeyRegister() {
  // 1) In der Android-APK: Nativen Fingerabdruck prüfen & Schlüssel im AndroidKeyStore versiegeln
  const an = (window as any).AndroidNative;
  if (an?.saveVault && an?.requestBiometricAuth) {
    const ok = await androidBiometricAuth();
    if (!ok) return;
    an.saveVault(JSON.stringify({ acct, base, pem: pemCache }));
    alert(`✓ Fingerabdruck-Tresor für ${acct} im Android-Hardware-Keystore aktiviert!\nBeim nächsten Mal reicht ein Tipp auf „🔑 Mit Passkey / Fingerabdruck anmelden".`);
    return;
  }
  try {
    const br = await api('/v1/webauthn/register/begin', { method: 'POST' });
    if (!br.ok) { alert(errText(br.status, await br.text())); return; }
    const begin = await br.json();
    const opts = decodeOpts(begin.options.publicKey);
    const cred = await navigator.credentials.create({ publicKey: opts });
    const ext: any = (cred as any).getClientExtensionResults?.() || {};
    const prfSecret = ext.prf?.first ? new Uint8Array(ext.prf.first) : null;
    const wrap_prf = prfSecret ? wrapKeyPRF(pemCache, prfSecret) : '';
    let wrap_pass = pendingWrap || '';
    if (!wrap_prf && !wrap_pass) {
      const p1 = prompt('Dein Gerät/Browser unterstützt noch keine direkte Passkey-Schlüsselableitung (PRF).\nBitte vergib eine kurze Passphrase (min. 8 Zeichen), mit der dieser Passkey deinen Schlüssel schützt:') || '';
      if (p1.length < 8) { alert('Abgebrochen: Passphrase muss mindestens 8 Zeichen lang sein.'); return; }
      wrap_pass = wrapKey(pemCache, p1);
    }
    const ua = navigator.userAgent;
    const label = `${new Date().toLocaleDateString('de-DE')} ${/android/i.test(ua) ? 'Android' : /iphone|ipad/i.test(ua) ? 'iOS' : /windows/i.test(ua) ? 'Windows' : /mac os/i.test(ua) ? 'macOS' : /linux/i.test(ua) ? 'Linux' : 'Gerät'} ${prfSecret ? '(Direkt-Fingerabdruck ✓)' : '(Passkey + Passphrase)'}`;
    const fr = await api('/v1/webauthn/register/finish', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sid: begin.sid, name: label, credential: cred2json(cred), wrap_prf, wrap_pass }) });
    const fin = await fr.json().catch(() => ({}));
    if (!fr.ok) { alert('✗ ' + (fin.error || errText(fr.status))); return; }
    alert(`✓ Passkey gespeichert: ${label}`);
  } catch (e: any) {
    alert('Passkey-Registrierung fehlgeschlagen: ' + String(e?.message || e).slice(0, 160));
  }
}
$('nav-in').onclick = () => { folder = 'in'; sel = -1; mark(); render(); };
$('nav-spam').onclick = () => { folder = 'spam'; sel = -1; mark(); render(); };
if ($('nav-sent')) $('nav-sent').onclick = () => { folder = 'out'; sel = -1; mark(); fetchReceipts().then(() => render()); };
if ($('nav-dra')) $('nav-dra').onclick = () => { folder = 'dra'; sel = -1; mark(); render(); };
$('nav-new').onclick = () => { folder = 'new'; draftId = ''; mark(); render(); };
$('nav-ab').onclick = () => { folder = 'ab'; sel = -1; abEdit = ''; mark(); render(); };
if ($('nav-ums')) $('nav-ums').onclick = () => { folder = 'ums'; sel = -1; mark(); render(); };
$('nav-out').onclick = () => {
  if (priv) priv.fill(0);
  priv = null; pemCache = ''; token = '';
  sessionStorage.removeItem(AUTO_KEY);
  localStorage.removeItem(AUTO_KEY);
  localStorage.setItem(NOAUTO_KEY, '1');
  location.reload();
};
if ($('l-passbtn')) $('l-passbtn').onclick = tryUnwrap;
function mark() {
  $('nav-in').classList.toggle('on', folder === 'in');
  $('nav-spam').classList.toggle('on', folder === 'spam');
  if ($('nav-sent')) $('nav-sent').classList.toggle('on', folder === 'out');
  if ($('nav-dra')) $('nav-dra').classList.toggle('on', folder === 'dra');
  $('nav-new').classList.toggle('on', folder === 'new');
  $('nav-ab').classList.toggle('on', folder === 'ab');
  if ($('nav-ums')) $('nav-ums').classList.toggle('on', folder === 'ums');
}

// --- Etappe G2 (§25): Umsätze — Monatsliste aus /v1/statement + CSV-Knopf.
// Kein neues Subsystem: liest nur das Statement, EUR-Spalte kommt vom Server. ---
const KINDDE: Record<string, string> = {
  postage_out: 'Porto versendet', postage_in: 'Porto erhalten', topup: 'Einzahlung',
  withdraw: 'Auszahlung', fee: 'Gebühr/Erstattung',
};
const fmtSat = (n: number) => Math.round(n).toLocaleString('de');
const fmtEur = (n: number) => n.toLocaleString('de', { style: 'currency', currency: 'EUR' });
const monLabel = (k: string) => new Date(+k.slice(0, 4), +k.slice(5) - 1, 1).toLocaleDateString('de', { month: 'long', year: 'numeric' });

async function dlCsv(path: string, name: string) {
  const r = await api(path);
  if (!r.ok) { alert(errText(r.status)); return; }
  const url = URL.createObjectURL(await r.blob());
  const a = document.createElement('a'); a.href = url; a.download = name; a.click();
}

async function renderUms() {
  $('list').innerHTML = '<div class="meta" style="padding:12px">Lade Umsätze…</div>';
  $('detail').innerHTML = '<p class="meta">Monat wählen — Details und CSV-Export erscheinen hier.</p>';
  let j: any;
  try {
    const r = await api('/v1/statement?fmt=json');
    if (!r.ok) throw new Error(errText(r.status));
    j = await r.json();
  } catch (e: any) {
    $('list').innerHTML = `<div class="meta" style="padding:12px">✗ ${esc(String(e?.message || e).slice(0, 140))}</div>`;
    return;
  }
  const rows = (j.zeilen || []) as any[];
  const mon: Record<string, any[]> = {};
  for (const x of rows) {
    const d = new Date(x.ts * 1000);
    const k = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
    (mon[k] ??= []).push(x);
  }
  const keys = Object.keys(mon).sort().reverse();
  const eurSum = (l: any[]) => l.filter(x => x.eur !== undefined).reduce((s, x) => s + Math.abs(x.eur), 0);
  const eurTxt = (l: any[]) => l.some(x => x.eur === undefined)
    ? (eurSum(l) > 0 ? '≈' + fmtEur(eurSum(l)) + ' (Teile ungeratet)' : '—')
    : fmtEur(eurSum(l));
  $('list').innerHTML = `<div class="abbar"><button id="ums-csv">⬇ CSV komplett</button>
      <button id="ums-topup" title="Lightning-Guthaben aufladen">⚡ Aufladen</button>
      <button id="ums-withdraw" title="Guthaben per Bolt11-Invoice auszahlen">📤 Abheben</button>
      <span class="meta" style="align-self:center" title="Hash-Kette: jeder Export setzt den vorigen fort">Kette: ${esc(String(j.kopf || '').slice(0, 10))}…</span></div>` +
    (keys.map(k => {
      const rs = mon[k];
      const ein = rs.filter(x => x.msat > 0), aus = rs.filter(x => x.msat < 0);
      const sat = (l: any[]) => l.reduce((s, x) => s + Math.abs(x.msat), 0) / 1000;
      return `<div class="row" data-mon="${k}"><div class="subj">${esc(monLabel(k))}</div>
        <div class="meta">Ein ${fmtSat(sat(ein))} sats (${eurTxt(ein)}) · Aus ${fmtSat(sat(aus))} sats (${eurTxt(aus)}) · ${rs.length} Zeilen</div></div>`;
    }).join('') || '<div class="meta" style="padding:12px">— keine Buchungen —</div>');
  $('ums-csv').onclick = () => dlCsv('/v1/statement?fmt=csv', `umsaetze-${acct}.csv`);

  // ⚡ Aufladen: Bolt11-Invoice vom Relay holen (Gutschrift erfolgt nach Settlement)
  $('ums-topup').onclick = async () => {
    const sats = prompt('Betrag in sats (1–10 000 000):', '1000');
    if (!sats) return;
    const r = await api('/v1/topup', { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ amount_sats: +sats }) });
    const j = await r.json().catch(() => ({})) as any;
    if (!r.ok) { alert(errText(r.status, j.error || '')); return; }
    $('detail').innerHTML = `<div class="window" style="max-width:72ch"><div class="title-bar"><div class="title-bar-text">⚡ Aufladen — ${fmtSat(j.amount_sats)} sats</div></div>
      <div class="window-body">
        <p class="meta">Mit beliebiger Lightning-Wallet bezahlen — Guthaben wird nach Settlement automatisch gutgeschrieben.</p>
        <textarea id="tu-pr" readonly rows="5" style="width:100%">${esc(String(j.payment_request || ''))}</textarea>
        <p><button id="tu-copy">Kopieren</button> <span id="tu-msg" class="meta"></span></p>
      </div></div>`;
    $('tu-copy').onclick = async () => {
      try { await navigator.clipboard.writeText(j.payment_request); $('tu-msg').textContent = '✓ kopiert'; }
      catch { ($('tu-pr') as HTMLTextAreaElement).select(); $('tu-msg').textContent = 'Strg+C drücken'; }
    };
  };

  // 📤 Abheben: Bolt11-Invoice einfügen, Relay bezahlt vom Guthaben
  $('ums-withdraw').onclick = () => {
    $('detail').innerHTML = `<div class="window" style="max-width:72ch"><div class="title-bar"><div class="title-bar-text">📤 Abheben</div></div>
      <div class="window-body">
        <p class="meta">Bolt11-Invoice einfügen — der Betrag wird vom Guthaben abgebucht und vom Relay-Node bezahlt.</p>
        <textarea id="wd-pr" rows="5" placeholder="lnbc…" style="width:100%"></textarea>
        <p><button id="wd-go">Auszahlen</button> <span id="wd-msg" class="meta"></span></p>
      </div></div>`;
    $('wd-go').onclick = async () => {
      const pr = ($('wd-pr') as HTMLTextAreaElement).value.trim();
      if (!pr) { $('wd-msg').textContent = '✗ keine Invoice eingefügt'; return; }
      $('wd-go').setAttribute('disabled', '1');
      $('wd-msg').textContent = 'zahle…';
      const r = await api('/v1/withdraw', { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ payment_request: pr }) });
      const j = await r.json().catch(() => ({})) as any;
      await refreshBalance();
      if (!r.ok) { $('wd-msg').textContent = '✗ ' + errText(r.status, j.error || ''); $('wd-go').removeAttribute('disabled'); return; }
      await renderUms(); // Umsätze neu laden …
      $('detail').innerHTML = `<div class="window" style="max-width:72ch"><div class="title-bar"><div class="title-bar-text">📤 Ausgezahlt</div></div>
        <div class="window-body"><p>✓ ${fmtSat(j.amount_sats)} sats bezahlt.</p>
        <p class="meta" style="word-break:break-all">Preimage: ${esc(String(j.preimage || ''))}<br>Payment-Hash: ${esc(String(j.payment_hash || ''))}</p></div></div>`;
    };
  };
  document.querySelectorAll('#list .row[data-mon]').forEach(el => el.addEventListener('click', () => {
    const k = el.getAttribute('data-mon')!;
    const rs = mon[k].slice().reverse();
    $('detail').innerHTML = `<div class="window" style="max-width:72ch"><div class="title-bar"><div class="title-bar-text">Umsätze ${esc(monLabel(k))}</div></div>
      <div class="window-body"><table style="width:100%;font-size:12px;border-collapse:collapse">${rs.map(x => `<tr style="border-bottom:1px solid #dfdfdf">
        <td style="padding:3px 4px;white-space:nowrap">${esc(String(x.zeit || '').replace('T', ' ').slice(0, 16))} UTC</td>
        <td>${esc(KINDDE[x.art] || x.art)}</td>
        <td style="text-align:right;white-space:nowrap">${x.msat > 0 ? '+' : '−'}${fmtSat(Math.abs(x.msat) / 1000)} sats</td>
        <td style="text-align:right;white-space:nowrap">${x.eur !== undefined ? (x.msat > 0 ? '+' : '−') + fmtEur(Math.abs(x.eur)) : '—'}</td>
        <td class="meta" style="text-align:right;max-width:14ch;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(String(x.referenz || ''))}">${esc(String(x.referenz || '').slice(0, 12))}</td></tr>`).join('')}</table>
      <p style="margin:10px 0 0"><button id="ums-mcsv">⬇ CSV ${esc(monLabel(k))}</button></p>
      <p class="meta">Zeilen sind hash-verkettet (Genesis → Kopf). LND-Onchain-/Routinggebühren stehen hier nicht — LND-Reports ergänzen.</p></div></div>`;
    const von = Math.floor(new Date(+k.slice(0, 4), +k.slice(5) - 1, 1).getTime() / 1000);
    const bis = Math.floor(new Date(+k.slice(0, 4), +k.slice(5), 1).getTime() / 1000);
    $('ums-mcsv').onclick = () => dlCsv(`/v1/statement?fmt=csv&from=${von}&to=${bis - 1}`, `umsaetze-${acct}-${k}.csv`);
  }));
}

// --- IdP (§21): OIDC-Login-Flow — Consent + BIP340-Signatur der Server-Challenge
// mit dem Mailbox-Key (Föderations-Beweis im bmail-Claim; Relay sieht den
// privaten Key nie, Signatur entsteht hier im Browser). ---
function oidcScreen(inner: string) {
  const ov = document.createElement('div');
  ov.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.35);display:flex;align-items:center;justify-content:center;z-index:70;padding:10px';
  ov.innerHTML = `<div class="window" style="width:430px;max-width:94vw"><div class="title-bar"><div class="title-bar-text">🔐 Anmelden mit lightningmail</div></div>
    <div class="window-body" id="oidc-body" style="padding:12px">${inner}</div></div>`;
  document.body.appendChild(ov);
}

async function oidcFlow() {
  if (!oidcRelay || !oidcSid || !token || !priv) return;
  const hdrs = (): Record<string, string> => {
    const h: Record<string, string> = { 'Content-Type': 'application/json' };
    h[('Auth' + 'orization') as string] = 'Bearer ' + token;
    return h;
  };
  try {
    const lr = await fetch(oidcRelay + '/oidc/auth/login', { method: 'POST', headers: hdrs(), body: JSON.stringify({ sid: oidcSid }) });
    const lj = await lr.json() as any;
    if (!lr.ok) {
      oidcScreen(`<p>✗ ${esc(lj.error || 'Fehler ' + lr.status)}</p>${lr.status === 401 ? '<p class="meta">Diese Anmeldung braucht ein Konto auf dem Relay des Dienstes. Bitte abmelden und beim richtigen Relay einloggen.</p>' : ''}`);
      return;
    }
    const challenge = fromB64(lj.challenge_b64);
    const payBadge = lj.pay_sats > 0
      ? `<div style="background:#fff7dc;border:2px solid #f4b71a;border-radius:8px;padding:10px 12px;margin:10px 0;font-size:14px;font-weight:700;color:#122338">⚡ Mikro-Paywall: ${lj.pay_sats} sats für ${esc(lj.pay_item || lj.client_name)}</div>`
      : '';
    oidcScreen(`<p style="font-size:14px;margin-top:0"><b>${esc(lj.client_name)}</b> möchte dich anmelden als<br><b>${esc(lj.address)}</b></p>
      <p class="meta">Der Dienst erhält deine Adresse, den Anmeldezeitpunkt und einen mit deinem Mailbox-Key signierten Nachweis (BIP340). Kein Kontozugriff, kein Mitlesen, keine Mails.</p>
      ${payBadge}
      <div class="row"><button id="oidc-ok">${lj.pay_sats > 0 ? '⚡ ' + lj.pay_sats + ' sats zahlen & freischalten' : 'Erlauben'}</button><button id="oidc-no">Ablehnen</button></div>
      <p id="oidc-err" class="meta"></p>`);
    const finish = (redirect: string) => {
      // OIDC-Parameter aus der URL putzen, damit ein Zurück nicht erneut triggert
      history.replaceState(null, '', location.pathname);
      location.href = redirect;
    };
    $('oidc-ok').onclick = async () => {
      $('oidc-err').textContent = 'signiere mit deinem Mailbox-Key…';
      try {
        const sig = toHex(schnorr.sign(new Uint8Array(sha256(challenge)), priv!));
        const sr = await fetch(oidcRelay + '/oidc/auth/sign', { method: 'POST', headers: hdrs(), body: JSON.stringify({ sid: oidcSid, sig }) });
        const sj = await sr.json() as any;
        if (!sr.ok || !sj.redirect) { $('oidc-err').textContent = '✗ ' + esc(sj.error || String(sr.status)); return; }
        finish(sj.redirect);
      } catch (e: any) { $('oidc-err').textContent = '✗ ' + String(e?.message || e).slice(0, 120); }
    };
    $('oidc-no').onclick = async () => {
      try {
        const dr = await fetch(oidcRelay + '/oidc/auth/sign', { method: 'POST', headers: hdrs(), body: JSON.stringify({ sid: oidcSid, deny: true }) });
        const dj = await dr.json() as any;
        if (dj.redirect) { finish(dj.redirect); return; }
      } catch { /* kein Redirect möglich — einfach schließen */ }
      oidcScreen('<p>Abgebrochen. Du kannst dieses Fenster schließen.</p>');
    };
  } catch (e: any) {
    oidcScreen(`<p>✗ ${esc(String(e?.message || e).slice(0, 160))}</p>`);
  }
}

// Start: gespeicherten Schluessel wiederladen. Ohne explizites Abmelden (lm_noauto)
// loggt die App sofort ein; sonst zeigt der Login die Ein-Klick-Zeile "Weiter als …".
let autoSaved = loadAuto();
let fromNativeVault = false;
// Android-Tresor: wenn localStorage leer ist, Schluessel aus dem Hardware-Keystore holen
if (!autoSaved && (window as any).AndroidNative?.loadVault) {
  try {
    const nv = JSON.parse((window as any).AndroidNative.loadVault() || 'null');
    if (nv && typeof nv.pem === 'string' && nv.pem && nv.acct && nv.base) { autoSaved = nv; fromNativeVault = true; }
  } catch { /* Tresor leer oder kaputt — normaler Login */ }
}
if (autoSaved) {
  ($('l-acct') as HTMLInputElement).value = autoSaved.acct;
  ($('l-relay') as HTMLSelectElement).value = autoSaved.base;
  const q = $('l-quick'); q.style.display = '';
  ($('l-quickgo') as HTMLButtonElement).textContent = `► Weiter als ${autoSaved.acct}${fromNativeVault ? ' (Android-Tresor)' : ''}`;
  $('l-quickgo').onclick = () => {
    pemCache = autoSaved.pem;
    login(autoSaved.pem).catch((e: any) => { $('l-err').textContent = '✗ ' + String(e?.message || e).slice(0, 120); });
  };
  $('l-forget').onclick = () => {
    sessionStorage.removeItem(AUTO_KEY);
    localStorage.removeItem(AUTO_KEY);
    try { (window as any).AndroidNative?.clearVault?.(); } catch {}
    q.style.display = 'none';
    $('l-err').textContent = 'Gespeicherter Schluessel geloescht — Datei, Passkey oder 24 Wörter nötig.';
  };
  if (!localStorage.getItem(NOAUTO_KEY)) {
    pemCache = autoSaved.pem;
    login(autoSaved.pem).catch((e: any) => { $('l-err').textContent = 'Auto-Login fehlgeschlagen: ' + String(e?.message || e).slice(0, 120); });
  }
}
