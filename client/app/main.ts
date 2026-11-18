// main.ts — DOM-Leim für die lightningmail v0.1 PWA (M2c). Logik lebt in src/crypto + src/send.
import { parseSec1PEM, pubFromPriv, authSign, toHex, fromB64, decodeEnvelope, decryptPayload, TAG, blobCount, blobRef, sec1PEM } from '../src/crypto';
import { newMnemonic, checkMnemonic, keyFromMnemonic, quizPositions, quizOptions } from '../src/bip39';
import { composeAndSend } from '../src/send';
import { StateSync, type Contact } from '../src/state';
import { wrapKey, unwrapKey, isWrapped, wrapKeyPRF, unwrapKeyPRF } from '../src/keywrap';
// Etappe B: oeffentliches Directory — signierte Profilkarten, Kauf pro card_hash
import { lookupAddress, buyCard, fetchCard, cardFields, cardFromB64, verifyCard, putProfile, delProfile, type Card, type CardPayload, type LookupEntry } from '../src/directory';
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
let sel = -1, folder: 'in' | 'spam' | 'out' | 'dra' | 'new' | 'ab' = 'in';
let pemCache = '';
// Auto-Login: erfolgreicher Login merkt sich Schluessel+Konto+Relay im Geraetespeicher
// (unverschluesselt, nur App-Sandbox; APK hat allowBackup=false). "Vergessen" loescht es,
// Abmelden setzt lm_noauto, damit Reload/401-Handler nicht sofort wieder einloggen.
const AUTO_KEY = 'lm_autologin', NOAUTO_KEY = 'lm_noauto';
const loadAuto = (): { acct: string; base: string; pem: string } | null => {
  try {
    const v = JSON.parse(localStorage.getItem(AUTO_KEY) || 'null');
    return v && typeof v.pem === 'string' && v.pem && v.acct && v.base ? v : null;
  } catch { return null; }
};
let sync: StateSync | null = null;
let draftId = '';
let abSel = '', abEdit = '', abQ = ''; // Adressbuch (Etappe A)
const spamKey = () => `lm_spam_${base.slice(1)}_${acct}`;
const spamSet = (): Set<string> => sync ? new Set(Object.keys(sync.doc.spam)) : new Set(JSON.parse(localStorage.getItem(spamKey()) || '[]'));
const spamAdd = (k: string) => { if (sync) sync.toggleSpam(k, true); else { const x = [...spamSet()]; x.push(k); localStorage.setItem(spamKey(), JSON.stringify(x)); } };
const spamDel = (k: string) => { if (sync) sync.toggleSpam(k, false); else { const x = new Set(spamSet()); x.delete(k); localStorage.setItem(spamKey(), JSON.stringify([...x])); } };

// Gesendet-Ordner (lokal, synchronisiert wird ab M2.5)
type MsgRow = { seq: number; msgId: string; subject: string; body: string; sender: string; pub: string; ts: number; atts: { sha256: string; name: string }[] };
type SentRow = { ts: number; to: string; subject: string; msg_id: string; bytes: number };
const sentKey = () => `lm_out_${base.slice(1)}_${acct}`;
const sentList = (): SentRow[] => JSON.parse(localStorage.getItem(sentKey()) || '[]');
const sentPush = (r: SentRow) => { const l = sentList(); l.unshift(r); localStorage.setItem(sentKey(), JSON.stringify(l.slice(0, 200))); };

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
  const r = await fetch(base + path, { ...init, headers: { ...(init?.headers || {}), Authorization: `Bearer ${token}` } });
  if (r.status === 401 && token) { token = ''; $('nav-out').click(); }
  return r;
}

async function login(pem: string) {
  acct = $('l-acct').value.trim(); base = $('l-relay').value;
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
  localStorage.setItem(AUTO_KEY, JSON.stringify({ acct, base, pem }));
  localStorage.removeItem(NOAUTO_KEY);
  $('login').classList.add('hidden'); $('app').classList.remove('hidden');
  const bp = $('btn-passkey'); if (bp && passkeyAvailable()) { bp.style.display = ''; bp.onclick = passkeyRegister; }
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
  try { await sync.pull(); } catch { /* ohne State-Slot laeuft die UI aus dem Cache */ }
  await refresh();
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
      const atts = (p.attachments || []).map((a: any) => ({ sha256: a.sha256, name: a.name }));
      const refs = env[TAG.BlobRefs] ? Array.from({ length: blobCount(env[TAG.BlobRefs]) }, (_, i) => toHex(blobRef(env[TAG.BlobRefs]!, i))) : [];
      msgs.push({ seq: m.seq, msgId: toHex(env[TAG.MsgID]), subject: p.subject, body: p.body, sender: toHex(env[TAG.SenderPubkey]).slice(0, 12), pub: toHex(env[TAG.SenderPubkey]), ts: m.received_at, atts: atts.length ? atts : refs.map((r, i) => ({ sha256: r, name: `anhang-${i + 1}` })) });
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
  if (folder === 'out') { renderSent(); return; }
  if (folder == 'dra') { renderDrafts(); return; }
  const list = visible().slice().reverse();
  $('list').innerHTML = list.map(m => `<div class="row ${m.seq === sel ? 'sel' : ''}" data-seq="${m.seq}">
    <div class="subj" ${sync && sync.doc.read[m.msgId] ? 'style="font-weight:400;color:#8a8271"' : ''}>${esc(m.subject)}</div>
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
      <p class="meta">${receipts[s.msg_id]
        ? `✓✓ vom Empfänger abgerufen: ${new Date(receipts[s.msg_id] * 1000).toLocaleString('de')}`
        : '✓ zugestellt (am Empfänger-Relay) — warte auf Abruf durch den Empfänger'}</p>
      <p class="meta">Der Text liegt nur beim Empfänger (und ab M2.5 im Sync). Gesendet-Ordner ist lokal.</p></div>`;
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

function renderDetail() {
  const m = msgs.find(x => x.seq === sel)!;
  const sp = spamSet().has(m.sender);
  const cn = contactFor(m.pub);
  $('detail').innerHTML = `<div class="card">
    <div class="subj" style="font-size:17px">${esc(m.subject)}</div>
    <div class="meta">Von ${cn ? esc(abLabel(cn)) : esc(m.sender) + '…'} · ${new Date(m.ts * 1000).toLocaleString('de')}</div>
    <pre style="white-space:pre-wrap;font:inherit;margin:14px 0">${esc(m.body)}</pre>
    ${m.atts.map(a => `<span class="attach" data-sha="${a.sha256}" data-name="${esc(a.name)}">↓ ${esc(a.name)}</span>`).join('')}
    <div class="classify">Absender:
      <button id="cl-spam" class="${sp ? 'on' : ''}">${sp ? 'unerwünscht' : 'als unerwünscht markieren'}</button>
      ${sp ? '<button id="cl-un">zurück nach Posteingang</button>' : ''}
      <button id="cl-del">löschen</button>
      ${cn ? '' : '<button id="cl-ab">als Kontakt speichern</button>'}
    </div></div>`;
  document.querySelectorAll('.attach').forEach(el => el.addEventListener('click', async () => {
    const r = await api(`/v1/blob/${el.getAttribute('data-sha')}`);
    if (!r.ok) { alert(errText(r.status)); return; }
    const url = URL.createObjectURL(await r.blob());
    const a = document.createElement('a'); a.href = url; a.download = el.getAttribute('data-name')!; a.click();
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
      <button id="ab-card" title="Öffentliche Profilkarte (Directory)">🌐 Meine Karte</button>
      <input id="ab-q" placeholder="Suchen" value="${esc(abQ)}" style="flex:1;min-width:70px"></div>
    <div id="abrows"></div>`;
  const all = sync ? sync.liveContacts() : [];
  const drawRows = () => {
    const q = abQ.trim().toLowerCase();
    const list = all
      .filter(c => !q || [c.name, c.given, c.org, c.title, c.lnaddr, c.email, c.cell, c.phone].join(" ").toLowerCase().includes(q))
      .sort((x, y) => abLabel(x).localeCompare(abLabel(y), "de"));
    // Etappe B: Directory-Fernsuche (nur exakter Treffer, kein Scan)
    const dirRow = q ? `<div class="row" id="ab-dirrow">
      <div class="subj">🌐 Directory: „${esc(abQ.trim())}" suchen</div>
      <div class="meta">exakter Treffer auf diesem Relay — Schlüssel gratis, Karte bezahlt</div></div>` : '';
    $('abrows').innerHTML = dirRow + (list.map(c => `<div class="row ${c.id === abSel ? 'sel' : ''}" data-cid="${c.id}">
      <div class="subj">${esc(abLabel(c))}</div>
      <div class="meta">${esc([c.org, c.lnaddr || c.email].filter(Boolean).join(" · "))}</div></div>`).join('') ||
      '<div class="meta" style="padding:12px">— keine Kontakte —</div>');
    if ($('ab-dirrow')) $('ab-dirrow').onclick = () => dirSearch(abQ);
    document.querySelectorAll('#abrows .row[data-cid]').forEach(el => {
      el.addEventListener('click', () => { abSel = el.getAttribute('data-cid')!; abEdit = ''; renderAB(); });
      el.addEventListener('dblclick', () => { abSel = el.getAttribute('data-cid')!; abEdit = abSel; abSeed = {}; renderAB(); });
    });
  };
  drawRows();
  ($('ab-q') as HTMLInputElement).addEventListener('input', (ev) => { abQ = (ev.target as HTMLInputElement).value; drawRows(); });
  $('ab-new').onclick = () => { abEdit = 'new'; abSel = ''; abSeed = {}; renderAB(); };
  $('ab-card').onclick = () => { abEdit = 'mycard'; abSel = ''; renderAB(); };
  $('ab-del').onclick = () => {
    const c = all.find(x => x.id === abSel); if (!c || !sync) return;
    if (!confirm(`Kontakt „${abLabel(c)}“ aus dem Adressbuch entfernen?`)) return;
    sync.delContact(c.id); abSel = ''; abEdit = ''; renderAB();
  };
  $('ab-exp').onclick = () => exportVcf(all);

  if (abEdit === 'mycard') { renderMyCard(); return; }
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

// --- Etappe B: eigene Profilkarte (signierte Projektion + gdpr1-Consent) ---
const ctLabel = (meur: number) => (meur / 10).toLocaleString('de', { maximumFractionDigits: 2 }) + ' ct';

async function renderMyCard() {
  $('detail').innerHTML = '<p class="meta">Lade eigene Karte…</p>';
  let fields: Card = {}; let priceCt = 2.5; let published = false;
  try {
    const p = await fetchCard(base, token, acct); // eigene Karte ist frei
    fields = cardFields(p); priceCt = (p.price_meur ?? 25) / 10; published = true;
  } catch { /* 404 = noch keine Karte veroeffentlicht */ }
  $('detail').innerHTML = `<div class="window" style="max-width:64ch"><div class="title-bar"><div class="title-bar-text">🌐 Meine öffentliche Karte</div></div>
    <div class="window-body">
      <p class="meta" style="margin-top:0">Nur markierte Felder werden veröffentlicht — die Karte ist mit deinem Mailbox-Key signiert und weltweit lesbar, wer den Kartenpreis zahlt.</p>
      <form id="mc-form" class="abform">${ABFIELDS.map(([k, l]) =>
        `<label><input type="checkbox" id="mck-${k}" ${(fields as any)[k] !== undefined ? 'checked' : ''} style="width:auto"> ${l}</label>` +
        `<input id="mcv-${k}" value="${esc(String((fields as any)[k] ?? ''))}" placeholder="${l}">`).join('')}
        <label>Kartenpreis (ct)</label><input id="mc-price" type="number" min="0" max="10000" step="0.1" value="${priceCt}">
        <div></div><div><label style="font-weight:400"><input type="checkbox" id="mc-consent" style="width:auto">
          Ich willige ein, dass die markierten Felder als signierte Karte im öffentlichen Directory gespeichert und gegen Gebühr ausgegeben werden (DSGVO; Löschung jederzeit, Kopie = gdpr1).</label></div>
        <div></div><div><button type="submit">${published ? 'Aktualisieren' : 'Veröffentlichen'}</button>
          ${published ? '<button type="button" id="mc-del">Löschen…</button>' : ''}
          <button type="button" id="mc-cancel">Abbrechen</button>
          <span id="mc-status" class="meta"></span></div>
      </form></div></div>`;
  $('mc-cancel').onclick = () => { abEdit = ''; renderAB(); };
  if ($('mc-del')) $('mc-del').onclick = async () => {
    if (!confirm('Öffentliche Karte löschen? Der Server löscht Karte und Einwilligungs-Historie komplett (bereits verkaufte Kopien bei Dritten bleiben ausgenommen — Achtungs-Note).')) return;
    try { await delProfile(base, token); $('mc-status').textContent = '✓ gelöscht'; published = false; setTimeout(() => renderMyCard(), 600); }
    catch (e: any) { $('mc-status').textContent = '✗ ' + e.message; }
  };
  ($('mc-form') as HTMLFormElement).onsubmit = async (ev) => {
    ev.preventDefault();
    if (!($('mc-consent') as HTMLInputElement).checked) { $('mc-status').textContent = '✗ Ohne DSGVO-Einwilligung keine Veröffentlichung.'; return; }
    if (!priv) { $('mc-status').textContent = '✗ kein Schlüssel geladen'; return; }
    const f: Card = {};
    for (const [k] of ABFIELDS) {
      if (!($(('mck-' + k)) as HTMLInputElement).checked) continue;
      const v = ($('mcv-' + k) as HTMLInputElement).value.trim();
      if (v) (f as any)[k] = v;
    }
    const ct = parseFloat(($('mc-price') as HTMLInputElement).value);
    if (!(ct >= 0) || ct > 10000) { $('mc-status').textContent = '✗ Preis: 0–10000 ct'; return; }
    try {
      const r = await putProfile(base, token, priv, f, Math.round(ct * 10));
      $('mc-status').textContent = '✓ veröffentlicht — Karten-Hash ' + r.card_hash.slice(0, 12) + '…';
    } catch (e: any) { $('mc-status').textContent = '✗ ' + String(e.message || e).slice(0, 160); }
  };
}

// --- Etappe B: Directory-Fernsuche (exakter Treffer; Key gratis, Karte bezahlt) ---
async function dirSearch(raw: string) {
  const q = raw.trim().toLowerCase();
  if (!q) return;
  $('detail').innerHTML = `<p class="meta">Suche „${esc(q)}" im Directory…</p>`;
  let e: LookupEntry;
  try { e = await lookupAddress(base, q); }
  catch (err: any) {
    const m0 = String(err?.message || err);
    const st = /: (\d{3}) /.exec(m0);
    $('detail').innerHTML = `<div class="window" style="max-width:56ch"><div class="title-bar"><div class="title-bar-text">Directory</div></div>
      <div class="window-body"><p>${st ? esc(errText(+st[1], m0)) : '✗ ' + esc(m0.slice(0, 160))}</p>
      ${st && +st[1] === 404 ? '<p class="meta">Nur exakte Treffer auf diesem Relay — kein Scan, keine Liste. Andere Relays: Adressdomäne zeigt via _bmail._tcp-DNS dorthin (Föderation folgt).</p>' : ''}</div></div>`;
    return;
  }
  const fp = e.pubkey.slice(0, 8) + '…' + e.pubkey.slice(-6);
  const priceLine = e.has_card
    ? `Karte: ${ctLabel(e.total_meur ?? 50)}${e.total_msat ? ` (≈ ${Math.ceil(e.total_msat / 1000)} sats)` : ' — Kauf erst mit Tageskurs möglich'}${e.purchased ? ' · bezahlt ✓' : ''}`
    : 'Keine öffentliche Karte — nur Schlüssel sichtbar.';
  $('detail').innerHTML = `<div class="window" style="max-width:56ch"><div class="title-bar"><div class="title-bar-text">Directory — ${esc(e.address)}</div></div>
    <div class="window-body">
      <p class="meta" style="margin-top:0">Mailbox-Key ${esc(fp)} · Porto an ihn: ${e.foreign_sats} sats<br>${esc(priceLine)}</p>
      <p>${e.has_card
        ? (e.purchased ? '<button id="dir-show">Karte anzeigen</button>' : `<button id="dir-buy">Karte kaufen — ${ctLabel(e.total_meur ?? 50)}</button>`)
        : ''}
      <button id="dir-mail">Nachricht senden</button></p>
      <p id="dir-msg" class="meta"></p>
    </div></div>`;
  const addrFull = e.address.includes('@') ? e.address : `${e.address}@${location.hostname}`;
  $('dir-mail').onclick = () => {
    folder = 'new'; draftId = ''; mark(); render();
    setTimeout(() => { ($('c-to') as HTMLInputElement).value = addrFull; }, 0);
  };
  if ($('dir-buy')) $('dir-buy').onclick = async () => {
    $('dir-msg').textContent = 'Kaufe…';
    try { const p = await buyCard(base, token, e.address); renderBoughtCard(p); refreshBalance(); }
    catch (err: any) { $('dir-msg').textContent = '✗ ' + String(err?.message || err).slice(0, 160); }
  };
  if ($('dir-show')) $('dir-show').onclick = async () => {
    try { const p = await fetchCard(base, token, e.address); renderBoughtCard(p); }
    catch (err: any) { $('dir-msg').textContent = '✗ ' + String(err?.message || err).slice(0, 160); }
  };
}

function renderBoughtCard(p: CardPayload) {
  const bytes = cardFromB64(p.card_b64);
  const sigOk = verifyCard(p.pubkey, bytes, p.sig);
  const f = cardFields(p);
  const addrFull = p.address.includes('@') ? p.address : `${p.address}@${location.hostname}`;
  $('detail').innerHTML = `<div class="window" style="max-width:64ch"><div class="title-bar"><div class="title-bar-text">Karte — ${esc(p.address)}</div></div>
    <div class="window-body">
      <p class="meta" style="margin-top:0">${sigOk ? '✓ Signatur gültig (Mailbox-Key)' : '⚠ SIGNATUR UNGÜLTIG — Karte nicht übernehmbar!'}
      · Consent ${esc(p.consent?.v || '?')} vom ${p.consent?.ts ? new Date(p.consent.ts * 1000).toLocaleDateString('de') : '?'}
      ${p.paid ? ` · bezahlt: ${ctLabel(p.paid.total_meur ?? 0)}${p.paid.fresh === false ? ' (Dedup — schon gekauft, nichts gebucht)' : ''}` : ''}</p>
      <div class="abform">${ABFIELDS.filter(([k]) => String((f as any)[k] || '')).map(([k, l]) =>
        `<label>${l}</label><div style="white-space:pre-wrap;font-size:12px">${esc(String((f as any)[k]))}</div>`).join('')}</div>
      <p style="margin:10px 0 0">${sigOk ? '<button id="bc-ab">Ins Adressbuch übernehmen</button>' : ''}
      <button id="bc-mail">Nachricht senden</button></p>
      <p id="bc-msg" class="meta"></p>
    </div></div>`;
  if ($('bc-mail')) $('bc-mail').onclick = () => {
    folder = 'new'; draftId = ''; mark(); render();
    setTimeout(() => { ($('c-to') as HTMLInputElement).value = f.lnaddr || addrFull; }, 0);
  };
  if ($('bc-ab')) $('bc-ab').onclick = () => {
    if (!sync) { $('bc-msg').textContent = '✗ ohne Sync kein Adressbuch'; return; }
    const id = newId();
    sync.saveContact({ id, ...f, pubkey: p.pubkey, lnaddr: f.lnaddr || addrFull } as { id: string } & Partial<Contact>);
    $('bc-msg').textContent = '✓ ins Adressbuch übernommen';
    abSel = id; abEdit = '';
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
    <div class="window-body" style="padding:8px"><div style="max-height:300px;overflow:auto;background:#fff;border:2px inset #dfdfdf">` +
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
    el.textContent = `Empfänger-Key ${fp.slice(0, 6)}…${fp.slice(-4)} · Porto ${p.foreign_sats} sats` +
      (fp.slice(0, 2) === '02' || fp.slice(0, 2) === '03' ? '' : ' · WARNUNG: seltsamer Key');
  };
  $('c-to').addEventListener('change', lookup);
  $('c-ab').onclick = () => openPicker((addrs) => {
    if (!addrs.length) return;
    const el = $('c-to') as HTMLInputElement;
    el.value = [el.value.trim(), ...addrs].filter(Boolean).join(', ');
    el.dispatchEvent(new Event('change'));
  });
  $('c-file').addEventListener('change', () => {
    const fs = [...($('c-file') as any).files] as File[];
    const el = $('portofuss') as HTMLElement;
    if (fs.length) el.textContent = `${fs.length} Anhang: ` + fs.map(f => `${f.name} (${Math.round(f.size / 1024)} kB)`).join(', ');
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
      const out = await composeAndSend(base, token, priv!, { to: $('c-to').value, subject: $('c-subj').value, body: $('c-body').value, attachments: atts });
      sentPush({ ts: Math.floor(Date.now() / 1000), to: $('c-to').value, subject: $('c-subj').value, msg_id: String(out.msg_id || ''), bytes: total });
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

async function useKey(txt: string) {
  if (isWrapped(txt)) {
    pendingWrap = txt;
    $('l-passrow').style.display = '';
    $('l-err').textContent = 'Verschluesselte Key-Datei — Passphrase eingeben.';
    return;
  }
  pemCache = txt; await login(txt);
}
async function tryUnwrap() {
  try { pemCache = unwrapKey(pendingWrap, ($('l-pass') as HTMLInputElement).value); await login(pemCache); }
  catch (e: any) { $('l-err').textContent = '✗ ' + e.message; }
}
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
  // §27-Währungsfrage: Relay sagt via /health, was es besiedelt (heute: nur btc)
  let currencies: string[] = ['btc'];
  try { currencies = (await (await fetch(base + '/health')).json()).currencies || currencies; } catch { /* Default btc */ }
  const mn = newMnemonic();
  const { body, close } = wizOverlay('Neues Konto — Einrichtung');
  const setErr = (t: string) => { const e = $('w-err'); if (e) e.textContent = t; };
  const wireCancel = () => { $('w-x').onclick = close; };

  // Schritt 1: Name + Währung
  const relaySel = ($('l-relay') as HTMLSelectElement).value;
  const relayName = relaySel.startsWith('/') ? location.hostname + relaySel : relaySel;
  body.innerHTML = `<p class="meta">Schritt 1/4 — Konto &amp; Währung</p>
    <label>Kontoname (klein, a-z 0-9 . _ -, 2–32 Zeichen)</label><input id="w-name" value="${esc(($('l-acct') as HTMLInputElement).value.trim())}">
    <label>Relay</label><input value="${esc(relayName)}" disabled>
    <p class="meta">Womit zahlst du Porto? ${currencies.map(c => '⚡ ' + c.toUpperCase()).join(' · ')}
    — heute zahlt alles in Bitcoin-Lightning; die echte Auswahl (BTC/LTC, §26) kommt, wenn dein Relay mehrere Währungen besiedelt.</p>
    ${ERRROW}<div class="row"><button id="w-next">Weiter</button><button id="w-x">Abbrechen</button></div>`;
  wireCancel();
  $('w-next').onclick = () => {
    const nm = ($('w-name') as HTMLInputElement).value.trim().toLowerCase();
    if (!/^[a-z0-9][a-z0-9._-]{1,31}$/.test(nm)) { setErr('Kontoname: 2–32 Zeichen, klein, a-z 0-9 . _ -'); return; }
    ($('l-acct') as HTMLInputElement).value = nm;
    stepWords();
  };

  // Schritt 2: die 24 Wörter
  function stepWords() {
    const words = mn.split(' ');
    body.innerHTML = `<p class="meta">Schritt 2/4 — Deine 24 Wörter (BIP39, englische Standardliste)</p>
      <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:2px 8px;background:#fff;border:2px inset #dfdfdf;padding:8px;font-size:12px">
        ${words.map((w, i) => `<span><b style="color:#8a8271">${i + 1}.</b> ${esc(w)}</span>`).join('')}</div>
      <p class="meta" style="color:#8b0000">⚠ Jetzt offline auf Papier notieren. Wer diese Wörter hat, kann dein Konto jederzeit übernehmen — kein Screenshot, keine Cloud, niemandem vorlesen.</p>
      <div class="row"><button id="w-copy" type="button">Kopieren</button></div>
      <label style="font-weight:400"><input type="checkbox" id="w-noted" style="width:auto"> Ich habe die 24 Wörter offline notiert</label>
      ${ERRROW}<div class="row"><button id="w-next" disabled>Weiter</button><button id="w-x">Abbrechen</button></div>`;
    wireCancel();
    $('w-copy').onclick = async () => {
      try { await navigator.clipboard.writeText(mn); $('w-copy').textContent = '✓ kopiert — Zwischenablage danach leeren!'; }
      catch { setErr('Kopieren nicht erlaubt — Wörter manuell abschreiben.'); }
    };
    ($('w-noted') as HTMLInputElement).onchange = (ev) => { ($('w-next') as HTMLButtonElement).disabled = !(ev.target as HTMLInputElement).checked; };
    $('w-next').onclick = stepQuiz;
  }

  // Schritt 3: Wortquiz — Backup-Beweis
  function stepQuiz() {
    const words = mn.split(' ');
    const qs = quizPositions(mn, 3);
    let done = 0;
    body.innerHTML = `<p class="meta">Schritt 3/4 — Zur Kontrolle: was hast du notiert?</p>
      ${qs.map((p, qi) => `<p style="margin:8px 0 4px">Wort <b>#${p + 1}</b>?</p>
        <div class="row" id="wq-${qi}">${quizOptions(mn, p).map(o => `<button type="button" data-w="${esc(o)}">${esc(o)}</button>`).join('')}</div>`).join('')}
      ${ERRROW}<div class="row"><button id="w-next" disabled>Weiter</button><button id="w-x">Abbrechen</button></div>`;
    wireCancel();
    qs.forEach((p, qi) => {
      document.querySelectorAll(`#wq-${qi} button`).forEach(btn => {
        btn.addEventListener('click', () => {
          const b = btn as HTMLElement;
          if (b.dataset.done) return;
          if (b.getAttribute('data-w') === words[p]) {
            b.dataset.done = '1';
            b.style.background = '#98fb98';
            document.querySelectorAll(`#wq-${qi} button`).forEach(x => { (x as HTMLButtonElement).disabled = true; });
            if (++done === qs.length) ($('w-next') as HTMLButtonElement).disabled = false;
          } else {
            b.style.background = '#ffb6c1';
            setErr('Falsches Wort — schau auf deinen Zettel.');
          }
        });
      });
    });
    $('w-next').onclick = stepKeyfile;
  }

  // Schritt 4: .lmkey-Datei optional, dann Konto-Anlage + Auto-Login
  function stepKeyfile() {
    const nm = ($('l-acct') as HTMLInputElement).value.trim();
    const pem = sec1PEM(keyFromMnemonic(mn));
    body.innerHTML = `<p class="meta">Schritt 4/4 — Schlüsseldatei (optional)</p>
      <p class="meta">Deine 24 Wörter sind das Haupt-Backup — Recovery geht jederzeit. Zusätzlich kannst du eine verschlüsselte .lmkey-Datei speichern: Login per Datei statt Wörter-Tippen. (Später auch über 🔐 im App-Kopf möglich.)</p>
      <input type="password" id="w-p1" placeholder="Passphrase (min. 8 Zeichen)">
      <input type="password" id="w-p2" placeholder="zur Kontrolle erneut">
      ${ERRROW}
      <div class="row"><button id="w-save" type="button">💾 Datei speichern &amp; anlegen</button>
        <button id="w-skip" type="button">Überspringen — nur Wörter</button>
        <button id="w-x">Abbrechen</button></div>`;
    wireCancel();
    $('w-save').onclick = async () => {
      const p1 = ($('w-p1') as HTMLInputElement).value;
      if (p1.length < 8) { setErr('Passphrase zu kurz (min. 8 Zeichen).'); return; }
      if (p1 !== ($('w-p2') as HTMLInputElement).value) { setErr('Passphrasen stimmen nicht überein.'); return; }
      try {
        const blob = new Blob([wrapKey(pem, p1)], { type: 'text/plain' });
        const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
        a.download = `lightningmail-${nm}.lmkey`; a.click();
      } catch { setErr('Download fehlgeschlagen — Datei später über 🔐 möglich. Konto wird angelegt.'); }
      await create();
    };
    $('w-skip').onclick = () => create();
    async function create() {
      setErr('lege Konto an…');
      const r = await fetch(base + '/v1/account', { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: nm, pubkey: toHex(pubFromPriv(parseSec1PEM(pem))) }) });
      if (!r.ok) {
        const t = await r.text();
        setErr(/reserv/i.test(t) ? `„${nm}" ist ein reservierter Name (Service-/Impressumsadresse).`
          : r.status === 409 ? `Name „${nm}“ ist auf diesem Relay schon vergeben.` : errText(r.status, t));
        return;
      }
      pemCache = pem; close();
      await login(pem);
    }
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
  await useKey(await f.text());
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
  return { id: c.id, rawId: b64u(c.rawId), type: c.type, response: r, clientExtensionResults: c.getClientExtensionResults?.() || {} };
};

if (!passkeyAvailable()) {
  const lp = $('l-passkey') as HTMLButtonElement;
  lp.disabled = true; lp.title = 'Passkeys brauchen HTTPS (Secure Context)';
}

async function passkeyLogin() {
  $('l-err').textContent = '';
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
      $('l-err').textContent = 'Passkey bestätigt. Dieser Browser kann den Schlüssel nicht per PRF entsiegeln — Notfall-Passphrase eingeben.';
    } else {
      $('l-err').textContent = '✗ Dieser Passkey hat keinen Schlüssel-Wrap. Einmal mit Schlüsseldatei anmelden und Passkey neu hinzufügen.';
    }
  } catch (e: any) {
    $('l-err').textContent = '✗ ' + String(e?.message || e).slice(0, 140);
  }
}
$('l-passkey').onclick = passkeyLogin;

async function passkeyRegister() {
  try {
    const br = await api('/v1/webauthn/register/begin', { method: 'POST' });
    if (!br.ok) { alert(errText(br.status, await br.text())); return; }
    const begin = await br.json();
    const opts = decodeOpts(begin.options.publicKey);
    const cred = await navigator.credentials.create({ publicKey: opts });
    const ext: any = (cred as any).getClientExtensionResults?.() || {};
    const prfSecret = ext.prf?.first ? new Uint8Array(ext.prf.first) : null;
    const wrap_prf = prfSecret ? wrapKeyPRF(pemCache, prfSecret) : '';
    let wrap_pass = pendingWrap || ''; // vorhandener Passphrase-Wrap wird mitgespeichert
    if (!wrap_pass && confirm('Zusätzlich eine Notfall-Passphrase für diesen Passkey setzen?\n\n(Abbrechen = nur Passkey/PRF — Anmeldung in Browsern ohne PRF-Unterstützung, z.B. Firefox/Safari, ist dann nicht möglich.)')) {
      const p1 = prompt('Notfall-Passphrase (min. 8 Zeichen):') || '';
      if (p1) {
        if (p1 === prompt('zur Kontrolle erneut eingeben:')) wrap_pass = wrapKey(pemCache, p1);
        else alert('Passphrasen stimmen nicht überein — ohne Notfall-Wrap gespeichert.');
      }
    }
    const ua = navigator.userAgent;
    const label = `${new Date().toLocaleDateString('de-DE')} ${/android/i.test(ua) ? 'Android' : /iphone|ipad/i.test(ua) ? 'iOS' : /windows/i.test(ua) ? 'Windows' : /mac os/i.test(ua) ? 'macOS' : /linux/i.test(ua) ? 'Linux' : 'Gerät'} ${prfSecret ? '(PRF ✓)' : '(PRF ✗)'}`;
    const fr = await api('/v1/webauthn/register/finish', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sid: begin.sid, name: label, credential: cred2json(cred), wrap_prf, wrap_pass }) });
    const fin = await fr.json().catch(() => ({}));
    if (!fr.ok) { alert('✗ ' + (fin.error || errText(fr.status))); return; }
    alert(`✓ Passkey hinzugefügt: ${label}${prfSecret ? '' : '\nAchtung: ohne PRF wurde kein Schlüssel-Wrap erzeugt — Notfall-Passphrase nötig für Login.'}`);
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
$('nav-out').onclick = () => { localStorage.setItem(NOAUTO_KEY, '1'); location.reload(); };
if ($('l-passbtn')) $('l-passbtn').onclick = tryUnwrap;
function mark() {
  $('nav-in').classList.toggle('on', folder === 'in');
  $('nav-spam').classList.toggle('on', folder === 'spam');
  if ($('nav-sent')) $('nav-sent').classList.toggle('on', folder === 'out');
  if ($('nav-dra')) $('nav-dra').classList.toggle('on', folder === 'dra');
  $('nav-new').classList.toggle('on', folder === 'new');
  $('nav-ab').classList.toggle('on', folder === 'ab');
}

// Start: gespeicherten Schluessel wiederladen. Ohne explizites Abmelden (lm_noauto)
// loggt die App sofort ein; sonst zeigt der Login die Ein-Klick-Zeile "Weiter als …".
const autoSaved = loadAuto();
if (autoSaved) {
  ($('l-acct') as HTMLInputElement).value = autoSaved.acct;
  ($('l-relay') as HTMLSelectElement).value = autoSaved.base;
  const q = $('l-quick'); q.style.display = '';
  ($('l-quickgo') as HTMLButtonElement).textContent = `► Weiter als ${autoSaved.acct}`;
  $('l-quickgo').onclick = () => {
    pemCache = autoSaved.pem;
    login(autoSaved.pem).catch((e: any) => { $('l-err').textContent = '✗ ' + String(e?.message || e).slice(0, 120); });
  };
  $('l-forget').onclick = () => {
    localStorage.removeItem(AUTO_KEY);
    q.style.display = 'none';
    $('l-err').textContent = 'Gespeicherter Schluessel geloescht — Datei oder Demo-Key noetig.';
  };
  if (!localStorage.getItem(NOAUTO_KEY)) {
    pemCache = autoSaved.pem;
    login(autoSaved.pem).catch((e: any) => { $('l-err').textContent = 'Auto-Login fehlgeschlagen: ' + String(e?.message || e).slice(0, 120); });
  }
}
