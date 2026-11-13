// main.ts — DOM-Leim für die lightningmail v0.1 PWA (M2c). Logik lebt in src/crypto + src/send.
import { parseSec1PEM, pubFromPriv, authSign, toHex, fromB64, decodeEnvelope, decryptPayload, TAG, blobCount, blobRef } from '../src/crypto';
import { composeAndSend } from '../src/send';

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
let msgs: { seq: number; subject: string; body: string; sender: string; ts: number; atts: { sha256: string; name: string }[] }[] = [];
let sel = -1, folder: 'in' | 'spam' | 'out' | 'new' = 'in';
let pemCache = '';
const spamKey = () => `lm_spam_${base.slice(1)}_${acct}`;
const spamSet = (): Set<string> => new Set(JSON.parse(localStorage.getItem(spamKey()) || '[]'));
const spamAdd = (s: string) => { const x = spamSet(); x.add(s); localStorage.setItem(spamKey(), JSON.stringify([...x])); };
const spamDel = (s: string) => { const x = spamSet(); x.delete(s); localStorage.setItem(spamKey(), JSON.stringify([...x])); };

// Gesendet-Ordner (lokal, synchronisiert wird ab M2.5)
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
  if (!r.ok) { $('l-err').textContent = errText(r.status, await r.text()); return; }
  token = ((await r.json()) as any).token;
  $('login').classList.add('hidden'); $('app').classList.remove('hidden');
  $('who').textContent = `${acct}@${base.slice(1)} · `;
  await refresh();
}

async function refreshBalance() {
  const br = await api('/v1/balance');
  if (!br.ok) { $('balance').textContent = errText(br.status); return; }
  const bal = await br.json() as any;
  $('balance').textContent = `Guthaben: ${Math.floor((bal.balance_msat || 0) / 1000)} sats`;
}

async function refresh() {
  await refreshBalance();
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
      msgs.push({ seq: m.seq, subject: p.subject, body: p.body, sender: toHex(env[TAG.SenderPubkey]).slice(0, 12), ts: m.received_at, atts: atts.length ? atts : refs.map((r, i) => ({ sha256: r, name: `anhang-${i + 1}` })) });
    } catch (e: any) { (window as any).__decodeErr = String(e && e.stack || e); }
  }
  render();
}

function visible() {
  const sp = spamSet();
  return msgs.filter(m => folder === 'spam' ? sp.has(m.sender) : !sp.has(m.sender));
}

function render() {
  if (folder === 'new') { renderCompose(); $('list').innerHTML = ''; return; }
  if (folder === 'out') { renderSent(); return; }
  const list = visible().slice().reverse();
  $('list').innerHTML = list.map(m => `<div class="row ${m.seq === sel ? 'sel' : ''}" data-seq="${m.seq}">
    <div class="subj">${esc(m.subject)}</div>
    <div class="meta">${esc(m.sender)}… · ${new Date(m.ts * 1000).toLocaleString('de')} ${m.atts.length ? '📎' : ''}</div></div>`).join('') ||
    '<div class="meta" style="padding:12px">— leer —</div>';
  document.querySelectorAll('#list .row').forEach(el =>
    el.addEventListener('click', () => { sel = +el.getAttribute('data-seq')!; render(); renderDetail(); }));
  if (sel >= 0 && list.some(m => m.seq === sel)) renderDetail(); else $('detail').innerHTML = '<p class="meta">Message wählen.</p>';
}

function renderSent() {
  const l = sentList();
  $('list').innerHTML = l.map((s, i) => `<div class="row ${i === sel ? 'sel' : ''}" data-si="${i}">
    <div class="subj">${esc(s.subject)}</div>
    <div class="meta">→ ${esc(s.to)} · ${new Date(s.ts * 1000).toLocaleString('de')} · ${(s.bytes / 1024).toFixed(0)} kB</div></div>`).join('') ||
    '<div class="meta" style="padding:12px">— nichts gesendet —</div>';
  document.querySelectorAll('#list .row').forEach(el => el.addEventListener('click', () => {
    sel = +el.getAttribute('data-si')!; const s = sentList()[sel];
    $('detail').innerHTML = `<div class="card"><div class="subj" style="font-size:17px">${esc(s.subject)}</div>
      <div class="meta">An ${esc(s.to)} · ${new Date(s.ts * 1000).toLocaleString('de')}<br>msg_id ${esc(s.msg_id.slice(0, 16))}… · Porto bezahlt</div>
      <p class="meta">Der Text liegt nur beim Empfänger (und ab M2.5 im Sync). Gesendet-Ordner ist lokal.</p></div>`;
  }));
}

function esc(s: string) { return (s || '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]!)); }

function renderDetail() {
  const m = msgs.find(x => x.seq === sel)!;
  const sp = spamSet().has(m.sender);
  $('detail').innerHTML = `<div class="card">
    <div class="subj" style="font-size:17px">${esc(m.subject)}</div>
    <div class="meta">Von ${esc(m.sender)}… · ${new Date(m.ts * 1000).toLocaleString('de')}</div>
    <pre style="white-space:pre-wrap;font:inherit;margin:14px 0">${esc(m.body)}</pre>
    ${m.atts.map(a => `<span class="attach" data-sha="${a.sha256}" data-name="${esc(a.name)}">↓ ${esc(a.name)}</span>`).join('')}
    <div class="classify">Absender:
      <button id="cl-spam" class="${sp ? 'on' : ''}">${sp ? 'unerwünscht' : 'als unerwünscht markieren'}</button>
      ${sp ? '<button id="cl-un">zurück nach Posteingang</button>' : ''}
    </div></div>`;
  document.querySelectorAll('.attach').forEach(el => el.addEventListener('click', async () => {
    const r = await api(`/v1/blob/${el.getAttribute('data-sha')}`);
    if (!r.ok) { alert(errText(r.status)); return; }
    const url = URL.createObjectURL(await r.blob());
    const a = document.createElement('a'); a.href = url; a.download = el.getAttribute('data-name')!; a.click();
  }));
  $('cl-spam').onclick = () => { sp ? spamDel(m.sender) : spamAdd(m.sender); render(); };
  if ($('cl-un')) $('cl-un').onclick = () => { spamDel(m.sender); render(); };
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
    <input id="c-to" placeholder="An: name@domain" required>
    <input id="c-subj" placeholder="Betreff" required>
    <textarea id="c-body" placeholder="Nachricht…"></textarea>
    <input type="file" id="c-file" multiple>
    <label style="font-size:13px;color:var(--faint)"><input type="checkbox" id="c-orig"> Original senden (Fotos sonst auf 1600px JPEG komprimiert)</label>
    <div id="portofuss" class="meta">Empfänger wählen — Porto und Fingerprint erscheinen hier.</div>
    <div><button type="submit">Senden</button> <span id="c-msg" class="meta"></span></div>
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
  $('c-file').addEventListener('change', () => {
    const fs = [...($('c-file') as any).files] as File[];
    const el = $('portofuss') as HTMLElement;
    if (fs.length) el.textContent = `${fs.length} Anhang: ` + fs.map(f => `${f.name} (${Math.round(f.size / 1024)} kB)`).join(', ');
  });

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
      $('c-msg').textContent = '✓ gesendet (' + (out.msg_id || '').slice(0, 10) + '…)';
      await refreshBalance();
    } catch (e: any) {
      const m0 = String(e.message || e);
      const st = /: (\d{3}) /.exec(m0);
      $('c-msg').textContent = '✗ ' + (st ? errText(+st[1], m0) : m0.slice(0, 120));
    }
  };
}

async function useKey(txt: string) { pemCache = txt; await login(txt); }
$('l-demo').onclick = async () => {
  const r = await fetch(`/keys/${$('l-acct').value.trim()}.key`);
  if (!r.ok) { $('l-err').textContent = 'Demo-Key nicht gefunden (' + $('l-acct').value.trim() + ')'; return; }
  await useKey(await r.text());
};
$('l-file').onchange = async (ev: Event) => {
  const f = (ev.target as any).files[0]; if (!f) return;
  await useKey(await f.text());
};
$('l-login').onclick = async () => {
  if (!pemCache) { $('l-err').textContent = 'Erst Schluessel laden (Demo-Knopf oder Datei).'; return; }
  await login(pemCache);
};
$('nav-in').onclick = () => { folder = 'in'; sel = -1; mark(); render(); };
$('nav-spam').onclick = () => { folder = 'spam'; sel = -1; mark(); render(); };
if ($('nav-sent')) $('nav-sent').onclick = () => { folder = 'out'; sel = -1; mark(); render(); };
$('nav-new').onclick = () => { folder = 'new'; mark(); render(); };
$('nav-out').onclick = () => location.reload();
function mark() {
  $('nav-in').classList.toggle('on', folder === 'in');
  $('nav-spam').classList.toggle('on', folder === 'spam');
  if ($('nav-sent')) $('nav-sent').classList.toggle('on', folder === 'out');
  $('nav-new').classList.toggle('on', folder === 'new');
}
