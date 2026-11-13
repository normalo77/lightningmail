// main.ts — DOM-Leim für die lightningmail v0.1 PWA. Logik lebt in src/crypto + src/send.
import { parseSec1PEM, pubFromPriv, authSign, toHex, fromB64, decodeEnvelope, decryptPayload, TAG, blobCount, blobRef } from '../src/crypto';
import { composeAndSend } from '../src/send';

const $ = (id: string) => document.getElementById(id)!;
let base = '/relay-b', token = '', priv: Uint8Array | null = null, acct = '';
let msgs: { seq: number; subject: string; body: string; sender: string; ts: number; atts: { sha256: string; name: string }[] }[] = [];
let sel = -1, folder: 'in' | 'spam' | 'new' = 'in';
let pemCache = ''; // geladener Schluesseltext, damit 'Anmelden' erneut geht
const spamKey = () => `lm_spam_${base.slice(1)}_${acct}`;
const spamSet = (): Set<string> => new Set(JSON.parse(localStorage.getItem(spamKey()) || '[]'));
const spamAdd = (s: string) => { const x = spamSet(); x.add(s); localStorage.setItem(spamKey(), JSON.stringify([...x])); };
const spamDel = (s: string) => { const x = spamSet(); x.delete(s); localStorage.setItem(spamKey(), JSON.stringify([...x])); };

async function api(path: string, init?: RequestInit) {
  const r = await fetch(base + path, { ...init, headers: { ...(init?.headers || {}), Authorization: `Bearer ${token}` } });
  return r;
}

async function login(pem: string) {
  acct = $('l-acct').value.trim(); base = $('l-relay').value;
  priv = parseSec1PEM(pem);
  const sig = authSign(priv, acct);
  const r = await fetch(base + '/v1/auth', { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ address: acct, pubkey_hex: toHex(pubFromPriv(priv)), sig: toHex(sig) }) });
  if (!r.ok) { $('l-err').textContent = 'Login fehlgeschlagen: ' + r.status + ' ' + await r.text(); return; }
  token = ((await r.json()) as any).token;
  $('login').classList.add('hidden'); $('app').classList.remove('hidden');
  $('who').textContent = `${acct}@${base.slice(1)} · `;
  await refresh();
}

async function refresh() {
  const bal = await (await api('/v1/balance')).json() as any;
  $('balance').textContent = `Guthaben: ${Math.floor((bal.balance_msat || 0) / 1000)} sats`;
  const inbox = await (await api('/v1/inbox')).json() as any;
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
    } catch { /* unreadbar — ordentlich ignorieren */ }
  }
  render();
}

function visible() {
  const sp = spamSet();
  return msgs.filter(m => folder === 'spam' ? sp.has(m.sender) : !sp.has(m.sender));
}

function render() {
  if (folder === 'new') { renderCompose(); $('list').innerHTML = ''; return; }
  const list = visible().slice().reverse();
  $('list').innerHTML = list.map(m => `<div class="row ${m.seq === sel ? 'sel' : ''}" data-seq="${m.seq}">
    <div class="subj">${esc(m.subject)}</div>
    <div class="meta">${esc(m.sender)}… · ${new Date(m.ts * 1000).toLocaleString('de')} ${m.atts.length ? '📎' : ''}</div></div>`).join('') ||
    '<div class="meta" style="padding:12px">— leer —</div>';
  document.querySelectorAll('#list .row').forEach(el =>
    el.addEventListener('click', () => { sel = +el.getAttribute('data-seq')!; render(); renderDetail(); }));
  if (sel >= 0 && list.some(m => m.seq === sel)) renderDetail(); else $('detail').innerHTML = '<p class="meta">Message wählen.</p>';
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
    if (!r.ok) { alert('Blob ' + r.status); return; }
    const url = URL.createObjectURL(await r.blob());
    const a = document.createElement('a'); a.href = url; a.download = el.getAttribute('data-name')!; a.click();
  }));
  $('cl-spam').onclick = () => { sp ? spamDel(m.sender) : spamAdd(m.sender); render(); };
  if ($('cl-un')) $('cl-un').onclick = () => { spamDel(m.sender); render(); };
}

async function renderCompose() {
  $('detail').innerHTML = `<div class="card"><form class="compose" id="cform">
    <input id="c-to" placeholder="An: name@domain" required>
    <input id="c-subj" placeholder="Betreff" required>
    <textarea id="c-body" placeholder="Nachricht…"></textarea>
    <input type="file" id="c-file" multiple>
    <label style="font-size:13px;color:var(--faint)"><input type="checkbox" id="c-orig"> Original senden (keine Komprimierung — M2b-Foto-Kompression folgt)</label>
    <div id="portofuss">Porto: 10 sats pro fremdem Empfänger (wird vor dem Senden berechnet)</div>
    <div><button type="submit">Senden</button> <span id="c-msg" class="meta"></span></div>
  </form></div>`;
  $('cform').onsubmit = async (ev) => {
    ev.preventDefault();
    $('c-msg').textContent = 'sende…';
    try {
      const files = [...($('c-file') as any).files];
      const atts = await Promise.all(files.map(async f => ({ name: f.name, bytes: new Uint8Array(await f.arrayBuffer()) })));
      const out = await composeAndSend(base, token, priv!, { to: $('c-to').value, subject: $('c-subj').value, body: $('c-body').value, attachments: atts });
      $('c-msg').textContent = '✓ gesendet (' + (out.msg_id || '').slice(0, 10) + '…)';
    } catch (e: any) { $('c-msg').textContent = '✗ ' + e.message; }
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
$('nav-in').onclick = () => { folder = 'in'; mark(); render(); };
$('nav-spam').onclick = () => { folder = 'spam'; mark(); render(); };
$('nav-new').onclick = () => { folder = 'new'; mark(); render(); };
$('nav-out').onclick = () => location.reload();
function mark() {
  $('nav-in').classList.toggle('on', folder === 'in');
  $('nav-spam').classList.toggle('on', folder === 'spam');
  $('nav-new').classList.toggle('on', folder === 'new');
}
