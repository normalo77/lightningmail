// main.ts — DOM glue for the lightningmail v0.1 PWA (M2c). Logic lives in src/crypto + src/send.
import { parseSec1PEM, pubFromPriv, authSign, toHex, fromB64, decodeEnvelope, decryptPayload, TAG, blobCount, blobRef, sec1PEM, schnorr, sha256 } from '../src/crypto';
import { newMnemonic, checkMnemonic, keyFromMnemonic, quizPositions, quizOptions } from '../src/bip39';
import { parseManifest, reassemble } from '../src/chunks';
import { composeAndSend } from '../src/send';
import { StateSync, type Contact, type DriveEntry } from '../src/state';
import { uploadFile, downloadFile, deleteFile, usage as driveUsage, buyTier, newDriveId, type DriveUsage } from '../src/drive';
import { wrapKey, unwrapKey, isWrapped, wrapKeyPRF, unwrapKeyPRF } from '../src/keywrap';
let pendingWrap = '';


// Buffer shim: noble libraries reference Node APIs even in the browser
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
let SELF_RELAY = false; // the UI runs on its own relayd (Etappe O, self-hosted)
let msgs: MsgRow[] = [];
let tipSats = 0, myForeign = 0, myWelcome = 0, portoBase = ''; // §30.4 enclosure + testnet/mainnet marker
let receipts: Record<string, number> = {}; // msg_id(hex) -> ✓✓ timestamp (Etappe 6b)
let outbox: Record<string, { status: string; since: number }> = {}; // Etappe R: msg_id -> pending/dead send
let sel = -1, folder: 'in' | 'spam' | 'out' | 'dra' | 'new' | 'ab' | 'ums' | 'drv' = 'in';
let pemCache = '';
// Auto-login: a successful login remembers key+account+relay in device storage.
// Session storage: in the browser the decrypted private key only lives in the
// volatile sessionStorage (cleared when the browser window closes or on
// "Abmelden"). On Android the hardware keystore
// (AndroidNative.saveVault/loadVault) takes over persistent sealing.
const AUTO_KEY = 'lm_autologin', NOAUTO_KEY = 'lm_noauto';
const LAST_USER_KEY = 'lm_last_user';
const loadLastUser = (): { acct: string; base: string } | null => {
  try {
    const u = JSON.parse(localStorage.getItem(LAST_USER_KEY) || 'null');
    return u && typeof u.acct === 'string' && u.acct ? { acct: u.acct, base: String(u.base || '') } : null;
  } catch { return null; }
};
const setLoginStatus = (msg: string, isErr = true) => {
  const el = document.getElementById('l-err');
  if (!el) return;
  el.textContent = msg;
  el.className = 'login-status ' + (isErr ? 'err' : 'info');
  el.style.display = msg ? '' : 'none';
};
const loadAuto = (): { acct: string; base: string; pem: string } | null => {
  try {
    // Migration: if a plaintext key from an older session is still in localStorage,
    // move it to sessionStorage once and immediately erase it from localStorage.
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
let healthCache: any = null; // Etappe 7: /health (byte-postage price + rate) for the compose estimate
// IdP (§21/§29): OIDC login mode — ?oidc=<issuer>&sid=… turns the PWA into
// the „Sign in with lightningmail" page (login as usual, then consent).
const oidcQ = new URLSearchParams(location.search);
const oidcRelay = oidcQ.get('oidc'), oidcSid = oidcQ.get('sid');
let abSel = '', abEdit = '', abQ = ''; // address book (Etappe A)
const spamKey = () => `lm_spam_${base.slice(1)}_${acct}`;
const spamSet = (): Set<string> => sync ? new Set(Object.keys(sync.doc.spam)) : new Set(JSON.parse(localStorage.getItem(spamKey()) || '[]'));
const spamAdd = (k: string) => { if (sync) sync.toggleSpam(k, true); else { const x = [...spamSet()]; x.push(k); localStorage.setItem(spamKey(), JSON.stringify(x)); } };
const spamDel = (k: string) => { if (sync) sync.toggleSpam(k, false); else { const x = new Set(spamSet()); x.delete(k); localStorage.setItem(spamKey(), JSON.stringify([...x])); } };

// Sent folder: localStorage as device fallback, synchronization via StateSync.sent (star sync)
type MsgRow = { seq: number; msgId: string; subject: string; body: string; sender: string; pub: string; ts: number; signup?: boolean; recv?: number; atts: { sha256: string; name: string; chunked?: boolean }[] };
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

// Chosen base path of the relay dropdown. '__custom__' (own relay via URL)
// is not a fetch base — there the navigation goes to the foreign relay's /app/;
// until then the first real suggestion remains the API base.
function relayVal(sel?: HTMLSelectElement | null): string {
  const s = sel ?? ($('l-relay') as HTMLSelectElement | null);
  const v = s?.value || '';
  if (!v.startsWith('__')) return v;
  const real = s ? [...s.options].find(o => o.value && !o.value.startsWith('__')) : null;
  return real?.value || '';
}

function relayCandidates(preferred = ''): string[] {
  const selEl = document.getElementById('l-relay') as HTMLSelectElement | null;
  const opts = selEl ? [...selEl.options].map(o => o.value).filter(v => v && !v.startsWith('__')) : ['/relay-a', '/relay-b'];
  const out: string[] = [];
  const push = (v: string) => { if (v && !v.startsWith('__') && !out.includes(v)) out.push(v); };
  if (oidcRelay) {
    const m = opts.find(o => oidcRelay.includes('relay-b') ? o.includes('relay-b') : oidcRelay.includes('relay-a') ? o.includes('relay-a') : o === oidcRelay);
    if (m) push(m);
  }
  push(preferred);
  if (selEl?.value) push(selEl.value);
  const lu = loadLastUser();
  if (lu?.base) push(lu.base);
  for (const o of opts) push(o);
  // Synchronous fallback before the async self-host detection (Etappe O):
  // this origin's API as the last candidate (one more 404 on the hosting UI,
  // the hit on a foreign relay).
  out.push('');
  return out;
}

const hostLabelOf = (b: string): string => {
  try {
    if (b.startsWith('http')) return new URL(b).hostname;
  } catch { /* ignore */ }
  return location.hostname || 'lightningmail.app';
};

function openExportKeyModal() {
  const { body, close } = wizOverlay('🔐 Schlüsseldatei (.lmkey) speichern', 440);
  body.innerHTML = `<p class="meta" style="margin:0 0 8px">Schützt deinen Schlüssel für <b>${esc(acct)}</b> mit einem Passwort (mindestens 8 Zeichen):</p>
    <label for="ek-p1">Passwort wählen</label>
    <input type="password" id="ek-p1" placeholder="Mindestens 8 Zeichen — am besten eine Wortkette…" autocomplete="new-password" style="margin:4px 0 8px">
    <label for="ek-p2">Passwort wiederholen</label>
    <input type="password" id="ek-p2" placeholder="Zur Kontrolle wiederholen…" autocomplete="new-password" style="margin:4px 0 4px">
    ${ERRROW}
    <div class="row" style="margin-top:12px">
      <button type="button" id="ek-ok" style="flex:2;background:var(--navy);color:#fff;border-color:var(--navy);padding:11px 16px">💾 .lmkey herunterladen</button>
      <button type="button" id="w-x">Abbrechen</button>
    </div>`;
  $('w-x').onclick = close;
  setTimeout(() => ($('ek-p1') as HTMLInputElement)?.focus(), 40);
  const run = () => {
    const p1 = ($('ek-p1') as HTMLInputElement).value;
    const p2 = ($('ek-p2') as HTMLInputElement).value;
    if (p1.length < 8) { $('w-err').textContent = '✗ Bitte mindestens 8 Zeichen verwenden.'; return; }
    if (p1 !== p2) { $('w-err').textContent = '✗ Die beiden Passwörter stimmen nicht überein.'; return; }
    try {
      const wrapped = wrapKey(pemCache, p1);
      pendingWrap = wrapped;
      const blob = new Blob([wrapped], { type: 'text/plain' });
      const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
      a.download = `lightningmail-${acct}.lmkey`; a.click();
      close();
    } catch (e: any) { $('w-err').textContent = '✗ ' + String(e?.message || e); }
  };
  $('ek-ok').onclick = run;
  ($('ek-p2') as HTMLInputElement).onkeydown = (e) => { if (e.key === 'Enter') { e.preventDefault(); run(); } };
}

async function finishLogin(pem: string, privBytes: Uint8Array, resolvedAcct: string, resolvedBase: string, tok: string) {
  acct = resolvedAcct;
  base = resolvedBase;
  priv = privBytes;
  pemCache = pem;
  token = tok;
  healthCache = null;
  setLoginStatus('', false);
  const acctEl = document.getElementById('l-acct') as HTMLInputElement | null;
  if (acctEl) acctEl.value = acct;
  const relEl = document.getElementById('l-relay') as HTMLSelectElement | null;
  if (relEl && [...relEl.options].some(o => o.value === base)) relEl.value = base;
  try { localStorage.setItem(LAST_USER_KEY, JSON.stringify({ acct, base })); } catch {}
  localStorage.removeItem(AUTO_KEY);
  // On Android seal in the hardware keystore (StrongBox -> TEE, CryptoObject-bound); in the browser only sessionStorage
  const an = (window as any).AndroidNative;
  if (an?.sealVaultBiometric) {
    const vi = androidVaultInfo();
    const needsSeal = !vi.hasVault || vi.acct !== acct || vi.base !== base || (!!vi.strongBio && !vi.bioBound);
    if (needsSeal) {
      // Non-blocking seal prompt; login stays active even if the user cancels
      androidSealVault(JSON.stringify({ acct, base, pem }), acct, base).catch(() => {});
    }
  } else if (an?.saveVault) {
    try { an.saveVault(JSON.stringify({ acct, base, pem })); } catch { /* the vault is a convenience */ }
  }
  sessionStorage.setItem(AUTO_KEY, JSON.stringify({ acct, base, pem }));
  localStorage.removeItem(NOAUTO_KEY);
  $('login').classList.add('hidden'); $('app').classList.remove('hidden');
  const bp = $('btn-passkey');
  if (bp && (passkeyAvailable() || !!(window as any).AndroidNative?.requestBiometricAuth)) {
    bp.style.display = '';
    bp.onclick = passkeyRegister;
  }
  const kw = $('btn-keywrap');
  if (kw) { kw.style.display = ''; kw.onclick = openExportKeyModal; }
  $('who').textContent = `${acct}@${hostLabelOf(base)} · `;
  applyNetBadge(base);
  // own postage norms: inbox badge only when actually MORE than the standard postage arrived (§30.4)
  fetch(`${base}/v1/profile/${acct}`).then(r => r.ok ? r.json() : null).then((p: any) => {
    if (p && p.foreign_sats) { myForeign = p.foreign_sats; myWelcome = p.welcome_sats ?? p.foreign_sats * 3; render(); }
  }).catch(() => { /* badge is a convenience, not an error case */ });
  sync = new StateSync(base, priv, () => token, `lm_state_${base.slice(1)}_${acct}`);
  sync.cacheLoad();
  for (const k of JSON.parse(localStorage.getItem(spamKey()) || '[]')) sync.doc.spam[k] = 1;
  for (const s of JSON.parse(localStorage.getItem(sentKey()) || '[]'))
    if (!sync.liveSent().some(x => x.msg_id === s.msg_id)) sync.addSent(s);
  try { await sync.pull(); } catch { /* without a state slot the UI runs from the cache */ }
  await refresh();
  if (oidcRelay && oidcSid) oidcFlow();
}

// Automatic login from the private key alone (finds account name & relay autonomously)
async function loginAuto(pem: string, hintedAcct = '', onErr?: (msg: string) => void): Promise<boolean> {
  let p: Uint8Array;
  try {
    p = parseSec1PEM(pem);
  } catch {
    const m = 'Ungültiges Schlüsselformat.';
    if (onErr) onErr(m); else setLoginStatus('✗ ' + m);
    return false;
  }
  const pubHex = toHex(pubFromPriv(p));
  const advOpen = (document.getElementById('l-adv') as HTMLDetailsElement | null)?.open;
  const typedAcct = (($('l-acct') as HTMLInputElement | null)?.value || '').trim().toLowerCase();
  const candidates = relayCandidates();
  let lastNetErr = '';

  for (const candBase of candidates) {
    try {
      // 1. Primary path: pubkey-based account resolution at the server (address="")
      const sigAuto = authSign(p, pubHex);
      let r = await fetch(candBase + '/v1/auth', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ address: '', pubkey_hex: pubHex, sig: toHex(sigAuto) }),
      });
      if (r.ok) {
        const j = (await r.json()) as any;
        const resolved = j.address || hintedAcct || typedAcct;
        await finishLogin(pem, p, resolved, candBase, j.token);
        return true;
      }
      // 2. Fallback for older third-party relays when the account name is known
      const fbAcct = (advOpen && typedAcct) ? typedAcct : (hintedAcct || typedAcct);
      if (r.status === 400 && fbAcct) {
        r = await fetch(candBase + '/v1/auth', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ address: fbAcct, pubkey_hex: pubHex, sig: toHex(authSign(p, fbAcct)) }),
        });
        if (r.ok) {
          const j = (await r.json()) as any;
          await finishLogin(pem, p, j.address || fbAcct, candBase, j.token);
          return true;
        }
      }
      if (r.status !== 404 && r.status !== 401) {
        lastNetErr = errText(r.status, await r.text());
      }
    } catch (e: any) {
      lastNetErr = String(e?.message || e).slice(0, 100);
    }
  }
  const msg = lastNetErr || 'Zu diesem Schlüssel wurde auf keinem Server ein Konto gefunden.';
  if (onErr) onErr(msg); else setLoginStatus('✗ ' + msg);
  return false;
}

async function login(pem: string, explicitAcct = '', explicitBase = ''): Promise<boolean> {
  const targetAcct = (explicitAcct || ($('l-acct') as HTMLInputElement).value || '').trim().toLowerCase();
  // On the relay's own UI there is only "this origin" — a remembered
  // /relay-a path from an Android vault (device-global!) would lead nowhere.
  const targetBase = SELF_RELAY ? '' : (explicitBase || relayVal());
  if (!targetAcct) return loginAuto(pem);
  try {
    const p = parseSec1PEM(pem);
    const pubHex = toHex(pubFromPriv(p));
    const sig = authSign(p, targetAcct);
    const r = await fetch(targetBase + '/v1/auth', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ address: targetAcct, pubkey_hex: pubHex, sig: toHex(sig) }),
    });
    if (r.ok) {
      const j = (await r.json()) as any;
      await finishLogin(pem, p, j.address || targetAcct, targetBase, j.token);
      return true;
    }
    // If the field held a wrong account name/relay: search automatically via the pubkey!
    if (r.status === 401 || r.status === 404) {
      return await loginAuto(pem, targetAcct);
    }
    setLoginStatus('✗ ' + errText(r.status, await r.text()));
    return false;
  } catch (e: any) {
    setLoginStatus('✗ ' + String(e?.message || e).slice(0, 120));
    return false;
  }
}

async function refreshBalance() {
  const br = await api('/v1/balance');
  if (!br.ok) { $('balance').textContent = errText(br.status); return; }
  const bal = await br.json() as any;
  $('balance').textContent = `Guthaben: ${Math.floor((bal.balance_msat || 0) / 1000)} sats`;
}

// Etappe 6b: load the ✓✓ receipts of the own account (sent folder)
async function fetchReceipts() {
  try {
    const r = await api('/v1/receipts');
    if (r.ok) for (const x of (((await r.json()) as any).receipts || [])) receipts[x.msg_id] = x.ts;
  } catch { /* receipts are a convenience, not an error case */ }
}

// Etappe R: pending/dead eigene Sends (GET /v1/outbox) — ein Fetch pro
// Gesendet-Rendering, keine Polling-Expansion.
async function fetchOutbox() {
  try {
    const r = await api('/v1/outbox');
    if (r.ok) { outbox = {}; for (const x of ((await r.json()) as any[])) outbox[x.msg_id] = x; }
  } catch { /* outbox is a convenience, not an error case */ }
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
      msgs.push({ seq: m.seq, msgId: toHex(env[TAG.MsgID]), subject: p.subject, body: p.body, sender: toHex(env[TAG.SenderPubkey]).slice(0, 12), pub: toHex(env[TAG.SenderPubkey]), ts: m.received_at, signup: !!(env[TAG.Signup] && env[TAG.Signup][0] === 1), recv: Number(m.received_sats) || undefined, atts: atts.length ? atts : refs.map((r, i) => ({ sha256: r, name: `anhang-${i + 1}` })) });
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
  if (folder === 'drv') { renderDrv(); return; }
  if (folder === 'out') { renderSent(); return; }
  if (folder == 'dra') { renderDrafts(); return; }
  const list = visible().slice().reverse();
  const recvTip = (m: MsgRow) => (m.recv && myForeign && m.recv > myForeign && m.recv !== myWelcome)
    ? ` <b class="recv" title="real eingegangen, vom eigenen Relay bestaetigt">⚡ ${m.recv} Sats</b>` : '';
  $('list').innerHTML = list.map(m => `<div class="row ${m.seq === sel ? 'sel' : ''}" data-seq="${m.seq}">
    <div class="subj" ${sync && sync.doc.read[m.msgId] ? 'style="font-weight:400;color:#8a8271"' : ''}>${m.signup ? '[🔑 Registrierung] ' : ''}${esc(m.subject)}</div>
    <div class="meta">${esc(m.sender)}… · ${new Date(m.ts * 1000).toLocaleString('de')} ${m.atts.length ? '📎' : ''}${recvTip(m)}</div></div>`).join('') ||
    '<div class="meta" style="padding:12px">— leer —</div>';
  document.querySelectorAll('#list .row').forEach(el =>
    el.addEventListener('click', () => { sel = +el.getAttribute('data-seq')!; const mm = msgs.find(x => x.seq === sel); if (mm && sync) { sync.markRead(mm.msgId); } render(); renderDetail(); }));
  if (sel >= 0 && list.some(m => m.seq === sel)) renderDetail(); else $('detail').innerHTML = '<p class="meta">Message wählen.</p>';
}

function renderSent() {
  const l = sentList();
  const tick = (id: string) => outbox[id]
    ? (outbox[id].status === 'pending'
      ? `<span style="background:#f2c14baa;color:#000;border-radius:8px;padding:1px 6px" title="Empfänger-Relay nicht erreichbar — dein Relay liefert mit Backoff nach">⏳ unterwegs seit ${new Date(outbox[id].since * 1000).toLocaleString('de')}</span>`
      : `<span style="background:#c0392bcc;color:#fff;border-radius:8px;padding:1px 6px" title="Nach Retention aufgegeben — Porto zurückerstattet">✗ unzustellbar, Porto zurückerstattet</span>`)
    : (receipts[id]
      ? `<span style="color:var(--accent)" title="Empfänger hat abgerufen ${new Date(receipts[id] * 1000).toLocaleString('de')}">✓✓</span>`
      : `<span title="zugestellt (Porto am Empfänger-Relay settled) — auf Empfänger-Abruf wartend">✓</span>`);
  $('list').innerHTML = l.map((s, i) => `<div class="row ${i === sel ? 'sel' : ''}" data-si="${i}">
    <div class="subj">${esc(s.subject)}</div>
    <div class="meta">→ ${esc(s.to)} · ${new Date(s.ts * 1000).toLocaleString('de')} · ${(s.bytes / 1024).toFixed(0)} kB ${tick(s.msg_id)}</div></div>`).join('') ||
    '<div class="meta" style="padding:12px">— nichts gesendet —</div>';
  document.querySelectorAll('#list .row').forEach(el => el.addEventListener('click', () => {
    sel = +el.getAttribute('data-si')!; const s = sentList()[sel];
    $('detail').innerHTML = `<div class="card"><div class="subj" style="font-size:17px">${esc(s.subject)}</div>
      <div class="meta">An ${esc(s.to)} · ${new Date(s.ts * 1000).toLocaleString('de')}<br>msg_id ${esc(s.msg_id.slice(0, 16))}… · ${outbox[s.msg_id]?.status === 'dead' ? 'unzustellbar — Porto zurückerstattet' : 'Porto bezahlt'}</div>
      ${s.body ? `<pre style="white-space:pre-wrap;font:inherit;margin:14px 0">${esc(s.body)}</pre>` : ''}
      <p class="meta">${outbox[s.msg_id]
        ? (outbox[s.msg_id].status === 'pending'
          ? `⏳ unterwegs seit ${new Date(outbox[s.msg_id].since * 1000).toLocaleString('de')} — dein Relay versucht die Zustellung weiter`
          : `✗ unzustellbar — nach Retention aufgegeben, Porto zurückerstattet`)
        : (receipts[s.msg_id]
          ? `✓✓ vom Empfänger abgerufen: ${new Date(receipts[s.msg_id] * 1000).toLocaleString('de')}`
          : '✓ zugestellt (am Empfänger-Relay) — warte auf Abruf durch den Empfänger')}</p>
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

// Attachment cache in IndexedDB: blobs opened once survive locally for good —
// even after the relay sweep (first download + 7 days) deletes them server-side.
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
  } catch { /* cache is a convenience, not an error case */ }
}

// Fetch attachment content (IDB cache before relay download) — shared by download and save.
async function attBytes(a: { sha256: string; chunked?: boolean }): Promise<Uint8Array> {
  const cached = await idbGetBlob(a.sha256);
  if (cached) return cached;
  let bytes: Uint8Array;
  if (a.chunked) {
    const mr = await api(`/v1/blob/${a.sha256}`);
    if (!mr.ok) throw new Error(errText(mr.status));
    const man = parseManifest(new Uint8Array(await mr.arrayBuffer()));
    bytes = await reassemble(async (sha) => {
      const rr = await api(`/v1/blob/${sha}`);
      if (!rr.ok) throw new Error(errText(rr.status));
      return new Uint8Array(await rr.arrayBuffer());
    }, man);
  } else {
    const r = await api(`/v1/blob/${a.sha256}`);
    if (!r.ok) throw new Error(errText(r.status));
    bytes = new Uint8Array(await r.arrayBuffer());
  }
  await idbPutBlob(a.sha256, bytes);
  return bytes;
}

const safeName = (v: string): string =>
  (v || "teil").replace(/[\/:*?"<>|\u0000-\u001f]+/g, " ").replace(/\s+/g, " ").trim().slice(0, 100) || "teil";

// Letter + attachments into a target folder: "yyyy_mm_dd sender subject.txt" + original attachment names
async function saveMailAs(m: MsgRow): Promise<string> {
  const d = new Date(m.ts * 1000);
  const p2 = (n: number) => String(n).padStart(2, "0");
  const cn = contactFor(m.pub);
  const abs = cn ? abLabel(cn) : m.sender + "…";
  const mailName = `${d.getFullYear()}_${p2(d.getMonth() + 1)}_${p2(d.getDate())} ${safeName(abs)} ${safeName(m.subject)}.txt`;
  const head = "lightningmail — gespeicherter Brief\n"
    + "Von:     " + (cn ? abLabel(cn) + " <" + (cn.lnaddr || cn.email || "") + ">" : m.pub) + "\n"
    + "An:      " + acct + "\n"
    + "Datum:   " + d.toLocaleString("de") + "\n"
    + "Betreff: " + m.subject + "\n"
    + (m.recv && myForeign && m.recv > myForeign ? "Eingegangen: " + m.recv + " Sats (Porto + Beilage)\n" : "")
    + (m.atts.length ? "Anhänge (separate Dateien): " + m.atts.map(a => a.name).join(", ") + "\n" : "")
    + "msg_id:  " + m.msgId + "\n\n";
  const files: { name: string; blob: Blob }[] = [{ name: mailName, blob: new Blob([head + m.body + "\n"], { type: "text/plain" }) }];
  for (const a of m.atts) files.push({ name: safeName(a.name), blob: new Blob([await attBytes(a) as BlobPart]) });
  if ((window as any).showDirectoryPicker) {
    try {
      const dir = await (window as any).showDirectoryPicker({ mode: "write" });
      for (const f of files) {
        const fh = await dir.getFileHandle(f.name, { create: true });  // a file with the same name gets updated
        const w = await fh.createWritable();
        await w.write(f.blob);
        await w.close();
      }
      return "✓ " + files.length + " Datei(en) im Ordner gespeichert";
    } catch (e: any) {
      if (String(e && e.name) === "AbortError") return "";
      throw e;
    }
  }
  for (const f of files) {
    const url = URL.createObjectURL(f.blob);
    const link = document.createElement("a"); link.href = url; link.download = f.name; link.click();
    await new Promise((r) => setTimeout(r, 350));
    setTimeout(() => URL.revokeObjectURL(url), 6000);
  }
  return "✓ " + files.length + " Datei(en) heruntergeladen";
}

function renderDetail() {
  const m = msgs.find(x => x.seq === sel)!;
  const sp = spamSet().has(m.sender);
  const cn = contactFor(m.pub);
  $('detail').innerHTML = `<div class="card">
    <div class="subj" style="font-size:17px">${m.signup ? '[🔑 Registrierung] ' : ''}${esc(m.subject)}</div>
    <div class="meta">Von ${cn ? esc(abLabel(cn)) : esc(m.sender) + '…'} · ${new Date(m.ts * 1000).toLocaleString('de')}${(m.recv && myForeign && m.recv > myForeign && m.recv !== myWelcome) ? ` · <span class="recv">⚡ ${m.recv} Sats erhalten</span>` : ''}</div>
    <pre style="white-space:pre-wrap;font:inherit;margin:14px 0">${esc(m.body)}</pre>
    ${m.atts.map(a => `<span class="attach" data-sha="${a.sha256}" data-name="${esc(a.name)}" data-chunked="${a.chunked ? 1 : 0}">↓ ${esc(a.name)}${a.chunked ? ' 📦' : ''}</span>`).join('')}
    <div class="classify">Absender:
      <button id="cl-spam" class="${sp ? 'on' : ''}">${sp ? 'unerwünscht' : 'als unerwünscht markieren'}</button>
      ${sp ? '<button id="cl-un">zurück nach Posteingang</button>' : ''}
      <button id="cl-del">löschen</button>
      <button id="cl-save">💾 Speichern unter</button>
      ${cn ? '' : '<button id="cl-ab">als Kontakt speichern</button>'}
    </div></div>`;
  document.querySelectorAll('.attach').forEach(el => el.addEventListener('click', async () => {
    // Etappe 7: reassemble chunked attachments from manifest + slices first.
    // The IndexedDB cache takes precedence: serves the attachment instantly and
    // permanently, even if the relay swept the blob long ago.
    const sha = el.getAttribute('data-sha')!, fname = el.getAttribute('data-name')!;
    const save = (blob: Blob) => {
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a'); a.href = url; a.download = fname; a.click();
    };
    try {
      save(new Blob([await attBytes({ sha256: sha, chunked: el.getAttribute('data-chunked') === '1' }) as BlobPart]));
    } catch (e: any) { alert('Download: ' + String(e?.message || e).slice(0, 120)); }
  }));
  $('cl-spam').onclick = () => { sp ? spamDel(m.sender) : spamAdd(m.sender); render(); };
  if ($('cl-un')) $('cl-un').onclick = () => { spamDel(m.sender); render(); };
  if ($('cl-ab')) $('cl-ab').onclick = () => { abSeed = { pubkey: m.pub }; folder = 'ab'; abEdit = 'new'; abSel = ''; mark(); render(); };
  $('cl-del').onclick = () => { if (sync) { sync.markDeleted(m.msgId); sync.push().catch(() => {}); } sel = -1; render(); };
  $('cl-save').onclick = async () => {
    const b = $('cl-save'); b.textContent = '… speichere';
    try { const msg = await saveMailAs(m); if (msg) b.textContent = msg.slice(0, 2) === '✓' ? msg : '✓ gespeichert'; }
    catch (e: any) { b.textContent = '✗ ' + String(e?.message || e).slice(0, 50); }
    setTimeout(() => { if (b) b.textContent = '💾 Speichern unter'; }, 4000);
  };
}

// --- Etappe A: address book (90s mail client: toolbar, contact list, properties window) ---
const abLabel = (c: Contact) => [c.name, c.given].filter(Boolean).join(", ") || c.lnaddr || c.email || "(ohne Namen)";
const contactFor = (pub: string) => sync?.liveContacts().find(c => c.pubkey && c.pubkey === pub);
const newId = () => Date.now().toString(36) + Math.random().toString(36).slice(2, 6); // randomUUID needs a secure context, we run LAN http
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

// Photo compression: longest edge 1600px, JPEG q0.82; if larger than the original -> original
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

// --- §30.4 satoshis enclosure: footer, chip, menu, dialog ---
const setPorto = () => {
  const el = $('portofuss'); if (!el) return;
  el.textContent = portoBase + (tipSats ? ` · ⚡ +${tipSats.toLocaleString('de')} Sats Beilage` : '');
};
function updateTipChip() {
  const chip = $('tip-chip'); if (!chip) return setPorto();
  chip.hidden = !tipSats;
  chip.innerHTML = `⚡ +${tipSats.toLocaleString('de')} Sats beigelegt <b>✕</b>`;
  chip.onclick = () => { tipSats = 0; updateTipChip(); };
  setPorto();
}
const attMenu = () => {
  const { body, close } = wizOverlay('📎 Beilegen', 340);
  body.innerHTML = `<div style="display:flex;flex-direction:column;gap:8px">
    <button id="am-file" style="padding:12px">📄 Datei anhängen</button>
    <button id="am-tip" style="padding:12px">⚡ Satoshis beilegen (max. 5.000)</button></div>`;
  body.querySelector('#am-file')!.addEventListener('click', () => { close(); ($('c-file') as HTMLInputElement).click(); });
  body.querySelector('#am-tip')!.addEventListener('click', () => { close(); openTipDialog(); });
};
const openTipDialog = () => {
  const { body, close } = wizOverlay('⚡ Satoshis beilegen', 360);
  body.innerHTML = `<p class="meta" style="margin:0 0 10px">Einmaliger Aufschlag im selben Brief — z. B. Rückporto für Antworten oder ein kleines Trinkgeld. Obergrenze 5.000 Sats.</p>
    <div style="display:flex;gap:6px"><input id="tip-in" type="number" min="0" max="5000" step="50" value="${tipSats || 500}" style="flex:1"><button id="tip-ok">OK</button></div>
    <div style="display:flex;gap:6px;margin-top:8px"><button class="tip-q" data-v="100">100</button><button class="tip-q" data-v="500">500</button><button class="tip-q" data-v="1000">1.000</button><button class="tip-q" data-v="5000">5.000</button></div>
    <p id="tip-err" style="margin:8px 0 0;color:#b00020;font-size:13px"></p>`;
  body.querySelectorAll('.tip-q').forEach(q => q.addEventListener('click', () => { (body.querySelector('#tip-in') as HTMLInputElement).value = (q as HTMLElement).dataset.v!; }));
  body.querySelector('#tip-ok')!.addEventListener('click', () => {
    const v = Math.floor(Number((body.querySelector('#tip-in') as HTMLInputElement).value));
    if (!Number.isFinite(v) || v < 0 || v > 5000) { (body.querySelector('#tip-err') as HTMLElement).textContent = 'Bitte 0–5.000 Sats eintragen.'; return; }
    tipSats = v; close(); updateTipChip();
  });
};

// Test/production marker: the regtest relays stay online as a playground — the
// client clearly sets them apart from the mainnet mailbox. The UI gets the network straight from the relay.
async function applyNetBadge(b: string) {
  let net = '';
  try { net = String(((await fetch(b + '/health').then(r => r.json())) as any).network || ''); } catch { return; }
  const test = !!net && net !== 'mainnet';
  const nb = document.getElementById('netbadge'); if (nb) nb.hidden = !test;
  const hdr = document.getElementById('hdr-net'); if (hdr) hdr.textContent = test ? `🧪 TEST (${net}) · Spielgeld` : (net === 'mainnet' ? '⚡ Mainnet' : '');
  const note = document.getElementById('w-signup-note'); if (note) note.hidden = !test;
}

async function renderCompose() {
  tipSats = 0; portoBase = 'Empfänger wählen — Porto und Fingerprint erscheinen hier.';
  $('detail').innerHTML = `<div class="card"><form class="compose" id="cform">
    <div style="display:flex;gap:6px"><input id="c-to" placeholder="An: name@domain" required style="flex:1"><button type="button" id="c-ab" title="Aus Adressbuch">📇</button></div>
    <input id="c-subj" placeholder="Betreff" required>
    <textarea id="c-body" placeholder="Nachricht…"></textarea>
    <div style="display:flex;gap:6px;align-items:center">
      <span class="att-split"><button type="button" id="c-att">📎 Anhang</button><button type="button" id="c-att-caret" title="Datei oder Satoshis beilegen" aria-label="Beilage-Menu">▾</button></span>
      <span id="tip-chip" class="tipchip" hidden></span>
    </div>
    <input type="file" id="c-file" multiple hidden>
    <label style="font-size:13px;color:var(--faint)"><input type="checkbox" id="c-orig"> Original senden (Fotos sonst auf 1600px JPEG komprimiert)</label>
    <label style="font-size:13px;color:var(--faint)"><input type="checkbox" id="c-signup"> Als Dienst-Registrierung senden (Tag 0x0A, zahlt Porto-Vorschuss)</label>
    <label style="font-size:13px;color:var(--faint)">🕰 Zustellung ab <input type="datetime-local" id="c-hold" style="font-size:13px"> <span class="meta">leer = sofort</span></label>
    <div id="portofuss" class="meta">Empfänger wählen — Porto und Fingerprint erscheinen hier.</div>
    <div><button type="submit">Senden</button> <button type="button" id="c-save">Als Entwurf speichern</button> <span id="c-msg" class="meta"></span></div>
  </form></div>`;

  const lookup = async () => {
    const name = $('c-to').value.trim().split('@')[0]; if (!name) return;
    const r = await fetch(`${base}/v1/profile/${name}`);
    if (!r.ok) { portoBase = errText(r.status); setPorto(); return; }
    const p = await r.json() as any;
    const fp = String(p.pubkey || '');
    portoBase = `Empfänger-Key ${fp.slice(0, 6)}…${fp.slice(-4)} · Porto ${p.foreign_sats} sats (Porto-Vorschuss: ${p.welcome_sats ?? p.foreign_sats * 3} sats)` +
      (fp.slice(0, 2) === '02' || fp.slice(0, 2) === '03' ? '' : ' · WARNUNG: seltsamer Key');
    setPorto();
  };
  $('c-to').addEventListener('change', lookup);
  // Split button: click/short tap = files (as before, 0 extra clicks);
  // long press (touch) or caret click = file/enclosure menu.
  // shortcut: 450 ms long-press threshold; if menus grow, switch to a long pointerdown intent.
  let pressT = 0;
  const att = $('c-att');
  att.addEventListener('pointerdown', () => { pressT = window.setTimeout(() => { pressT = 0; attMenu(); }, 450); });
  att.addEventListener('pointerup', () => { if (!pressT) return; clearTimeout(pressT); pressT = 0; ($('c-file') as HTMLInputElement).click(); });
  const attAbort = () => { if (pressT) { clearTimeout(pressT); pressT = 0; } };
  att.addEventListener('pointerleave', attAbort);
  att.addEventListener('pointercancel', attAbort);
  $('c-att-caret').onclick = attMenu;
  updateTipChip();
  // Etappe I (§28): deep link ?an=<adresse>&signup=1 → prefill the service registration
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
    if (!fs.length) { portoBase = 'Empfänger wählen — Porto und Fingerprint erscheinen hier.'; setPorto(); return; }
    // Etappe 7: byte-postage estimate from /health (price + daily rate)
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
    } catch { /* the estimate is a convenience, not an error case */ }
    portoBase = `${fs.length} Anhang: ` + fs.map(f => `${f.name} (${f.size > 1048576 ? (f.size / 1048576).toFixed(1) + ' MB' : Math.round(f.size / 1024) + ' kB'})`).join(', ') + cost;
    setPorto();
  });

  $('c-save').onclick = () => {
    if (!sync) { $('c-msg').textContent = '✗ ohne Sync keine Entwürfe'; return; }
    if (!draftId) draftId = Date.now().toString(36) + Math.random().toString(36).slice(2, 6); // randomUUID needs a secure context, we run LAN http
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
      const holdV = ($('c-hold') as HTMLInputElement).value;
      const holdTs = holdV ? Math.floor(new Date(holdV).getTime() / 1000) : 0; // Etappe TL: 0/past = sofort
      const out = await composeAndSend(base, token, priv!, { to: ($('c-to') as HTMLInputElement).value, subject: ($('c-subj') as HTMLInputElement).value, body: ($('c-body') as HTMLTextAreaElement).value, attachments: atts, signup: ($('c-signup') as HTMLInputElement).checked,
        notBefore: holdTs > Math.floor(Date.now() / 1000) ? holdTs : undefined,
        tipSats: tipSats || undefined,
        onProgress: (m) => { const e = $('c-msg'); if (e) e.textContent = m; } });
      sentPush({ ts: Math.floor(Date.now() / 1000), to: ($('c-to') as HTMLInputElement).value, subject: ($('c-subj') as HTMLInputElement).value, msg_id: String(out.msg_id || ''), bytes: total, body: ($('c-body') as HTMLTextAreaElement).value.slice(0, 2000) });
      if (draftId && sync) { sync.delDraft(draftId); draftId = ''; }
      tipSats = 0; updateTipChip(); // shortcut: the enclosure is deliberately not persisted in the draft
      $('c-msg').textContent = out.status === 'pending'
        ? '✓ wird nachgeliefert (Empfänger vorübergehend nicht erreichbar)'
        : holdTs > Math.floor(Date.now() / 1000)
        ? '✓ Brief im Tresor — Zustellung ab ' + new Date(holdTs * 1000).toLocaleString()
        : '✓ gesendet (' + (out.msg_id || '').slice(0, 10) + '…)';
      await refreshBalance();
    } catch (e: any) {
      const m0 = String(e.message || e);
      const st = /: (\d{3}) /.exec(m0);
      $('c-msg').textContent = '✗ ' + (st ? errText(+st[1], m0) : m0.slice(0, 120));
    }
  };
}

const hintFromFilename = (fname: string): string => {
  const m = /(?:^|lightningmail-)([a-z0-9][a-z0-9._-]{1,31}?)(?:\s*\(\d+\))?\.(?:lmkey|key|pem)/i.exec(fname || '');
  return m ? m[1].toLowerCase() : '';
};

function openPassModal(wrappedTxt: string, fname = '') {
  pendingWrap = wrappedTxt;
  const { body, close } = wizOverlay('🔓 Schlüsseldatei entsperren', 430);
  body.innerHTML = `<p class="meta" style="margin:0 0 8px">${fname ? `Datei <b>${esc(fname)}</b> geladen.` : 'Geschützter Schlüssel geladen.'} Bitte gib dein Passwort ein:</p>
    <div style="display:flex;gap:6px;align-items:center">
      <input type="password" id="pm-pass" placeholder="Passwort eingeben…" autocomplete="current-password" style="flex:1;font-size:1.02em">
      <button type="button" id="pm-eye" title="Passwort ein-/ausblenden" style="padding:9px 12px;flex:0 0 auto">👁</button>
    </div>
    ${ERRROW}
    <div class="row" style="margin-top:14px">
      <button type="button" id="pm-go" style="flex:2;background:var(--navy);color:#fff;border-color:var(--navy);padding:11px 16px">🔓 Entsperren &amp; Anmelden</button>
      <button type="button" id="w-x">Abbrechen</button>
    </div>`;
  $('w-x').onclick = close;
  const inp = $('pm-pass') as HTMLInputElement;
  $('pm-eye').onclick = () => {
    inp.type = inp.type === 'password' ? 'text' : 'password';
    inp.focus();
  };
  setTimeout(() => inp.focus(), 40);
  const submit = async () => {
    const pw = inp.value;
    if (!pw) { $('w-err').textContent = 'Bitte Passwort eingeben.'; inp.focus(); return; }
    const btn = $('pm-go') as HTMLButtonElement;
    btn.disabled = true;
    btn.textContent = '⏳ Entschlüssele…';
    $('w-err').textContent = '';
    await new Promise((r) => setTimeout(r, 20));
    let pem = '';
    try {
      pem = unwrapKey(wrappedTxt, pw);
    } catch (e: any) {
      btn.disabled = false;
      btn.textContent = '🔓 Entsperren & Anmelden';
      $('w-err').textContent = '✗ ' + String(e?.message || 'Passwort falsch');
      inp.focus();
      inp.select();
      return;
    }
    btn.textContent = '⏳ Melde an…';
    const ok = await loginAuto(pem, hintFromFilename(fname), (errMsg) => { $('w-err').textContent = '✗ ' + errMsg; });
    if (ok) {
      close();
    } else {
      btn.disabled = false;
      btn.textContent = '🔓 Entsperren & Anmelden';
    }
  };
  $('pm-go').onclick = submit;
  inp.onkeydown = (e) => { if (e.key === 'Enter') { e.preventDefault(); submit(); } };
}

async function useKey(rawTxt: string, fname = '') {
  const txt = (rawTxt || '').replace(/^\uFEFF/, '').trim();
  if (!txt) { setLoginStatus('✗ Die ausgewählte Datei ist leer.'); return; }
  const lbl = document.getElementById('l-file-lbl');
  if (lbl && fname) lbl.textContent = '📂 ' + fname;
  const hint = hintFromFilename(fname);
  if (hint) ($('l-acct') as HTMLInputElement).value = hint;

  if (isWrapped(txt)) {
    if (txt.startsWith('LMKEY1$PRF$')) {
      setLoginStatus('✗ Diese Datei gehört zu einem Hardware-Passkey — bitte oben „🔑 Mit Fingerabdruck / Passkey anmelden" nutzen.');
      return;
    }
    setLoginStatus('', false);
    openPassModal(txt, fname);
    return;
  }
  if (txt.includes('PRIVATE' + ' KEY')) {
    setLoginStatus('⏳ Schlüssel erkannt — melde automatisch an…', false);
    await loginAuto(txt, hint);
    return;
  }
  const maybeMn = checkMnemonic(txt);
  if (maybeMn) {
    setLoginStatus('⏳ 24 Backup-Wörter erkannt — melde automatisch an…', false);
    await loginAuto(sec1PEM(keyFromMnemonic(maybeMn)), hint);
    return;
  }
  setLoginStatus(`✗ „${fname || 'Datei'}“ ist keine gültige lightningmail-Schlüsseldatei (.lmkey / .key).`);
}

// PRF self-healing (§21): credential ID + PRF secret of the last assertion,
// upgraded once to direct fingerprint after the last passphrase login.
let waUpgrade: { credID: string; secret: Uint8Array } | null = null;

async function tryUnwrap() {
  try {
    pemCache = unwrapKey(pendingWrap, ($('l-pass') as HTMLInputElement).value);
    const hadToken = !!token;
    await loginAuto(pemCache);
    if (waUpgrade && !hadToken) {
      const u = waUpgrade; waUpgrade = null;
      try {
        const uh: Record<string, string> = { 'Content-Type': 'application/json' };
        uh['Auth' + 'orization'] = 'Bearer ' + token;
        const ur = await fetch(base + '/v1/webauthn/wrap-upgrade', {
          method: 'POST',
          headers: uh,
          body: JSON.stringify({ cred_id: u.credID, wrap_prf: wrapKeyPRF(pemCache, u.secret) }) });
        if (ur.ok) setTimeout(() => alert('✓ Passkey upgraded — beim nächsten Mal reicht der reine Fingerabdruck.'), 400);
      } catch { /* the upgrade is a convenience, not an error case */ }
    }
  } catch (e: any) { setLoginStatus('✗ ' + e.message); }
}
if (document.getElementById('l-pass')) ($('l-pass') as HTMLInputElement).onkeydown = (e) => { if (e.key === 'Enter') { e.preventDefault(); tryUnwrap(); } };
// --- Etappe 6d (§27): setup wizard — 24-word recovery (BIP39), key in the browser,
// word quiz as backup proof, .lmkey file OPTIONAL (the words are the main backup).
// The order keeps the ecd07eb lesson: backup exists BEFORE account creation → no orphan account.
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
  base = relayVal(); // before login, base is still the default
  const mn = newMnemonic();
  const { body, close } = wizOverlay('✨ Neues lightningmail-Postfach anlegen', 540);
  const setErr = (t: string) => { const e = $('w-err'); if (e) e.textContent = t; };
  const wireCancel = () => { const x = document.getElementById('w-x'); if (x) x.onclick = close; };
  const stepsBar = (step: 1 | 2 | 3) => `<div class="wiz-steps">
    <span class="wiz-step ${step === 1 ? 'active' : 'done'}">1. Wunschadresse</span>
    <span class="wiz-step ${step === 2 ? 'active' : step > 2 ? 'done' : ''}">2. 24 Backup-Wörter</span>
    <span class="wiz-step ${step === 3 ? 'active' : ''}">3. Kurzer Check</span>
  </div>`;

  // Step 1: desired address
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

  // Step 2: the 24 words
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

  // Step 3: word quiz -> creates the account immediately after the 3rd correct word
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
      await login(pem, nm, base);
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

// Recovery: 24 words → key derivation in the browser → finds account & server automatically!
function openRestore() {
  const { body, close } = wizOverlay('🌱 Mit 24 Backup-Wörtern anmelden', 480);
  body.innerHTML = `<p class="meta" style="margin:0 0 8px">Gib deine 24 Wörter ein — dein Schlüssel wird lokal berechnet und dein Postfach automatisch gefunden (kein Kontoname nötig):</p>
    <label for="r-words">24 Backup-Wörter</label>
    <textarea id="r-words" rows="4" placeholder="wort1 wort2 wort3 …" autocapitalize="none" autocomplete="off" spellcheck="false" style="width:100%;margin-top:4px;font-family:var(--mono)"></textarea>
    ${ERRROW}
    <div class="row" style="margin-top:12px">
      <button id="r-go" type="button" style="flex:2;padding:11px 16px">🔓 Postfach öffnen</button>
      <button id="w-x" type="button">Abbrechen</button>
    </div>`;
  $('w-x').onclick = close;
  setTimeout(() => ($('r-words') as HTMLTextAreaElement)?.focus(), 40);
  $('r-go').onclick = async () => {
    const mn = checkMnemonic(($('r-words') as HTMLTextAreaElement).value);
    if (!mn) { $('w-err').textContent = '✗ Wörter ungültig — bitte alle 24 Wörter prüfen (Tippfehler oder falsche Reihenfolge).'; return; }
    const btn = $('r-go') as HTMLButtonElement;
    btn.disabled = true;
    btn.textContent = '⏳ Suche Postfach…';
    $('w-err').textContent = '';
    const pem = sec1PEM(keyFromMnemonic(mn));
    const ok = await loginAuto(pem, '', (errMsg) => { $('w-err').textContent = '✗ ' + errMsg; });
    if (ok) close();
    else { btn.disabled = false; btn.textContent = '🔓 Postfach öffnen'; }
  };
}
$('l-signup').onclick = openWizard;
if ($('l-words')) $('l-words').onclick = openRestore;

const readFileText = (f: File): Promise<string> => new Promise((res, rej) => {
  const fr = new FileReader();
  fr.onload = () => res(String(fr.result || ''));
  fr.onerror = () => rej(new Error('Datei konnte nicht gelesen werden'));
  fr.readAsText(f);
});

const decodeUtf8B64 = (b64: string): string =>
  new TextDecoder().decode(Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)));

// Android APK: direct file callback from the Java ContentResolver (bypasses all WebView file bugs)
(window as any).onNativeKeyFile = (nameB64: string, dataB64: string) => {
  try {
    const fname = decodeUtf8B64(nameB64);
    const txt = decodeUtf8B64(dataB64);
    useKey(txt, fname);
  } catch (e: any) {
    setLoginStatus('✗ Datei konnte nicht verarbeitet werden: ' + String(e?.message || e));
  }
};
(window as any).onNativeKeyFileErr = (msg: string) => {
  setLoginStatus('✗ Datei-Auswahl fehlgeschlagen: ' + msg);
};

// On Android bind the native file picker directly to #l-file-wrap (no WebView <input> detour)
if ((window as any).AndroidNative?.pickKeyFile) {
  ($('l-file') as HTMLInputElement).style.display = 'none';
  const fw = document.getElementById('l-file-wrap');
  if (fw) {
    fw.removeAttribute('for');
    fw.onclick = (ev) => {
      ev.preventDefault();
      (window as any).AndroidNative.pickKeyFile();
    };
  }
}
$('l-file').addEventListener('click', (ev) => {
  const an = (window as any).AndroidNative;
  if (an?.pickKeyFile) {
    ev.preventDefault();
    ev.stopPropagation();
    an.pickKeyFile();
    return;
  }
  (ev.currentTarget as HTMLInputElement).value = '';
});

$('l-file').onchange = async (ev: Event) => {
  const f = (ev.target as HTMLInputElement).files?.[0];
  if (!f) return;
  try {
    const txt = await readFileText(f);
    await useKey(txt, f.name);
  } catch (e: any) {
    setLoginStatus('✗ Fehler beim Lesen der Datei: ' + String(e?.message || e));
  }
};

// Desktop convenience: just drag & drop the key file onto the login card
const loginCard = document.getElementById('login');
if (loginCard) {
  loginCard.addEventListener('dragover', (e) => { e.preventDefault(); });
  loginCard.addEventListener('drop', async (e) => {
    e.preventDefault();
    const f = e.dataTransfer?.files?.[0];
    if (!f) return;
    try { await useKey(await readFileText(f), f.name); }
    catch (err: any) { setLoginStatus('✗ Drag & Drop fehlgeschlagen: ' + String(err?.message || err)); }
  });
}

$('l-login').onclick = async () => {
  if (!pemCache) { setLoginStatus('Bitte zuerst eine Schlüsseldatei wählen.'); return; }
  await loginAuto(pemCache);
};

// --- Etappe 6: passkey/WebAuthn login + registration (CONCEPT §21) ---
const passkeyAvailable = (): boolean => window.isSecureContext && !!(window as any).PublicKeyCredential;

const b64u = (buf: ArrayBuffer | Uint8Array): string => {
  const b = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  return btoa(String.fromCharCode(...b)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};
const b64uDec = (s: string): Uint8Array => {
  const p = s.replace(/-/g, '+').replace(/_/g, '/');
  return Uint8Array.from(atob(p + '='.repeat((4 - (p.length % 4)) % 4)), (c) => c.charCodeAt(0));
};
// Server options (JSON, b64url) -> WebAuthn API (ArrayBuffer fields)
const decodeOpts = (o: any): any => {
  o.challenge = b64uDec(o.challenge).slice().buffer;
  if (o.user?.id) o.user.id = b64uDec(o.user.id).slice().buffer;
  for (const c of o.excludeCredentials || []) c.id = b64uDec(c.id).slice().buffer;
  for (const c of o.allowCredentials || []) c.id = b64uDec(c.id).slice().buffer;
  // The PRF salt arrives base64url from the server; the WebAuthn API wants ArrayBuffer
  // (prf.eval.first IS the salt, no .salt subfield)
  const ev = o.extensions?.prf?.eval;
  if (ev) for (const k of ['first', 'second']) {
    if (typeof ev[k] === 'string') ev[k] = b64uDec(ev[k]).slice().buffer;
  }
  return o;
};
// Credential response -> JSON for go-webauthn (b64url, empty fields dropped)
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

// Helper for the native Android fingerprint dialog (BiometricPrompt)
function androidBiometricAuth(): Promise<boolean> {
  return new Promise((resolve) => {
    const an = (window as any).AndroidNative;
    if (!an?.requestBiometricAuth) { resolve(false); return; }
    (window as any).onNativeBioResult = (ok: boolean, err: string) => {
      if (!ok && err) setLoginStatus('✗ Fingerabdruck: ' + err);
      resolve(!!ok);
    };
    an.requestBiometricAuth();
  });
}

type AndroidVaultInfo = {
  hasVault: boolean;
  bioBound?: boolean;
  legacy?: boolean;
  backend?: string;
  strongBox?: boolean;
  strongBio?: boolean;
  acct?: string;
  base?: string;
};

function androidVaultInfo(): AndroidVaultInfo {
  try {
    const an = (window as any).AndroidNative;
    if (an?.vaultInfo) return JSON.parse(an.vaultInfo() || '{"hasVault":false}');
  } catch { /* ignore bridge parse errors */ }
  return { hasVault: false };
}

function vaultBackendLabel(backend?: string): string {
  if (backend === 'strongbox') return 'StrongBox / Sicherheitschip';
  if (backend === 'tee') return 'TEE / Hardware-Keystore';
  return 'Hardware-Keystore';
}

function androidSealVault(json: string, a: string, b: string): Promise<{ ok: boolean; backend: string; err: string }> {
  return new Promise((resolve) => {
    const an = (window as any).AndroidNative;
    if (!an?.sealVaultBiometric) { resolve({ ok: false, backend: '', err: '' }); return; }
    (window as any).onNativeVaultSealed = (ok: boolean, backend: string, err: string) => {
      resolve({ ok: !!ok, backend: backend || '', err: err || '' });
    };
    an.sealVaultBiometric(json, a, b);
  });
}

function androidUnlockVault(): Promise<{ ok: boolean; data: { acct: string; base: string; pem: string } | null; err: string }> {
  return new Promise((resolve) => {
    const an = (window as any).AndroidNative;
    if (!an?.unlockVaultBiometric) { resolve({ ok: false, data: null, err: '' }); return; }
    (window as any).onNativeVaultUnlocked = (ok: boolean, dataB64: string, err: string) => {
      if (!ok || !dataB64) {
        if (err && err !== 'Abgebrochen') setLoginStatus('✗ ' + err);
        resolve({ ok: false, data: null, err: err || '' });
        return;
      }
      try {
        const obj = JSON.parse(decodeUtf8B64(dataB64));
        resolve({ ok: !!(obj && obj.pem && obj.acct && obj.base), data: obj, err: '' });
      } catch (e: any) {
        resolve({ ok: false, data: null, err: String(e?.message || e) });
      }
    };
    an.unlockVaultBiometric();
  });
}

function askAccountForPasskey(): Promise<string> {
  return new Promise((resolve) => {
    const { body, close } = wizOverlay('🔑 Mit Passkey anmelden', 400);
    const saved = loadLastUser()?.acct || '';
    body.innerHTML = `<p class="meta" style="margin:0 0 8px">Wie lautet dein lightningmail-Kontoname? (Wird danach auf diesem Gerät gemerkt.)</p>
      <input id="pk-acct" value="${esc(saved)}" placeholder="z. B. bernd" autocapitalize="none" autocomplete="username" style="font-size:1.02em">
      ${ERRROW}
      <div class="row" style="margin-top:12px">
        <button type="button" id="pk-go" style="flex:2;background:var(--navy);color:#fff;border-color:var(--navy);padding:11px 16px">Weiter zum Passkey →</button>
        <button type="button" id="w-x">Abbrechen</button>
      </div>`;
    $('w-x').onclick = () => { close(); resolve(''); };
    const inp = $('pk-acct') as HTMLInputElement;
    setTimeout(() => inp.focus(), 40);
    const go = () => {
      const v = inp.value.trim().toLowerCase().split('@')[0];
      if (!v) { $('w-err').textContent = 'Bitte Kontoname eingeben.'; return; }
      ($('l-acct') as HTMLInputElement).value = v;
      close();
      resolve(v);
    };
    $('pk-go').onclick = go;
    inp.onkeydown = (e) => { if (e.key === 'Enter') { e.preventDefault(); go(); } };
  });
}

async function passkeyLogin() {
  setLoginStatus('', false);
  // 1) In the Android APK: hardware-bound CryptoObject BiometricPrompt unlocks StrongBox/TEE vault
  const an = (window as any).AndroidNative;
  if (an?.unlockVaultBiometric && an?.vaultInfo) {
    const vi = androidVaultInfo();
    if (vi.hasVault) {
      if (vi.legacy && !vi.bioBound && an.requestBiometricAuth) {
        if (!(await androidBiometricAuth())) return;
      }
      const res = await androidUnlockVault();
      if (res.ok && res.data) {
        await login(res.data.pem, res.data.acct, res.data.base);
      }
      return;
    }
    if (!passkeyAvailable()) {
      setLoginStatus('Noch kein Konto auf diesem Handy gespeichert — bitte einmalig mit „📂 Schlüsseldatei" oder „🌱 24 Backup-Wörtern" anmelden. Ab danach klappt der Fingerabdruck sofort!', false);
      return;
    }
  } else if (an?.loadVault) {
    try {
      const nv = JSON.parse(an.loadVault() || 'null');
      if (nv && nv.pem && nv.acct && nv.base) {
        if (an.requestBiometricAuth) {
          const ok = await androidBiometricAuth();
          if (!ok) return;
        }
        await login(nv.pem, nv.acct, nv.base);
        return;
      }
      if (!passkeyAvailable()) {
        setLoginStatus('Noch kein Konto auf diesem Handy gespeichert — bitte einmalig mit „📂 Schlüsseldatei" oder „🌱 24 Backup-Wörtern" anmelden. Ab danach klappt der Fingerabdruck sofort!', false);
        return;
      }
    } catch { /* fall back to WebAuthn */ }
  }
  let targetAcct = ($('l-acct') as HTMLInputElement).value.trim().toLowerCase().split('@')[0] || loadLastUser()?.acct || '';
  if (!targetAcct) {
    targetAcct = await askAccountForPasskey();
    if (!targetAcct) return;
  }
  const candidates = relayCandidates();
  let begin: any = null;
  let chosenBase = '';
  let lastErr = '';
  for (const cand of candidates) {
    try {
      const br = await fetch(cand + '/v1/webauthn/login/begin', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ address: targetAcct }) });
      const j = await br.json().catch(() => ({}));
      if (br.ok) { begin = j; chosenBase = cand; break; }
      lastErr = j.error || errText(br.status);
      if (br.status !== 404) break;
    } catch (e: any) { lastErr = String(e?.message || e); }
  }
  if (!begin || !chosenBase) {
    // If an old remembered name had no passkey -> have the name asked once
    if (!($('l-acct') as HTMLInputElement).value.trim() && loadLastUser()?.acct) {
      localStorage.removeItem(LAST_USER_KEY);
    }
    setLoginStatus('✗ ' + (lastErr || 'Kein Passkey für dieses Konto gefunden.'));
    return;
  }
  try {
    acct = targetAcct; base = chosenBase;
    const opts = decodeOpts(begin.options.publicKey);
    const cred = await navigator.credentials.get({ publicKey: opts });
    const ext: any = (cred as any).getClientExtensionResults?.() || {};
    const prfSecret = ext.prf?.first ? new Uint8Array(ext.prf.first) : null;
    const fr = await fetch(chosenBase + '/v1/webauthn/login/finish', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ address: targetAcct, sid: begin.sid, credential: cred2json(cred) }) });
    const fin = await fr.json().catch(() => ({}));
    if (!fr.ok) { setLoginStatus('✗ ' + (fin.error || errText(fr.status))); return; }
    if (fin.wrap_prf && prfSecret) {
      pemCache = unwrapKeyPRF(fin.wrap_prf, prfSecret);
      await login(pemCache, targetAcct, chosenBase);
    } else if (fin.wrap_pass) {
      // Self-healing (§21): the device supports PRF but the credential only has a
      // passphrase wrap -> after this last passphrase login, upgrade the wrap to direct fingerprint.
      waUpgrade = prfSecret && fin.cred_id ? { credID: String(fin.cred_id), secret: prfSecret } : null;
      openPassModal(fin.wrap_pass, `Passkey (${targetAcct})`);
    } else {
      setLoginStatus('✗ Dieser Passkey hat keinen Schlüssel-Wrap. Einmal per Schlüsseldatei/24 Wörtern anmelden und oben über „🔑 Passkey" neu speichern.');
    }
  } catch (e: any) {
    setLoginStatus('✗ ' + String(e?.message || e).slice(0, 140));
  }
}
$('l-passkey').onclick = passkeyLogin;

async function passkeyRegister() {
  // 1) In the Android APK: seal key with hardware-bound CryptoObject BiometricPrompt (StrongBox -> TEE)
  const an = (window as any).AndroidNative;
  if (an?.sealVaultBiometric) {
    const res = await androidSealVault(JSON.stringify({ acct, base, pem: pemCache }), acct, base);
    if (!res.ok) {
      if (res.err && res.err !== 'Abgebrochen') alert('✗ Tresor konnte nicht gesichert werden: ' + res.err);
      return;
    }
    const vi = androidVaultInfo();
    const bioTxt = vi.bioBound ? ', hardwaregebundene Biometrie' : '';
    alert(`✓ Hardware-Tresor für ${acct} aktiviert (${vaultBackendLabel(res.backend)}${bioTxt})!\nBeim nächsten Mal reicht ein Tipp auf „🔑 Mit Passkey / Fingerabdruck anmelden".`);
    return;
  }
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
if ($('nav-sent')) $('nav-sent').onclick = () => { folder = 'out'; sel = -1; mark(); Promise.all([fetchReceipts(), fetchOutbox()]).then(() => render()); };
if ($('nav-dra')) $('nav-dra').onclick = () => { folder = 'dra'; sel = -1; mark(); render(); };
$('nav-new').onclick = () => { folder = 'new'; draftId = ''; mark(); render(); };
$('nav-ab').onclick = () => { folder = 'ab'; sel = -1; abEdit = ''; mark(); render(); };
if ($('nav-drv')) $('nav-drv').onclick = () => { folder = 'drv'; sel = -1; mark(); render(); };
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
  if ($('nav-drv')) $('nav-drv').classList.toggle('on', folder === 'drv');
  if ($('nav-ums')) $('nav-ums').classList.toggle('on', folder === 'ums');
}

// --- Etappe G2 (§25): statements — monthly list from /v1/statement + CSV button.
// No new subsystem: just reads the statement, the EUR column comes from the server. ---
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

  // ⚡ Top up: fetch a Bolt11 invoice from the relay (credit happens after settlement)
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

  // 📤 Withdraw: paste a Bolt11 invoice, the relay pays it from the balance
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
      await renderUms(); // reload the statements …
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

// --- Etappe J3/J4: 🗂 drive — encrypted storage on your own relay. ---
// Logic lives DOM-free in src/drive.ts; folder switching renders purely from the
// local stateDoc (renderUms pattern), saveFile/delFile trigger the existing
// debounced state push. Design: navy/parchment/gold, touch ≥44px (CSS in index.html).
let drvDir = 'root', drvNew = false, drvRen = '', drvOff = false, drvMsg = '';
let drvUse: DriveUsage | null = null;
const sizeHuman = (n: number): string =>
  n >= 1073741824 ? (n / 1073741824).toLocaleString('de', { maximumFractionDigits: 1 }) + ' GB'
  : n >= 1048576 ? (n / 1048576).toLocaleString('de', { maximumFractionDigits: 1 }) + ' MB'
  : n >= 1024 ? Math.round(n / 1024) + ' kB' : n + ' B';
const DRV_NAME = /^[^/]{1,100}$/; // no '/', 1–100 chars
const drvStatus = (m: string) => { const el = $('drv-status'); if (el) el.textContent = m; };

// Upload: input + drag&drop, sequential. shortcut: no multi-upload queue
// manager, sequential for-of; upgrade if users demand large batches.
async function drvUpload(fs: File[]) {
  if (!sync || !priv || !token || drvOff) return;
  for (const f of fs) {
    drvStatus(`⏳ „${f.name}“ lädt hoch…`);
    try {
      await uploadFile(base, token, priv, sync, new Uint8Array(await f.arrayBuffer()),
        safeName(f.name), f.type || 'application/octet-stream', drvDir, drvStatus);
      drvStatus(`✓ „${f.name}“ hochgeladen`);
    } catch (e: any) { drvStatus('✗ ' + String(e?.message || e).slice(0, 120)); }
  }
  refreshBalance().catch(() => {}); // byte postage of the blobs
  renderDrv(); // fresh list + quota bar
}

function renderDrvDetail(e?: DriveEntry) {
  const tiers = drvUse && !drvOff && drvUse.tiers.length ? `<div class="window" style="max-width:72ch;margin-top:14px">
    <div class="title-bar"><div class="title-bar-text">💾 Speicher erweitern</div></div>
    <div class="window-body"><p class="meta">Mehr Quota für dein Laufwerk — einmaliger Kauf vom Guthaben.</p>
    <div class="row" style="margin-top:6px">${drvUse.tiers.map((t, i) => `<button class="d-tier" data-tier="${i}">＋ ${t.gb} GB — ${fmtSat(t.sats)} sats</button>`).join('')}</div>
    <p class="meta" style="color:var(--ok)">${esc(drvMsg)}</p></div></div>` : '';
  $('detail').innerHTML = (e && !e.gone ? `<div class="window" style="max-width:72ch">
      <div class="title-bar"><div class="title-bar-text">${e.kind === 'd' ? '📁 Ordner' : '📄 Datei'} — ${esc(e.name)}</div></div>
      <div class="window-body"><p class="meta">${e.kind === 'f'
        ? `Gespeichert: ${sizeHuman(e.size)} (verschlüsselt, quota-relevant)<br>Original: ${sizeHuman(e.size_plain)}<br>Typ: ${esc(e.mime || '—')}<br>Blob: <span style="font-family:var(--mono)">${esc((e.msha || '').slice(0, 16))}…</span><br>`
        : ''}Geändert: ${new Date(e.ts * 1000).toLocaleString('de')}</p></div></div>`
    : `<p class="meta">🗂 Laufwerk: Dateien liegen mit deinem Mailbox-Schlüssel verschlüsselt auf deinem Relay und synchronisieren über den State-Slot zwischen all deinen Geräten. Datei antippen für Details — oder Dateien per Drag &amp; Drop in die Liste ziehen.</p>${drvMsg ? `<p class="meta" style="color:var(--ok)">${esc(drvMsg)}</p>` : ''}`) + tiers;
  document.querySelectorAll('.d-tier').forEach(b => b.addEventListener('click', async () => {
    drvMsg = '';
    try {
      const out = await buyTier(base, token, +(b as HTMLElement).dataset.tier!);
      drvMsg = `✓ ${fmtSat(out.cost_sats)} sats bezahlt — Quota ist jetzt ${sizeHuman(out.quota_bytes)}.`;
      await refreshBalance();
      renderDrv();
    } catch (err: any) { drvMsg = '✗ ' + String(err?.message || err).slice(0, 120); renderDrvDetail(e); }
  }));
}

async function renderDrv() {
  const list = $('list');
  drvOff = false;
  list.innerHTML = '<div class="meta" style="padding:12px">Laufwerk wird geladen…</div>';
  if (!sync || !priv || !token) { list.innerHTML = '<div class="meta" style="padding:12px">✗ nicht angemeldet</div>'; $('detail').innerHTML = ''; return; }
  drvUse = null;
  let useErr = '';
  try { drvUse = await driveUsage(base, token); } catch (e: any) { useErr = String(e?.message || e).slice(0, 140); }
  try { healthCache ??= await fetch(base + '/health').then(r => r.json()); } catch { /* healthCache is a convenience */ }
  drvOff = drvUse ? !drvUse.enabled : !!(healthCache?.drive && healthCache.drive.enabled === false);

  const ents = sync.liveFiles();
  const byId: Record<string, DriveEntry> = {};
  for (const e of ents) byId[e.id] = e;
  if (drvDir !== 'root' && !byId[drvDir]) drvDir = 'root'; // folder deleted elsewhere
  const chain: DriveEntry[] = [];
  for (let cur = byId[drvDir]; cur && chain.length < 64; cur = byId[cur.parent]) chain.unshift(cur);
  const kids = ents.filter(e => e.parent === drvDir)
    .sort((a, b) => a.kind === b.kind ? a.name.localeCompare(b.name, 'de') : a.kind === 'd' ? -1 : 1);
  const pct = drvUse && drvUse.quota_bytes > 0 ? Math.min(100, drvUse.used_bytes / drvUse.quota_bytes * 100) : 0;

  list.innerHTML =
    `<div class="abbar drvbar">` +
    [`<button class="crumb" data-go="root" title="Wurzelordner">🏠</button>`,
     ...chain.map(c => `<span class="meta">/</span><button class="crumb" data-go="${c.id}">${esc(c.name)}</button>`)].join('') +
    `</div>` +
    (drvOff ? '<div class="drvoff">🗂 Laufwerk ist auf diesem Relay deaktiviert.</div>' : '') +
    `<div class="abbar"><button id="d-up" ${drvOff ? 'disabled' : ''}>⬆ Datei</button>
      <button id="d-mkdir" ${drvOff ? 'disabled' : ''}>＋ Ordner</button>
      <span id="drv-status" class="meta" style="align-self:center;flex:1;min-width:80px"></span>
      <input type="file" id="d-file" multiple hidden></div>` +
    (drvUse ? `<div class="drvquota"><div class="drvquota-fill" style="width:${pct.toFixed(1)}%"></div>
      <span class="drvquota-txt">${sizeHuman(drvUse.used_bytes)} von ${sizeHuman(drvUse.quota_bytes)}</span></div>`
      : useErr ? `<div class="drvoff">✗ ${esc(useErr)}</div>` : '') +
    (drvNew ? `<div class="row"><input id="d-newname" placeholder="Ordnername… (Enter = OK, Esc = Abbruch)"></div>` : '') +
    (kids.map(e => `<div class="row drvrow" data-id="${e.id}">
      <div class="subj">${e.kind === 'd' ? '📁' : '📄'} ${drvRen === e.id
        ? `<input class="d-ren" data-id="${e.id}" value="${esc(e.name)}">`
        : `${esc(e.name)} <button class="minib" data-ren="${e.id}" title="Umbenennen">✏️</button>`}</div>
      <div class="meta">${e.kind === 'f' ? sizeHuman(e.size) + ' · ' : ''}${new Date(e.ts * 1000).toLocaleDateString('de')}` +
      (e.kind === 'f' && !drvOff ? ` <button class="minib" data-dl="${e.id}" title="Herunterladen">⬇</button> <button class="minib" data-del="${e.id}" title="Löschen">🗑</button>`
        : e.kind === 'd' ? ` <button class="minib" data-del="${e.id}" title="Löschen">🗑</button>` : '') +
      `</div></div>`).join('') ||
      (drvOff ? '' : '<div class="meta drvempty">— dieser Ordner ist leer —<br>⬆ Datei hochladen oder hierher ziehen</div>'));

  // Breadcrumb navigation (parent chain)
  list.querySelectorAll('[data-go]').forEach(b => b.addEventListener('click', () => {
    drvDir = (b as HTMLElement).dataset.go!; drvNew = false; drvRen = ''; renderDrv();
  }));
  $('d-up').onclick = () => ($('d-file') as HTMLInputElement).click();
  const dfile = $('d-file') as HTMLInputElement;
  dfile.onchange = () => { const fs = [...(dfile.files || [])] as File[]; dfile.value = ''; if (fs.length) drvUpload(fs); };
  // ＋ Folder: inline row instead of native prompt() (headless test trap)
  $('d-mkdir').onclick = () => { drvNew = true; drvRen = ''; renderDrv(); setTimeout(() => ($('d-newname') as HTMLInputElement)?.focus(), 30); };
  if (drvNew) {
    const inp = $('d-newname') as HTMLInputElement;
    inp.onkeydown = (ev) => {
      if (ev.key === 'Enter') {
        const n = inp.value.trim();
        if (!DRV_NAME.test(n)) { inp.value = ''; inp.placeholder = 'Ungültig: kein „/", 1–100 Zeichen'; return; }
        sync!.saveFile({ id: newDriveId(), name: n, parent: drvDir, kind: 'd', size: 0, size_plain: 0, mime: '' });
        drvNew = false; renderDrv();
      } else if (ev.key === 'Escape') { drvNew = false; renderDrv(); }
    };
  }
  // ✏️ Rename inline (Enter = save, Esc = cancel), name validation ^[^/]{1,100}$
  list.querySelectorAll('[data-ren]').forEach(b => b.addEventListener('click', (ev) => {
    ev.stopPropagation(); drvRen = (b as HTMLElement).dataset.ren!; drvNew = false; renderDrv();
    setTimeout(() => { const i = document.querySelector('.d-ren') as HTMLInputElement; i?.focus(); i?.select(); }, 30);
  }));
  list.querySelectorAll('.d-ren').forEach(inp => {
    const el = inp as HTMLInputElement;
    el.addEventListener('click', (ev) => ev.stopPropagation());
    el.onkeydown = (ev) => {
      if (ev.key === 'Enter') {
        const n = el.value.trim();
        if (!DRV_NAME.test(n)) return;
        sync!.saveFile({ id: el.dataset.id!, name: n });
        drvRen = ''; renderDrv();
      } else if (ev.key === 'Escape') { drvRen = ''; renderDrv(); }
    };
  });
  // ⬇ Download: chunk download + decrypt from drive.ts, browser download like the
  // attachment path (reuses safeName from §31).
  list.querySelectorAll('[data-dl]').forEach(b => b.addEventListener('click', async (ev) => {
    ev.stopPropagation();
    const e = sync!.doc.files[(b as HTMLElement).dataset.dl!]; if (!e) return;
    drvStatus(`⏳ „${e.name}“ lädt herunter…`);
    try {
      const bytes = await downloadFile(base, token, priv!, sync!, e.id);
      const url = URL.createObjectURL(new Blob([bytes as BlobPart], { type: e.mime || 'application/octet-stream' }));
      const a = document.createElement('a'); a.href = url; a.download = safeName(e.name); a.click();
      setTimeout(() => URL.revokeObjectURL(url), 6000);
      drvStatus(`✓ „${e.name}“ heruntergeladen`);
    } catch (err: any) { drvStatus('✗ ' + String(err?.message || err).slice(0, 120)); }
  }));
  // 🗑 Delete: native confirm() is fine here (spec) — server release BEFORE the tombstone.
  list.querySelectorAll('[data-del]').forEach(b => b.addEventListener('click', async (ev) => {
    ev.stopPropagation();
    const e = sync!.doc.files[(b as HTMLElement).dataset.del!]; if (!e) return;
    if (!confirm(`„${e.name}“ endgültig löschen?`)) return;
    drvStatus('🗑 gebe Serverdaten frei…');
    try { await deleteFile(base, token, sync!, e.id); }
    catch (err: any) { alert('✗ Löschen: ' + String(err?.message || err).slice(0, 140)); }
    renderDrv();
  }));
  // Row click: folders navigate, files show properties in the detail pane
  list.querySelectorAll('.drvrow[data-id]').forEach(row => row.addEventListener('click', () => {
    const e = sync!.doc.files[(row as HTMLElement).dataset.id!]; if (!e || e.gone) return;
    if (e.kind === 'd') { drvDir = e.id; drvNew = false; drvRen = ''; renderDrv(); }
    else renderDrvDetail(e);
  }));
  renderDrvDetail();
}

// Drag & drop onto the list pane: only active while the drive tab is open.
$('list').addEventListener('dragover', (e) => { if (folder !== 'drv' || drvOff) return; e.preventDefault(); if (e.dataTransfer) e.dataTransfer.dropEffect = 'copy'; });
$('list').addEventListener('drop', (e) => { if (folder !== 'drv' || drvOff) return; e.preventDefault(); const fs = [...(e.dataTransfer?.files || [])]; if (fs.length) drvUpload(fs); });

// --- IdP (§21): OIDC login flow — consent + BIP340 signature of the server
// challenge with the mailbox key (federation proof in the bmail claim; the relay
// never sees the private key, the signature is made here in the browser). ---
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
      // Clean the OIDC parameters from the URL so going back doesn't trigger again
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
      } catch { /* no redirect possible — just close */ }
      oidcScreen('<p>Abgebrochen. Du kannst dieses Fenster schließen.</p>');
    };
  } catch (e: any) {
    oidcScreen(`<p>✗ ${esc(String(e?.message || e).slice(0, 160))}</p>`);
  }
}

// ---- Self-hosting & own relay (Etappe O) --------------------------------
// If this origin's relayd also serves the UI (/app/, ui_dir), the API on the
// same origin comes first — alpha/beta suggestions would be nonsense here, so a
// single „Dieses Relay" (base = '', same-origin without CORS).
// Detected synchronously via ?self=1 (navigation from the app), asynchronously
// via a /health probe as fallback for directly opened relay addresses.
function applySelfRelayUi() {
  if (SELF_RELAY) return;
  SELF_RELAY = true;
  base = '';
  const sel0 = $('l-relay') as HTMLSelectElement;
  sel0.innerHTML = `<option value="">📟 Dieses Relay · ${esc(location.hostname)}</option>`;
  const w = document.getElementById('l-relay-custom-wrap'); if (w) w.remove();
  applyNetBadge('');
}
if (new URLSearchParams(location.search).has('self')) applySelfRelayUi();
(async () => {
  if (SELF_RELAY) return;
  let j: any = null;
  try { j = await (await fetch('/health')).json(); } catch { /* site frontend, not a relayd */ }
  if (j && typeof j.network === 'string') applySelfRelayUi();
})();

// Dropdown entry „Eigenes Relay (URL)": show the URL field; Enter or
// „Öffnen" NAVIGATES to the /app/ of the entered relay (no CORS, the page is
// served there by the relay itself). On Android the APK remembers the relay as start target.
{
  const custWrap = document.getElementById('l-relay-custom-wrap');
  const custInp = $('l-relay-custom') as HTMLInputElement | null;
  const custGo = $('l-relay-custom-go');
  const normOrigin = (raw: string): string => {
    let u = (raw || '').trim().replace(/\/+$/, '');
    if (!u) return '';
    if (!/^https?:\/\//i.test(u)) u = 'https://' + u;
    try { return new URL(u).origin; } catch { return ''; }
  };
  const openCustom = () => {
    const origin = normOrigin(custInp?.value || '');
    if (!origin) { setLoginStatus('✗ Das ist keine gültige Relay-Adresse (z. B. relay.example.org:8443).'); return; }
    try { (window as any).AndroidNative?.setHomeRelay?.(origin); } catch { /* browser without the native bridge */ }
    location.href = origin + '/app/?self=1';
  };
  if (custWrap && custInp && custGo) {
    $('l-relay')?.addEventListener('change', (e) => {
      const show = (e.target as HTMLSelectElement).value === '__custom__';
      custWrap.style.display = show ? '' : 'none';
      if (show) custInp.focus();
    });
    custGo.addEventListener('click', openCustom);
    custInp.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); openCustom(); } });
  }
}

// Prefill the last known account name (no secret) for passkey convenience
const relSel0 = document.getElementById('l-relay') as HTMLSelectElement | null;
relSel0?.addEventListener('change', () => applyNetBadge(relayVal(relSel0)));
applyNetBadge(relSel0 ? relayVal(relSel0) : base);
const rememberedUser = loadLastUser();
if (rememberedUser) {
  ($('l-acct') as HTMLInputElement).value = rememberedUser.acct;
  const relEl = $('l-relay') as HTMLSelectElement;
  if ([...relEl.options].some(o => o.value === rememberedUser.base)) relEl.value = rememberedUser.base;
  const pkBtn = document.getElementById('l-passkey');
  if (pkBtn && !(window as any).AndroidNative) {
    pkBtn.textContent = `🔑 Mit Passkey anmelden (${rememberedUser.acct})`;
  }
}

// Startup: reload the stored key. Without explicit logout (lm_noauto) the app
// logs in immediately; on Android with hardware-bound vault, BiometricPrompt unlocks it.
let autoSaved = loadAuto();
let fromNativeVault = false;
const startupAn = (window as any).AndroidNative;
if (!autoSaved && startupAn?.vaultInfo && startupAn?.unlockVaultBiometric) {
  const vi = androidVaultInfo();
  if (vi.hasVault) {
    const vAcct = vi.acct || rememberedUser?.acct || '';
    const vBase = vi.base || rememberedUser?.base || '';
    if (vAcct) ($('l-acct') as HTMLInputElement).value = vAcct;
    const relEl = $('l-relay') as HTMLSelectElement;
    if (vBase && [...relEl.options].some(o => o.value === vBase)) relEl.value = vBase;
    const q = $('l-quick'); q.style.display = '';
    const hwTag = vaultBackendLabel(vi.backend);
    ($('l-quickgo') as HTMLButtonElement).textContent = vAcct
      ? `🔑 Als ${vAcct} entsperren (${hwTag})`
      : `🔑 Tresor entsperren (${hwTag})`;
    const runBioUnlock = async () => {
      if (vi.legacy && !vi.bioBound && startupAn.requestBiometricAuth) {
        if (!(await androidBiometricAuth())) return;
      }
      const res = await androidUnlockVault();
      if (res.ok && res.data) {
        await login(res.data.pem, res.data.acct, res.data.base);
      }
    };
    $('l-quickgo').onclick = runBioUnlock;
    $('l-forget').onclick = () => {
      sessionStorage.removeItem(AUTO_KEY);
      localStorage.removeItem(AUTO_KEY);
      localStorage.removeItem(LAST_USER_KEY);
      try { startupAn.clearVault?.(); } catch {}
      q.style.display = 'none';
      ($('l-acct') as HTMLInputElement).value = '';
      setLoginStatus('Gespeicherter Zugang auf diesem Gerät entfernt.', false);
    };
    if (!localStorage.getItem(NOAUTO_KEY)) {
      runBioUnlock().catch((e: any) => {
        setLoginStatus('Auto-Login fehlgeschlagen: ' + String(e?.message || e).slice(0, 120));
      });
    }
  }
} else if (!autoSaved && startupAn?.loadVault) {
  try {
    const nv = JSON.parse(startupAn.loadVault() || 'null');
    if (nv && typeof nv.pem === 'string' && nv.pem && nv.acct && nv.base) { autoSaved = nv; fromNativeVault = true; }
  } catch { /* vault empty or broken — normal login */ }
}
if (autoSaved) {
  const saved = autoSaved;
  ($('l-acct') as HTMLInputElement).value = saved.acct;
  const relEl = $('l-relay') as HTMLSelectElement;
  if ([...relEl.options].some(o => o.value === saved.base)) relEl.value = saved.base;
  const q = $('l-quick'); q.style.display = '';
  ($('l-quickgo') as HTMLButtonElement).textContent = fromNativeVault
    ? `🔑 Als ${saved.acct} entsperren (Fingerabdruck)`
    : `► Direkt weiter als ${saved.acct}`;
  $('l-quickgo').onclick = async () => {
    if (fromNativeVault && (window as any).AndroidNative?.requestBiometricAuth) {
      const ok = await androidBiometricAuth();
      if (!ok) return;
    }
    await login(saved.pem, saved.acct, saved.base);
  };
  $('l-forget').onclick = () => {
    sessionStorage.removeItem(AUTO_KEY);
    localStorage.removeItem(AUTO_KEY);
    localStorage.removeItem(LAST_USER_KEY);
    try { (window as any).AndroidNative?.clearVault?.(); } catch {}
    q.style.display = 'none';
    ($('l-acct') as HTMLInputElement).value = '';
    setLoginStatus('Gespeicherter Zugang auf diesem Gerät entfernt.', false);
  };
  if (!localStorage.getItem(NOAUTO_KEY)) {
    login(saved.pem, saved.acct, saved.base).catch((e: any) => {
      setLoginStatus('Auto-Login fehlgeschlagen: ' + String(e?.message || e).slice(0, 120));
    });
  }
}
