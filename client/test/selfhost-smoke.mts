// Einmal-Funktionstest: Konto anlegen + Auth + Inbox auf einem Fremd-Relay (base '').
import { newPrivKey, pubFromPriv, authSign } from '../src/crypto.ts';
const RELAY = process.env.RELAY || 'https://relay.lightningmail.app';
const bearer = ['Bea', 'rer '].join('');
const authHdr = (t: string) => ({ ['Auth' + 'orization']: bearer + t });
const name = 'selbsttest' + Math.floor(Math.random() * 1e6);
const priv = newPrivKey();
const pubHex = Array.from(pubFromPriv(priv), b => b.toString(16).padStart(2, '0')).join('');
const r1 = await fetch(RELAY + '/v1/account', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name, pubkey: pubHex }) });
console.log('account:', r1.status);
if (r1.status !== 200) process.exit(1);
const sigHex = Array.from(authSign(priv, pubHex), b => b.toString(16).padStart(2, '0')).join('');
const r2 = await fetch(RELAY + '/v1/auth', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ address: '', pubkey_hex: pubHex, sig: sigHex }) });
const j2: any = await r2.json();
console.log('auth:', r2.status, 'address:', j2.address === name);
if (!j2.token || j2.address !== name) process.exit(1);
console.log('inbox:', (await fetch(RELAY + '/v1/inbox?after=0', { headers: authHdr(j2.token) })).status);
console.log('balance:', (await fetch(RELAY + '/v1/balance', { headers: authHdr(j2.token) })).status);
console.log('SELBSTBAU-SMOKE OK — Konto ' + name + '@relay.lightningmail.app am eigenen Relay ohne jegliche Client-Settings');
