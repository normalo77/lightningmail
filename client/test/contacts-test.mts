// contacts-test.mts — Etappe A: private address book in the state slot (sync, LWW, tombstone).
import { newPrivKey, pubFromPriv, authSign, toHex } from "../src/crypto";
import { StateSync, mergeDocs, emptyDoc, type Contact } from "../src/state";

const ok = (cond: boolean, msg: string) => { console.log((cond ? "PASS " : "FAIL ") + msg); if (!cond) process.exitCode = 1; };

// --- Unit: merge semantics without a server ---
const c = (id: string, ts: number, over: Partial<Contact> = {}): Contact =>
  ({ id, ts, name: "x", given: "", org: "", title: "", url: "", cell: "", phone: "", fax: "", email: "", addr: "", lnaddr: "", btc: "", crypto: "", pubkey: "", pgp: "", note: "", ...over });
const m1 = mergeDocs({ ...emptyDoc(), contacts: { a: c("a", 1, { name: "alt" }) } },
                     { ...emptyDoc(), contacts: { a: c("a", 2, { name: "neu" }) } });
ok(m1.contacts.a.name === "neu", "LWW: hoeherer ts gewinnt");
const m2 = mergeDocs({ ...emptyDoc(), contacts: { a: c("a", 9, { name: "neuer" }) } },
                     { ...emptyDoc(), contacts: { a: c("a", 1, { gone: 1 }) } });
ok(m2.contacts.a.name === "neuer" && !m2.contacts.a.gone, "Re-Merge: aelterer Tombstein frisst kein frisches Leben");
const m3 = mergeDocs({ ...emptyDoc(), contacts: { a: c("a", 1) } }, { ...emptyDoc(), contacts: { b: c("b", 1) } });
ok(!!m3.contacts.a && !!m3.contacts.b, "Verschiedene ids ueberleben beide Seiten");

// --- Integration: two devices, real relay ---
const base = process.env.RELAY || "http://127.0.0.1:8443";
// Self-provisioned throwaway account: since the browser signup (17.11.) the
// e2e-home/bernd key no longer matches prod-bernd.
const priv = newPrivKey();
const acct = "cts" + Date.now().toString(36);
const cr = await fetch(base + "/v1/account", { method: "POST", headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ name: acct, pubkey: toHex(pubFromPriv(priv)) }) });
if (!cr.ok) throw new Error("account " + cr.status);
const t0 = await (await fetch(base + "/v1/auth", { method: "POST", headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ address: acct, pubkey_hex: toHex(pubFromPriv(priv)), sig: toHex(authSign(priv, acct)) }) })).json() as any;
if (!t0.token) throw new Error("auth fehlgeschlagen");
const A = new StateSync(base, priv, () => t0.token, "testCa");
const B = new StateSync(base, priv, () => t0.token, "testCb");
await A.pull(); await B.pull();
A.saveContact({ id: "k1", name: "Hase", given: "Heinz", lnaddr: "heinz@example.org", cell: "0170-1234567" });
await A.push();
await B.pull();
ok(B.liveContacts().find(x => x.id === "k1")?.name === "Hase", "Kontakt synct auf Geraet B");
B.saveContact({ id: "k1", org: "ACME" }); await B.push();  // Partial-Edit
await A.pull();
const k1 = A.liveContacts().find(x => x.id === "k1");
ok(k1?.org === "ACME" && k1?.name === "Hase", "Partial-Edit erhaelt uebrige Felder");
A.delContact("k1"); await A.push();
await B.pull();
ok(!B.liveContacts().find(x => x.id === "k1") && B.doc.contacts["k1"]?.gone === 1, "Tombstein: Kontakt weg, Grab bleibt");
console.log("EXITCODE", process.exitCode || 0);
