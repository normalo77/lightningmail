// contacts-test.mts — Etappe A: privates Adressbuch im State-Slot (Sync, LWW, Tombstein).
import { readFileSync } from "node:fs";
import { parseSec1PEM, pubFromPriv, authSign, toHex } from "../src/crypto";
import { StateSync, mergeDocs, emptyDoc, type Contact } from "../src/state";

const ok = (cond: boolean, msg: string) => { console.log((cond ? "PASS " : "FAIL ") + msg); if (!cond) process.exitCode = 1; };

// --- Unit: Merge-Semantik ohne Server ---
const c = (id: string, ts: number, over: Partial<Contact> = {}): Contact =>
  ({ id, ts, name: "x", given: "", org: "", title: "", url: "", cell: "", phone: "", fax: "", email: "", addr: "", lnaddr: "", pubkey: "", pgp: "", note: "", ...over });
const m1 = mergeDocs({ ...emptyDoc(), contacts: { a: c("a", 1, { name: "alt" }) } },
                     { ...emptyDoc(), contacts: { a: c("a", 2, { name: "neu" }) } });
ok(m1.contacts.a.name === "neu", "LWW: hoeherer ts gewinnt");
const m2 = mergeDocs({ ...emptyDoc(), contacts: { a: c("a", 9, { name: "lebendig" }) } },
                     { ...emptyDoc(), contacts: { a: c("a", 1, { gone: 1 }) } });
ok(m2.contacts.a.gone === 1, "Tombstein gewinnt auch gegenaelter ts");
const m3 = mergeDocs({ ...emptyDoc(), contacts: { a: c("a", 1) } }, { ...emptyDoc(), contacts: { b: c("b", 1) } });
ok(!!m3.contacts.a && !!m3.contacts.b, "Verschiedene ids ueberleben beide Seiten");

// --- Integration: zwei Geraete, echtes Relay ---
const base = "http://127.0.0.1:8443";
const priv = parseSec1PEM(readFileSync("/root/lightningmail/test/e2e-home/bernd/bernd.key", "utf8"));
const t0 = await (await fetch(base + "/v1/auth", { method: "POST", headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ address: "bernd", pubkey_hex: toHex(pubFromPriv(priv)), sig: toHex(authSign(priv, "bernd")) }) })).json() as any;
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
