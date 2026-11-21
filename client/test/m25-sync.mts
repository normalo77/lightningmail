// m25-sync.mts — headless proof: two devices, one account, one state slot.
import { newPrivKey, pubFromPriv, authSign, toHex } from "../src/crypto";
import { StateSync } from "../src/state";

const base = process.env.RELAY || "http://127.0.0.1:8443";
// Self-provisioned throwaway account: since the browser signup (17.11.) the
// e2e-home/bernd key no longer matches prod-bernd — tests must not depend on
// real accounts.
const priv = newPrivKey();
const acct = "m25" + Date.now().toString(36);
const cr = await fetch(base + "/v1/account", { method: "POST", headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ name: acct, pubkey: toHex(pubFromPriv(priv)) }) });
if (!cr.ok) throw new Error("account " + cr.status);
async function tok(): Promise<string> {
  const r = await fetch(base + "/v1/auth", { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ address: acct, pubkey_hex: toHex(pubFromPriv(priv)), sig: toHex(authSign(priv, acct)) }) });
  if (!r.ok) throw new Error("auth " + r.status);
  return ((await r.json()) as any).token as string;
}
const ok = (cond: boolean, msg: string) => { console.log((cond ? "PASS " : "FAIL ") + msg); if (!cond) process.exitCode = 1; };

const tA = await tok(), tB = await tok();
const A = new StateSync(base, priv, () => tA, "testA");
const B = new StateSync(base, priv, () => tB, "testB");
await A.pull(); const v0 = A.version;
A.markRead("msg-eins"); await A.push();
ok(A.version === v0 + 1, `push erhoeht Version (${v0} -> ${A.version})`);

await B.pull();
ok(!!B.doc.read["msg-eins"], "Geraet B sieht gelesen-Markierung von A");
ok(B.version === A.version, "Versionen gleichen sich nach pull");

A.toggleSpam("absender-xy", true); await A.push();
B.markRead("msg-zwei");            await B.push(); // 409 -> auto-merge -> retry
const C = new StateSync(base, priv, () => tA, "testC");
await C.pull();
ok(!!C.doc.read["msg-eins"] && !!C.doc.read["msg-zwei"] && !!C.doc.spam["absender-xy"],
  "Merge enthaelt Aenderungen BEIDER Geraete");

A.saveDraft({ id: "d1", to: "gisela", subject: "Entwurf", body: "fassung-alt" }); await A.push();
await B.pull();
B.saveDraft({ id: "d1", to: "gisela", subject: "Entwurf", body: "fassung-neu" }); await B.push();
await C.pull();
const live = C.liveDrafts();
ok(live.length === 1 && live[0].body === "fassung-neu", "Draft LWW: neueste Fassung gewinnt");
A.delDraft("d1"); await A.push();
await C.pull();
ok(C.liveDrafts().length === 0, "Tombstone: geloeschter Entwurf bleibt weg");

// Sent folder (star sync): device A "sends" -> relay -> device B sees the entry
A.addSent({ msg_id: "sent-1", ts: 1700000001, to: "gisela", subject: "Hallo", body: "Text der gesendeten Mail", bytes: 123 });
await A.push();
await B.pull();
const sl = B.liveSent();
ok(sl.length === 1 && sl[0].to === "gisela" && sl[0].subject === "Hallo" && sl[0].body === "Text der gesendeten Mail",
  "addSent/liveSent: Gesendete Mail (Empfaenger, Betreff, Body) kommt auf Geraet B an");

console.log("EXITCODE", process.exitCode || 0);
