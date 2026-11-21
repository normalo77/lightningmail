// m1-golden.mts — Etappe M1b A6: generates the StateDoc golden fixtures that
// the Go port (desktop/core/statedoc.go) must reproduce byte-for-byte.
// Run on Hermes (Node + tsx + lm-work node_modules):
//   cd client && NODE_OPTIONS='--experimental-global-webcrypto' \
//     ./node_modules/.bin/tsx test/m1-golden.mts
// Output: ../desktop/core/testdata/m1-golden.json
// 20 cases: 17 mergeDocs + 3 sealed-blob (StateSync.seal -> Go OpenStateDoc).
// The "priv_hex" key is a fixed TEST VECTOR scalar — never a prod key!
import { fromHex } from "../src/crypto";
import { mergeDocs, emptyDoc, StateSync, type StateDoc, type Draft, type SentItem, type Contact, type DriveEntry } from "../src/state";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

// fixed TEST VECTOR scalar = 1 (built programmatically; never a prod key)
const PRIV = "0".repeat(63) + "1";

const draft = (id: string, ts: number, extra: Partial<Draft> = {}): Draft =>
  ({ id, ts, to: `${id}@x`, subject: `S ${id}`, body: `B ${id}`, ...extra });
const sent = (msg_id: string, ts: number, extra: Partial<SentItem> = {}): SentItem =>
  ({ msg_id, ts, to: "x@y", subject: `S ${msg_id}`, bytes: 100, ...extra });
const contact = (id: string, ts: number, extra: Partial<Contact> = {}): Contact =>
  ({ id, ts, name: id, given: "", org: "", title: "", url: "", cell: "", phone: "", fax: "", email: "", addr: "", lnaddr: "", pubkey: "", pgp: "", note: "", btc: "", crypto: "", ...extra } as Contact);
const file = (id: string, ts: number, extra: Partial<DriveEntry> = {}): DriveEntry =>
  ({ id, ts, name: id, parent: "root", kind: "f", size: 10, size_plain: 5, mime: "text/plain", ...extra } as DriveEntry);

type MergeCase = { name: string; a: StateDoc; b: StateDoc; merged: StateDoc };
const merges: MergeCase[] = [];
const add = (name: string, a: Partial<StateDoc>, b: Partial<StateDoc>) => {
  const da = { ...emptyDoc(), ...a }, db = { ...emptyDoc(), ...b };
  merges.push({ name, a: da, b: db, merged: mergeDocs(da, db) });
};

add("empty+empty", {}, {});
add("read-flags union", { read: { m1: 1, m2: 1 } }, { read: { m2: 1, m3: 1 } });
add("spam+deleted union", { spam: { s1: 1 }, deleted: { d1: 1 } }, { spam: { s2: 1 }, deleted: { d2: 1 } });
add("drafts: newer ts in b wins", { drafts: [draft("x", 100)] }, { drafts: [draft("x", 200)] });
add("drafts: newer ts in a wins", { drafts: [draft("x", 200)] }, { drafts: [draft("x", 100)] });
add("drafts: tie -> candidate(b) gone wins", { drafts: [draft("x", 5)] }, { drafts: [draft("x", 5, { gone: 1 })] });
add("drafts: tie -> live candidate LOSES vs gone current", { drafts: [draft("x", 5, { gone: 1 })] }, { drafts: [draft("x", 5)] });
add("drafts: multi-id dedupe + asc sort",
  { drafts: [draft("c", 30), draft("a", 10, { gone: 1 })] },
  { drafts: [draft("b", 20), draft("c", 31)] });
add("drafts: cap keeps last 30 (asc by ts)",
  { drafts: Array.from({ length: 35 }, (_, i) => draft(`d${i}`, 1000 + i)) }, {});
add("sent: dedupe, longer body wins over newer ts",
  { sent: [sent("m", 200, { body: "short" })] }, { sent: [sent("m", 100, { body: "a much longer body" })] });
add("sent: UTF-16 body length (emoji trap: 2 units vs 3 chars)",
  { sent: [sent("m", 50, { body: "abc" })] }, { sent: [sent("m", 40, { body: "😀" })] });
add("sent: equal body length -> newer ts wins",
  { sent: [sent("m", 10, { body: "aa" })] }, { sent: [sent("m", 20, { body: "bb" })] });
add("sent: cap 150 desc",
  { sent: Array.from({ length: 160 }, (_, i) => sent(`s${i}`, 5000 + i)) }, {});
add("contacts: union + b newer wins", { contacts: { c1: contact("c1", 1), c2: contact("c2", 9) } },
  { contacts: { c2: contact("c2", 10, { name: "neu" }), c3: contact("c3", 1) } });
add("contacts: tie -> gone wins (b), live candidate loses (order!)",
  { contacts: { g: contact("g", 7, { gone: 1 }), h: contact("h", 7) } },
  { contacts: { g: contact("g", 7), h: contact("h", 7, { gone: 1 }) } });
add("files: drive LWW + folders", { files: { f1: file("f1", 3), f2: file("f2", 3, { kind: "d" }) } },
  { files: { f1: file("f1", 4, { name: "neu", msha: "ab".repeat(32) }) } });
add("mixed: everything at once",
  { read: { m1: 1 }, drafts: [draft("x", 10)], sent: [sent("s", 10)], contacts: { c: contact("c", 1) }, files: { f: file("f", 1) } },
  { read: { m2: 1 }, spam: { p: 1 }, deleted: { d: 1 }, drafts: [draft("x", 11, { gone: 1 })], sent: [sent("s", 11, { body: "länger" })], contacts: { c: contact("c", 2, { gone: 1 }) }, files: { g: file("g", 2, { kind: "d" }) } });

// --- sealed blobs: the REAL StateSync.seal path (self-ECIES, AAD empty) ---
const ss = new StateSync("", fromHex(PRIV), () => "", "m1-golden");
const sealDoc = (name: string, doc: StateDoc) =>
  ({ name, state_b64: (ss as any).seal(doc) as string, doc });
const sealed = [
  sealDoc("sealed: empty doc", emptyDoc()),
  sealDoc("sealed: unicode umlauts + emoji", {
    ...emptyDoc(),
    read: { "ä😀m1": 1 },
    drafts: [draft("ü", 42, { subject: "Grüße 😀", body: "ÄÖÜ äöü ß — ok" })],
    contacts: { k: contact("k", 43, { name: "Bär", note: "🔒 versiegelt" }) },
  }),
  sealDoc("sealed: full doc all sections", {
    read: { m1: 1, m2: 1 }, spam: { s: 1 }, deleted: { d: 1 },
    drafts: [draft("a", 1), draft("b", 2, { gone: 1 })],
    sent: [sent("s1", 100, { body: "hello" }), sent("s2", 90)],
    contacts: { c1: contact("c1", 5, { lnaddr: "c1@alpha" }) },
    files: { f1: file("f1", 6, { size: 2097152, msha: "cd".repeat(32) }), f2: file("f2", 7, { kind: "d", gone: 1 }) },
  }),
];

const out = { note: "generated by client/test/m1-golden.mts — do not edit", priv_hex: PRIV, merge: merges, sealed };
const outPath = join(dirname(new URL(import.meta.url).pathname), "..", "..", "desktop", "core", "testdata", "m1-golden.json");
mkdirSync(dirname(outPath), { recursive: true });
writeFileSync(outPath, JSON.stringify(out, null, 1));
console.log(`GOLDEN_OK ${merges.length} merge + ${sealed.length} sealed cases -> ${outPath}`);
if (merges.length + sealed.length !== 20) { console.error("CASE COUNT WRONG"); process.exit(1); }
