// drive-test.mts — Etappe J2–J4: Drive-Client (state.ts files-Merge + drive.ts).
// Unit-Teil läuft ohne Netz; der Integrationsteil braucht ein laufendes Relay mit
// J1-Deployment (RELAY=… überschreibbar, Default http://127.0.0.1:8443):
//   NODE_OPTIONS='--experimental-global-webcrypto' npx tsx test/drive-test.mts
// Einweg-Konto (newPrivKey + POST /v1/account + auth) — KEINE Prod-Datei-Keys!
import { newPrivKey, pubFromPriv, authSign, toHex } from "../src/crypto";
import { StateSync, mergeDocs, emptyDoc, type DriveEntry } from "../src/state";
import { uploadFile, downloadFile, deleteFile, usage, buyTier, newDriveId } from "../src/drive";
import { execFileSync } from "node:child_process";

const base = process.env.RELAY || "http://127.0.0.1:8443";
const ok = (c: boolean, m: string) => { console.log((c ? "PASS " : "FAIL ") + m); if (!c) process.exitCode = 1; };
const skip = (m: string) => console.log("SKIP " + m);

// --- Unit: files-Merge, pure Funktion gegen simulierte Docs, ohne Netz ---
const f = (id: string, ts: number, extra: Partial<DriveEntry> = {}): DriveEntry =>
  ({ id, ts, name: id, parent: "root", kind: "f", size: 10, size_plain: 5, mime: "text/plain", ...extra });

const m1 = mergeDocs({ ...emptyDoc(), files: { a: f("a", 1, { name: "alt" }) } },
                     { ...emptyDoc(), files: { a: f("a", 2, { name: "neu" }) } });
ok(m1.files.a.name === "neu", "files-Merge: neuerer ts gewinnt (LWW)");
const m2 = mergeDocs({ ...emptyDoc(), files: { a: f("a", 9, { name: "neuer" }) } },
                     { ...emptyDoc(), files: { a: f("a", 1, { gone: 1 }) } });
ok(m2.files.a.name === "neuer" && !m2.files.a.gone, "files-Merge: lebendiger Eintrag gewinnt gegen ÄLTERES Grab");
const m3 = mergeDocs({ ...emptyDoc(), files: { a: f("a", 5) } },
                     { ...emptyDoc(), files: { a: f("a", 5, { gone: 1 }) } });
ok(!!m3.files.a.gone, "files-Merge: Gleichstand → gone gewinnt");
const m4 = mergeDocs({ ...emptyDoc(), files: { a: f("a", 1) } },
                     { ...emptyDoc(), files: { b: f("b", 1, { kind: "d" }) } });
ok(!!m4.files.a && !!m4.files.b && m4.files.b.kind === "d", "files-Merge: Union disjunkter ids");
ok(typeof emptyDoc().files === "object", "emptyDoc hat files-Map");
const m5 = mergeDocs({ ...emptyDoc(), contacts: { c: { id: "c", ts: 1, name: "x" } as any } }, emptyDoc());
ok(!!m5.contacts.c, "contacts-Merge unverändert intakt (Regression)");

// StateSync.saveFile/delFile ohne Netz (Push-Timer läuft nach Testende harmlos leer)
const offline = new StateSync("", new Uint8Array(32), () => "", "drvUnit");
offline.saveFile(f("u1", 1, { name: "eins" }));
ok(offline.doc.files.u1.ts >= Math.floor(Date.now() / 1000), "saveFile stempelt max(now,prev)+1");
offline.delFile("u1");
ok(offline.doc.files.u1.gone === 1, "delFile setzt Tombstone (kind egal)");
const tsGrab = offline.doc.files.u1.ts;
offline.saveFile({ id: "u1", name: "wieder-da" });
ok(!offline.doc.files.u1.gone && offline.doc.files.u1.name === "wieder-da" && offline.doc.files.u1.ts > tsGrab,
  "lebendiger Save erweckt (stript gone, stempelt über das Grab)");
ok(offline.liveFiles().length === 1 && offline.liveFiles()[0].id === "u1", "liveFiles filtert Gräber");
ok(/^[0-9a-f]{16}$/.test(newDriveId()) && newDriveId() !== newDriveId(), "newDriveId: hex16, eindeutig");

// --- Integration: erst wenn ein Relay erreichbar ist (sonst pending CT113) ---
const alive = await fetch(base + "/health").then(r => r.ok).catch(() => false);
if (!alive) {
  skip(`Integration: kein Relay unter ${base} — pending CT113 (nach J1-Deploy: NODE_OPTIONS='--experimental-global-webcrypto' RELAY=… npx tsx test/drive-test.mts)`);
  console.log("EXITCODE", process.exitCode || 0);
} else {

// 1) /health- und usage-Shape
const health = await (await fetch(base + "/health")).json() as any;
ok(health.drive && typeof health.drive.enabled === "boolean" && typeof health.drive.quota_mb === "number",
  `/health liefert drive:{enabled,quota_mb} (${JSON.stringify(health.drive)})`);

// Einweg-Konto
const priv = newPrivKey();
const acct = `drv${Date.now().toString(36)}${Math.floor(Math.random() * 1e4).toString(36)}`.slice(0, 32);
const cr = await fetch(base + "/v1/account", { method: "POST", headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ name: acct, pubkey: toHex(pubFromPriv(priv)) }) });
if (!cr.ok) throw new Error(`account ${acct}: ${cr.status} ${await cr.text()}`);
const ar = await fetch(base + "/v1/auth", { method: "POST", headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ address: acct, pubkey_hex: toHex(pubFromPriv(priv)), sig: toHex(authSign(priv, acct)) }) });
const token = ((await ar.json()) as any).token as string;
const authH: Record<string, string> = {};
authH["Auth" + "orization"] = "Bearer " + token;
console.log(`konto=${acct}@${base}`);

const u0 = await usage(base, token);
ok(typeof u0.enabled === "boolean" && typeof u0.used_bytes === "number" && typeof u0.quota_bytes === "number" && Array.isArray(u0.tiers),
  `usage-Shape {enabled,used_bytes,quota_bytes,tiers} (${JSON.stringify(u0)})`);

if (!u0.enabled) {
  skip("drive auf diesem Relay deaktiviert — Rest-Checks hängen (Parent: Relay-Config drive.enabled=true)");
} else {

const A = new StateSync(base, priv, () => token, "drvA");
await A.pull();

// 2) mkdir root/orderA
const dirId = newDriveId();
A.saveFile({ id: dirId, name: "orderA", parent: "root", kind: "d", size: 0, size_plain: 0, mime: "" });
await A.push();
ok(A.liveFiles().some(x => x.id === dirId && x.kind === "d"), "mkdir: Ordner orderA im State-Doc");

// 3) Upload 2.5 MiB crypto-zufällige Bytes (NIE periodisch füllen — Dedup-Falle)
const big = new Uint8Array(Math.floor(1048576 * 2.5));
for (let o = 0; o < big.length; o += 32768) globalThis.crypto.getRandomValues(big.subarray(o, o + 32768));
const up = await uploadFile(base, token, priv, A, big, "gross.bin", "application/octet-stream", dirId, () => {});
await A.push();
ok(!!up.msha && /^[0-9a-f]{64}$/.test(up.msha), `uploadFile → msha (${String(up.msha).slice(0, 12)}…)`);
ok(up.size > big.length && up.size_plain === big.length,
  `size = gespeichert (Chiffre+Manifest ${up.size}) > size_plain = Klartext (${up.size_plain})`);

// 4) list-Merge: zweiter Client sieht den Eintrag mit msha
const B = new StateSync(base, priv, () => token, "drvB");
await B.pull();
const seen = B.liveFiles().find(x => x.name === "gross.bin");
ok(!!seen && seen!.msha === up.msha && seen!.parent === dirId && seen!.kind === "f",
  "list-Merge: Eintrag auf Gerät B sichtbar (msha, parent, kind)");

// 5) downloadFile → bytegleich
const back = await downloadFile(base, token, priv, B, seen!.id);
ok(back.length === big.length && back.every((b, i) => b === big[i]), "downloadFile stellt Original bytegleich wieder her");

// 6) Löschen: nicht-leerer Ordner → Fehler; Datei → usage sinkt, Blob weg
let threw = false;
try { await deleteFile(base, token, B, dirId); } catch { threw = true; }
ok(threw, "delete nicht-leerer Ordner → Error (kein Tombstone)");
ok(!B.doc.files[dirId]?.gone, "fehlgeschlagener Ordner-Delete setzt KEINEN Tombstone");
const u1 = await usage(base, token);
await deleteFile(base, token, B, seen!.id);
await B.push();
const u2 = await usage(base, token);
ok(u1.used_bytes - u2.used_bytes === seen!.size,
  `usage sinkt exakt um entry.size (${u1.used_bytes} → ${u2.used_bytes}, erwartet −${seen!.size})`);
const gr = await fetch(`${base}/v1/blob/${up.msha}`, { headers: authH });
ok(gr.status === 404 || gr.status === 403, `GET freigegebener Manifest-Blob → 404/403 (ist ${gr.status})`);
ok(!!B.doc.files[seen!.id]?.gone, "Tombstone erst NACH Server-Freigabe");
await deleteFile(base, token, B, dirId);
ok(!B.liveFiles().some(x => x.id === dirId), "leerer Ordner löschbar");
await B.push();

// 7) buy tier (kleinster sats-Wert aus der Config) → quota steigt, balance −sats*1000
if (u2.tiers.length) {
  const ti = u2.tiers.reduce((best, t, i) => (t.sats < u2.tiers[best].sats ? i : best), 0);
  const tier = u2.tiers[ti];
  const db = process.env.BMAIL_DB || "/var/lib/bmail/alpha/ledger.db";
  let topped = false;
  try {
    execFileSync("python3", ["-c",
      `import sqlite3,sys; db=sqlite3.connect(sys.argv[1]); db.execute("UPDATE account SET balance_msat=balance_msat+? WHERE name=?", (${tier.sats * 1000 + 100000}, sys.argv[2])); db.commit()`,
      db, acct]);
    topped = true;
  } catch { topped = false; }
  if (!topped) skip("buy tier (kein sqlite-Zugriff fürs Guthaben — BMAIL_DB setzen)");
  else {
    const bal1 = ((await (await fetch(base + "/v1/balance", { headers: authH })).json()) as any).balance_msat;
    const buy = await buyTier(base, token, ti);
    const bal2 = ((await (await fetch(base + "/v1/balance", { headers: authH })).json()) as any).balance_msat;
    ok(buy.quota_bytes === u2.quota_bytes + tier.gb * 1073741824, `quota_bytes steigt um ${tier.gb} GB (${u2.quota_bytes} → ${buy.quota_bytes})`);
    ok(bal1 - bal2 === tier.sats * 1000, `balance delta == −${tier.sats}·1000 msat (ist −${bal1 - bal2})`);
    ok(buy.cost_sats === tier.sats, `cost_sats == Tier-Preis (${buy.cost_sats})`);
    const u3 = await usage(base, token);
    ok(u3.quota_bytes === buy.quota_bytes, "usage spiegelt neue quota_bytes");
  }
} else skip("buy tier (keine tiers in der Relay-Config)");

// 8) State-CAS/409: A steht auf alter Version (B hat zwischendurch gepusht) →
//    A.saveFile+push läuft durch den 409→pull→merge→retry-Pfad, BEIDE Einträge bleiben.
const ida = newDriveId(), idc = newDriveId();
A.saveFile({ id: ida, name: "casA", parent: "root", kind: "d", size: 0, size_plain: 0, mime: "" });
const C = new StateSync(base, priv, () => token, "drvC");
await C.pull();
C.saveFile({ id: idc, name: "casC", parent: "root", kind: "d", size: 0, size_plain: 0, mime: "" });
await C.push(); // externer Version-Bump
await A.push(); // stale version → 409-Pfad
const D = new StateSync(base, priv, () => token, "drvD");
await D.pull();
ok(!!D.liveFiles().find(x => x.id === ida) && !!D.liveFiles().find(x => x.id === idc),
  "CAS: konkurrierende Saves überleben beide (409 → auto-merge → retry)");
ok(!D.liveFiles().some(x => x.name === "gross.bin"), "Tombstone bleibt im Merge über alle Geräte weg");

} // drive enabled
console.log("EXITCODE", process.exitCode || 0);
}
