// m3-interop.mts — PWA-code side of the Etappe M3 proof: reads the state doc
// the DESKTOP client wrote (contacts + drive tree), downloads the desktop's
// encrypted drive file with drive.ts and compares hashes. Then uploads a
// reply-file through drive.ts so it is visible to the desktop on next sync.
// Run: ACCT=... KEY=/tmp/m3-desktop.key npx tsx test/m3-interop.mts
import { parseSec1PEM, pubFromPriv, authSign, toHex } from "../src/crypto";
import { StateSync } from "../src/state";
import { downloadFile, uploadFile, usage } from "../src/drive";
import * as fs from "fs";
import * as crypto from "crypto";

const base = process.env.RELAY || "http://127.0.0.1:8443";
const acct = process.env.ACCT || "";
const pem = fs.readFileSync(process.env.KEY || "/tmp/m3-desktop.key", "utf8");
const priv = parseSec1PEM(pem);
const ar = await fetch(base + "/v1/auth", {
  method: "POST", headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ address: acct, pubkey_hex: toHex(pubFromPriv(priv)), sig: toHex(authSign(priv, acct)) }),
});
if (!ar.ok) throw new Error("auth " + ar.status + " " + await ar.text());
const token = ((await ar.json()) as any).token as string;

const ok = (c: boolean, m: string) => { console.log((c ? "PASS " : "FAIL ") + m); if (!c) process.exitCode = 1; };

const S = new StateSync(base, priv, () => token, "interop");
await S.pull();

const contacts = S.liveContacts();
ok(contacts.some(c => c.name === "Gisela"), `desktop-Kontakte sichtbar (${contacts.map(c => c.name).join(", ")})`);

const files = S.liveFiles();
const folder = files.find(f => f.name === "belege" && f.kind === "d");
ok(!!folder, "desktop-Ordner 'belege' vorhanden");
const uploaded = files.find(f => f.kind === "f" && f.name === "m3-zufall.bin");
ok(!!uploaded && !!uploaded.msha, "desktop-Datei m3-zufall.bin mit Manifest vorhanden");

if (uploaded) {
  const bytes = await downloadFile(base, token, priv, S, uploaded.id);
  const sha = crypto.createHash("sha256").update(bytes).digest("hex");
  const want = fs.existsSync("/tmp/m3-zufall.sha") ? fs.readFileSync("/tmp/m3-zufall.sha", "utf8").trim() : "";
  ok(!want || sha === want, `PWA downloadet desktop-Upload, sha256 ${want ? "stimmt ueberein" : "(Ref fehlt)"} (${bytes.length} B)`);
  ok(bytes.length === uploaded.size_plain, "size_plain korrekt");
}
const u = await usage(base, token);
ok(u.used_bytes > 0, `Laufwerk-Nutzung gemeldet: ${u.used_bytes} B / ${u.quota_bytes} B`);

// cross-write: PWA uploads a file INTO the desktop's folder
const reply = crypto.randomBytes(700_000);
const e = await uploadFile(base, token, priv, S, reply, "pwa-reply.bin", "application/octet-stream", folder ? folder.id : "");
ok(!!e.msha, "PWA-Upload in desktop-Ordner geschrieben");
fs.writeFileSync("/tmp/m3-pwa-reply.sha", crypto.createHash("sha256").update(reply).digest("hex"));
await S.push();
console.log("EXITCODE", process.exitCode || 0);
