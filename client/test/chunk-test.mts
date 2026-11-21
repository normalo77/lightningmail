// chunk-test.mts — Etappe 7 (§22): 1-MiB slices + manifest, E2E roundtrip
// against running relays, byte-postage deduction, dedup, 402 without balance.
// Run: npx tsx test/chunk-test.mts
//   RELAY_A=/RELAY_B= overridable; balance via python3-sqlite (BMAIL_DB*).
import { newPrivKey, pubFromPriv, authSign, toHex, fromHex, decodeEnvelope, decryptPayload, fromB64, TAG, blobCount, blobRef } from "../src/crypto";
import { composeAndSend } from "../src/send";
import { CHUNK, needsChunking, splitChunks, manifestBytes, parseManifest, reassemble, MAX_REFS } from "../src/chunks";
import { execFileSync } from "node:child_process";

const baseA = process.env.RELAY_A || "http://127.0.0.1:8443";
const baseB = process.env.RELAY_B || "http://127.0.0.1:9443";
const dbA = process.env.BMAIL_DB_A || "/var/lib/bmail/alpha/ledger.db";
const ok = (c: boolean, m: string) => { console.log((c ? "PASS " : "FAIL ") + m); if (!c) process.exitCode = 1; };
const skip = (m: string) => console.log("SKIP " + m);
const auth = (t: string) => ({ Authorization: `Bearer ${t}` } as any);

// --- Unit: chunking/maths without a server ---
const big = new Uint8Array(Math.floor(CHUNK * 2.5));
// Don't fill periodically! (First attempt i*7+13 had period 256 → two
// identical slices → content dedup charged only once, test red.)
for (let i = 0; i < big.length; i++) big[i] = (Math.imul(i, 2654435761) >>> 20) & 0xff;
ok(!needsChunking(CHUNK), "exakt 1 MiB bleibt Einzeldatei (e2e-kompatibel)");
ok(needsChunking(CHUNK + 1), ">1 MiB wird gechunkt");
const parts = [...splitChunks(big)];
ok(parts.length === 3 && parts[0].length === CHUNK && parts[2].length === big.length - 2 * CHUNK, "splitChunks: 3 Scheiben, Reste korrekt");
const man = { v: 1 as const, size: big.length, chunks: ["aa", "bb", "cc"] };
ok(JSON.stringify(parseManifest(manifestBytes(man))) === JSON.stringify(man), "Manifest Roundtrip");
let threw = false;
try { parseManifest(new TextEncoder().encode('{"v":2,"size":1,"chunks":[]}')); } catch { threw = true; }
ok(threw, "Manifest falsche Version -> Fehler");
const man2 = { v: 1 as const, size: big.length, chunks: ["aa", "bb", "cc"] };
const back = await reassemble(async (sha) => parts[man2.chunks.indexOf(sha)], man2);
ok(back.length === big.length && back.every((b, i) => b === big[i]), "reassemble stellt Bytes exakt wieder her");
ok(MAX_REFS === 255, "Ref-Cap dokumentiert (255)");

// --- Accounts ---
async function mkAccount(base: string, tag: string) {
  const priv = newPrivKey();
  const name = `${tag}${Date.now().toString(36)}${Math.floor(Math.random() * 1e4).toString(36)}`.slice(0, 32);
  const r = await fetch(base + "/v1/account", { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name, pubkey: toHex(pubFromPriv(priv)) }) });
  if (!r.ok) throw new Error(`account ${name}: ${r.status} ${await r.text()}`);
  const a = await fetch(base + "/v1/auth", { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ address: name, pubkey_hex: toHex(pubFromPriv(priv)), sig: toHex(authSign(priv, name)) }) });
  return { name, priv, token: ((await a.json()) as any).token as string, base };
}
const topUp = (db: string, name: string, msat: number): boolean => {
  try {
    execFileSync("python3", ["-c",
      `import sqlite3,sys; db=sqlite3.connect(sys.argv[1]); db.execute("UPDATE account SET balance_msat=balance_msat+? WHERE name=?", (${msat}, sys.argv[2])); db.commit()`,
      db, name]);
    return true;
  } catch { return false; }
};

const sender = await mkAccount(baseA, "chk");
const recip = await mkAccount(baseB, "chk");
// Stub world (skill): handleSend looks the recipient up LOCALLY and rigidly
// keysend to Peers[0] → the recipient must exist on BOTH relays with the same key.
{
  const rr = await fetch(baseA + "/v1/account", { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name: recip.name, pubkey: toHex(pubFromPriv(recip.priv)) }) });
  if (!rr.ok && rr.status !== 409) throw new Error("recip auf A registrieren: " + rr.status);
}
console.log(`sender=${sender.name}@A recip=${recip.name}@B`);
const canMoney = topUp(dbA, sender.name, 20_000_000); // 20k sats

// Read the byte-postage config from the relay
const health = await (await fetch(baseA + "/health")).json() as any;
ok(Array.isArray(health.currencies) && health.currencies.includes("btc"), "/health nennt currencies");
const bp: number = health.byte_porto_meur_per_mb ?? 0;
console.log(`byte_porto_meur_per_mb=${bp} rate=${health.rate_meur_per_btc ?? "-"} `);

// --- 402 without balance (only when byte postage is active) ---
if (bp > 0 && !canMoney) skip("Guthaben-Checks (kein sqlite-Zugriff)");
if (bp > 0 && canMoney) {
  const poor = await mkAccount(baseA, "chkp");
  const r = await fetch(baseA + "/v1/blob", { method: "POST", headers: auth(poor.token), body: big.slice(0, CHUNK) as any });
  ok(r.status === 402, `Blob-Upload ohne Guthaben -> 402 (${r.status})`);
}

// --- Send with a 2.5-MiB attachment A→B ---
const balBefore = canMoney ? ((await (await fetch(baseA + "/v1/balance", { headers: auth(sender.token) })).json()) as any).balance_msat : 0;
const out = await composeAndSend(baseA, sender.token, sender.priv, {
  to: recip.name, subject: "dicker anhang", body: "2,5 MiB in Scheiben",
  attachments: [{ name: "gross.bin", bytes: big }],
  onProgress: () => {},
});
ok(!!out.msg_id, `Send mit 2,5-MiB-Anhang ok (${out.msg_id?.slice(0, 10)}…)`);

// Check the byte-postage deduction (slices + manifest, ceil per blob; the
// send postage to the foreign relay comes on top → subtract it from the lookup)
if (bp > 0 && canMoney && health.rate_meur_per_btc > 0) {
  const feeOf = (n: number) => {
    const x1000 = (BigInt(n) * BigInt(bp) * 1000n + 1048575n) / 1048576n; // ceil, all in BigInt
    return Number((x1000 * 100000000n + BigInt(health.rate_meur_per_btc) - 1n) / BigInt(health.rate_meur_per_btc));
  };
  const look = await (await fetch(`${baseA}/v1/profile/${sender.name}`)).json() as any;
  const postageMsat = (look.foreign_sats ?? 0) * 1000;
  const chunkFee = feeOf(CHUNK) * 2 + feeOf(big.length - 2 * CHUNK);
  const balAfter = ((await (await fetch(baseA + "/v1/balance", { headers: auth(sender.token) })).json()) as any).balance_msat;
  const deducted = balBefore - balAfter - postageMsat;
  // The manifest is small (~230 B) → max. ~2 msat extra; tolerance +100
  ok(deducted >= chunkFee && deducted <= chunkFee + 100, `Byte-Porto abgebucht: ${deducted} msat (Scheiben ~${chunkFee} + Manifest, Porto ${postageMsat} abgezogen)`);
} else if (bp > 0) skip("Byte-Porto-Buchungsprüfung (kein sqlite)");
else console.log("INFO byte_porto=0 — Uploads gratis (Config aus)");

// --- Receive on B: decode envelope, reassemble the chunked attachment ---
{
  let inbox: any = null;
  for (let i = 0; i < 20; i++) { // keysend settle + mirror take ~1-2s
    const r = await fetch(baseB + "/v1/inbox", { headers: auth(recip.token) });
    const j = await r.json() as any;
    if ((j.messages || []).length) { inbox = j.messages[0]; break; }
    await new Promise(res => setTimeout(res, 700));
  }
  if (!inbox) { ok(false, "Inbox B: Nachricht angekommen"); }
  else {
    const env = decodeEnvelope(fromB64(inbox.envelope_b64));
    const nRefs = blobCount(env[TAG.BlobRefs]!);
    ok(nRefs === 4, `Envelope blob_refs = 4 (3 Scheiben + Manifest), ist ${nRefs}`);
    const aad = new Uint8Array([...env[TAG.RecipientHash], ...env[TAG.MsgID]]);
    const pt = JSON.parse(new TextDecoder().decode(decryptPayload(recip.priv, env[TAG.Ephemeral]!, env[TAG.Payload]!, aad)));
    const att = pt.attachments?.[0];
    ok(!!att && att.chunked === true && att.size === big.length && att.chunks === 3, `Payload-Attachment chunked: ${JSON.stringify({ c: att?.chunked, s: att?.size, n: att?.chunks })}`);
    const getBlob = async (sha: string) => {
      const r = await fetch(`${baseB}/v1/blob/${sha}`, { headers: auth(recip.token) });
      if (!r.ok) throw new Error("blob " + r.status);
      return new Uint8Array(await r.arrayBuffer());
    };
    const man = parseManifest(await getBlob(att.sha256));
    const rebuilt = await reassemble(getBlob, man);
    ok(rebuilt.length === big.length && rebuilt.every((b, i) => b === big[i]), "Empfänger setzt 2,5 MiB bytegleich wieder zusammen (Mirror+ACL funktionieren)");
  }
}

// --- Dedup: uploading the same slice again costs nothing ---
if (bp > 0 && canMoney) {
  const bal1 = ((await (await fetch(baseA + "/v1/balance", { headers: auth(sender.token) })).json()) as any).balance_msat;
  const r = await fetch(baseA + "/v1/blob", { method: "POST", headers: auth(sender.token), body: big.slice(0, CHUNK) as any });
  const j = await r.json() as any;
  const bal2 = ((await (await fetch(baseA + "/v1/balance", { headers: auth(sender.token) })).json()) as any).balance_msat;
  ok(r.status === 200 && j.charged_msat === 0 && bal1 === bal2, `Dedup: Re-Upload charged_msat=0, Guthaben gleich (${bal1}=${bal2})`);
}

console.log("EXITCODE", process.exitCode || 0);
