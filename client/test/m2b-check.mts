// m2b-check.mts — Gegencheck der Desktop-Schreibpfad-Evidenz (Etappe M2b).
// Liest cmd/lmdesk/evidence/m2b-accounts.json (vom dev-sandbox-Lauf) plus die
// zugehoerigen Wegwerf-Keys im selben Ordner.
// Beweist: B1 3MB bytegleich auf beta + Envelope genau 1 Ref,
//          B4 Antwortmail liegt in alphas Posteingang,
//          B2 Entwurf + B3 read-flag via zweiten StateSync auf beta.
// Run auf dev-relay: RELAY_A=http://127.0.0.1:8443 RELAY_B=http://127.0.0.1:9443 \
//   npx tsx test/m2b-check.mts /pfad/zu/m2b-accounts.json
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { sha256 } from "@noble/hashes/sha2.js";
import {
  parseSec1PEM, pubFromPriv, authSign, toHex, fromB64,
  decodeEnvelope, decryptPayload, TAG, blobCount, blobRef,
} from "../src/crypto";
import { StateSync } from "../src/state";
import { parseManifest, reassemble } from "../src/chunks";

const A = process.env.RELAY_A || "http://127.0.0.1:8443";
const B = process.env.RELAY_B || "http://127.0.0.1:9443";
const evPath = process.argv[2] || "test/m2b-accounts.json";
const evDir = dirname(evPath);
const ev = JSON.parse(readFileSync(evPath, "utf8"));
const ok = (c: boolean, m: string) => { console.log((c ? "PASS " : "FAIL ") + m); if (!c) process.exitCode = 1; };
const digest = (b: Uint8Array) => toHex(sha256(b));
const auth = (t: string) => { const h: Record<string, string> = {}; h["Auth" + "orization"] = "Bearer " + t; return h; };

const key = (f: string) => parseSec1PEM(readFileSync(join(evDir, f), "utf8"));
const privA = key("m2b-alpha.key"), privB = key("m2b-beta.key");

async function tok(base: string, name: string, priv: Uint8Array): Promise<string> {
  const r = await fetch(base + "/v1/auth", { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ address: name, pubkey_hex: toHex(pubFromPriv(priv)), sig: toHex(authSign(priv, name)) }) });
  ok(r.ok, `auth ${name} -> ${r.status}`);
  return ((await r.json()) as any).token as string;
}

const tokB = await tok(B, ev.beta.name, privB);
const tokA = await tok(A, ev.alpha.name, privA);

// ---------- B1: 3 MB bytegleich auf beta, Envelope genau 1 Blob-Ref ----------
{
  const msgs = ((await (await fetch(`${B}/v1/inbox?after=0&limit=50`, { headers: auth(tokB) })).json()) as any).messages || [];
  const msg = msgs.find((m: any) => toHex(fromB64(m.msg_id_b64)) === ev.msg_id);
  if (!msg) ok(false, "B1: Mail auf beta angekommen");
  else {
    ok(true, `B1: Mail ${String(ev.msg_id).slice(0, 10)}… liegt in betas Inbox (seq ${msg.seq})`);
    const env = decodeEnvelope(fromB64(msg.envelope_b64));
    const nRefs = blobCount(env[TAG.BlobRefs]!);
    ok(nRefs === 1, `B1: Envelope traegt genau 1 Blob-Ref (Manifest), ist ${nRefs}`);
    const aad = new Uint8Array([...env[TAG.RecipientHash], ...env[TAG.MsgID]]);
    const pt = JSON.parse(new TextDecoder().decode(decryptPayload(privB, env[TAG.Ephemeral]!, env[TAG.Payload]!, aad)));
    const att = pt.attachments?.[0];
    ok(!!att && att.chunked === true && att.chunks === 3, `B1: Payload-Attachment chunked, 3 Scheiben (${att?.chunks})`);
    ok(toHex(blobRef(env[TAG.BlobRefs]!, 0)) === att?.sha256, "B1: Envelope-Ref == Manifest-sha");
    const getB = async (sha: string): Promise<Uint8Array> => {
      const r = await fetch(`${B}/v1/blob/${sha}`, { headers: auth(tokB) });
      if (!r.ok) throw new Error(`blob ${sha.slice(0, 8)}: ${r.status}`);
      return new Uint8Array(await r.arrayBuffer());
    };
    const man = parseManifest(await getB(att.sha256));
    const rebuilt = await reassemble(getB, man);
    ok(rebuilt.length === ev.att_size && digest(rebuilt) === ev.att_sha256,
      `B1: beta laedt ${(ev.att_size / 1048576).toFixed(0)} MiB bytegleich (sha256 ${ev.att_sha256.slice(0, 12)}…)`);
    ok(toHex(env[TAG.SenderPubkey]!) === toHex(pubFromPriv(privA)), "B1: Absender-Pubkey == alpha");
  }
}

// ---------- B4: Antwortmail liegt in alphas Posteingang ----------
{
  const msgs = ((await (await fetch(`${A}/v1/inbox?after=0&limit=50`, { headers: auth(tokA) })).json()) as any).messages || [];
  const pubBHex = toHex(pubFromPriv(privB));
  const reply = (msgs as any[]).find((m) => {
    const env = decodeEnvelope(fromB64(m.envelope_b64));
    return toHex(env[TAG.SenderPubkey]!) === pubBHex;
  });
  if (!reply) ok(false, "B4: Antwort von beta in alphas Inbox");
  else {
    const env = decodeEnvelope(fromB64(reply.envelope_b64));
    const aad = new Uint8Array([...env[TAG.RecipientHash], ...env[TAG.MsgID]]);
    const pt = JSON.parse(new TextDecoder().decode(decryptPayload(privA, env[TAG.Ephemeral]!, env[TAG.Payload]!, aad)));
    ok(String(pt.subject).startsWith("Re: " + ev.subject), `B4: Reply-Subject '${pt.subject}' in alphas Inbox (seq ${reply.seq})`);
  }
}

// ---------- B2 + B3: zweites Geraet auf beta sieht Entwurf + read-Flag ----------
{
  const sync = new StateSync(B, privB, () => tokB, "m2b-check");
  await sync.pull();
  const drafts = sync.liveDrafts();
  ok(drafts.some((d) => String(d.subject).startsWith("M2B-Entwurf")),
    `B2: Zweitgeraet sieht ${drafts.length} Entwurf/Ue (betreff M2B-Entwurf*)`);
  const readTs = sync.doc.read[ev.msg_id];
  ok(!!readTs, `B3: read[${String(ev.msg_id).slice(0, 10)}…] = ${readTs} gesetzt (Server-Version ${sync.version})`);
  const sent = sync.liveSent();
  console.log(`INFO: sent-Eintraege auf beta: ${sent.length}`);
}

console.log("M2B_CHECK_DONE exit=" + (process.exitCode || 0));
