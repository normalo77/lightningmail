// recipients-test.mts — unit tests for To/CC parsing, Reply-All and the
// composeAndSend fan-out (mocked fetch, no relay needed). Run: npx tsx test/recipients-test.mts
import { parseRecipients, uniqueRecipients, replyAll } from "../src/recipients";
import { composeAndSend } from "../src/send";
import { newPrivKey, pubFromPriv, toHex, decodeEnvelope, decryptPayload, TAG } from "../src/crypto";

const ok = (c: boolean, m: string) => { console.log((c ? "PASS " : "FAIL ") + m); if (!c) process.exitCode = 1; };
const eq = (name: string, got: unknown, want: unknown) =>
  ok(JSON.stringify(got) === JSON.stringify(want), `${name}: ${JSON.stringify(got)} == ${JSON.stringify(want)}`);

// --- parsing: comma/semicolon, trimming, case-insensitive dedupe, order ---
eq("parse mixed separators", parseRecipients(" a@x , b@x ;c@x ,, A@X "), ["a@x", "b@x", "c@x"]);
eq("parse empty", parseRecipients("  , ; "), []);
eq("parse single", parseRecipients("bob@relay"), ["bob@relay"]);
eq("union to+cc dedupes", uniqueRecipients("a@x, b@x", "B@x ; c@x"), ["a@x", "b@x", "c@x"]);
eq("union cc-only", uniqueRecipients("", "c@x"), ["c@x"]);

// --- reply-all ---
eq("reply-all basic",
  replyAll("alice@x", "bob@x, carol@x", "dave@x", "bob@x"),
  { to: ["alice@x"], cc: ["carol@x", "dave@x"] });
eq("reply-all self as bare name",
  replyAll("alice@x", "bob@x, carol@x", "", "bob"),
  { to: ["alice@x"], cc: ["carol@x"] });
eq("reply-all sender duplicate in cc removed",
  replyAll("alice@x", "bob@x", "alice@x, carol@x", "bob@x"),
  { to: ["alice@x"], cc: ["carol@x"] });
eq("reply-all to self only", replyAll("bob@x", "bob@x", "", "bob@x"), { to: [], cc: [] });
eq("reply-all no headers", replyAll("alice@x", "", "", "bob@x"), { to: ["alice@x"], cc: [] });

// --- composeAndSend fan-out against a mocked relay ---
const privB = newPrivKey(), privC = newPrivKey();
const pubs: Record<string, string> = { bob: toHex(pubFromPriv(privB)), carol: toHex(pubFromPriv(privC)) };
const sends: { to: string; wire: Uint8Array }[] = [];
const realFetch = globalThis.fetch;
globalThis.fetch = (async (url: any, init?: any) => {
  const u = String(url);
  const json = (o: unknown) => ({ ok: true, status: 200, json: async () => o } as any);
  if (u.includes("/v1/profile/")) {
    const name = u.split("/v1/profile/")[1].split("@")[0];
    return pubs[name] ? json({ pubkey: pubs[name], foreign_sats: 5 }) : { ok: false, status: 404, text: async () => "nope" } as any;
  }
  if (u.includes("/v1/send")) {
    sends.push({ to: new URL(u).searchParams.get("to")!, wire: new Uint8Array(init.body) });
    return { ok: true, status: 202, json: async () => ({ msg_id: "mid", status: "sent" }) } as any;
  }
  throw new Error("unexpected fetch " + u);
}) as any;

const sender = newPrivKey();
const decode = (wire: Uint8Array, priv: Uint8Array) => {
  const env = decodeEnvelope(wire);
  const aad = new Uint8Array([...env[TAG.RecipientHash], ...env[TAG.MsgID]]);
  return { env, payload: JSON.parse(new TextDecoder().decode(decryptPayload(priv, env[TAG.Ephemeral], env[TAG.Payload], aad))) };
};

const out = await composeAndSend("http://mock", "tok", sender, {
  to: "bob, BOB", cc: "carol;bob", subject: "s", body: "b", from: "alice@x",
});
eq("fan-out: one envelope per unique recipient", sends.map(s => s.to), ["bob", "carol"]);
ok(!!out.results && out.results.length === 2 && out.results.every(r => r.ok), "fan-out: both results ok");
const dB = decode(sends[0].wire, privB), dC = decode(sends[1].wire, privC);
eq("bob headers", dB.payload.headers, { To: "bob", Cc: "carol", From: "alice@x" });
eq("carol headers", dC.payload.headers, { To: "bob", Cc: "carol", From: "alice@x" });
eq("carol body", [dC.payload.subject, dC.payload.body], ["s", "b"]);
ok(toHex(dB.env[TAG.MsgID]) !== toHex(dC.env[TAG.MsgID]), "distinct msg_id per fan-out envelope (relay uniqueness)");

// single recipient: verbatim server answer, no Cc/From noise beyond what's given
sends.length = 0;
const one = await composeAndSend("http://mock", "tok", sender, { to: "carol", subject: "x", body: "y" });
eq("single: one send", sends.length, 1);
eq("single: server answer verbatim", [one.msg_id, one.status, (one as any).results], ["mid", "sent", undefined]);
eq("single: headers To only", decode(sends[0].wire, privC).payload.headers, { To: "carol" });

// partial failure: unknown cc recipient must not sink the good one
sends.length = 0;
const part = await composeAndSend("http://mock", "tok", sender, { to: "bob", cc: "nobody", subject: "x", body: "y" });
eq("partial: bob sent", sends.map(s => s.to), ["bob"]);
eq("partial: failure reported", part.failed, ["nobody"]);
ok(!!part.results && part.results[1].ok === false && !!part.results[1].error, "partial: per-recipient error recorded");

// total failure throws
let threw = false;
try { await composeAndSend("http://mock", "tok", sender, { to: "nobody", subject: "x", body: "y" }); } catch { threw = true; }
ok(threw, "all recipients failing throws");

globalThis.fetch = realFetch;
console.log("EXITCODE", process.exitCode || 0);
