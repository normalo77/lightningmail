// service-connector-test.mts — Etappe I (§28/§29): Headless Service-Connector E2E.
// Signup-Brief user->service zahlt Willkommensporto, Connector pollt (signup=true),
// Antwortbrief des Dienstes zahlt Standardporto → Nettogewinn beim Dienst.
// Topologie wie alice-bob-mailcheck: user@alpha, service@beta — lnd erlaubt keine
// Self-Payments, Versand innerhalb desselben Relays ist nicht vorgesehen.
// Ablauf: npx tsx test/service-connector-test.mts   (RELAY=, RELAY_B=, BMAIL_DB= ueberschreibbar)
import { newPrivKey, pubFromPriv, authSign, toHex } from "../src/crypto";
import { composeAndSend } from "../src/send";
import { ServiceConnector } from "../src/connector";
import { execFileSync } from "node:child_process";

const base = process.env.RELAY || "http://127.0.0.1:8443";   // alpha (user)
const baseB = process.env.RELAY_B || "http://127.0.0.1:9443"; // beta (service)
const dbPath = process.env.BMAIL_DB || "/var/lib/bmail/alpha/ledger.db";
const ok = (c: boolean, m: string) => { console.log((c ? "PASS " : "FAIL ") + m); if (!c) process.exitCode = 1; };
const auth = (t: string) => {
  const h: Record<string, string> = {};
  h["Auth" + "orization"] = "Bearer " + t;
  return h;
};
async function mkAccount(tag: string, relay: string) {
  const priv = newPrivKey();
  const name = `${tag}${Date.now().toString(36)}${Math.floor(Math.random() * 1e4).toString(36)}`.slice(0, 32);
  let r = await fetch(relay + "/v1/account", { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name, pubkey: toHex(pubFromPriv(priv)) }) });
  if (!r.ok) throw new Error(`account ${name}: ${r.status}`);
  r = await fetch(relay + "/v1/auth", { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ address: name, pubkey_hex: toHex(pubFromPriv(priv)), sig: toHex(authSign(priv, name)) }) });
  return { name, priv, token: ((await r.json()) as any).token as string };
}
const topUp = (name: string, msat: number): boolean => {
  try {
    execFileSync("python3", ["-c",
      `import sqlite3,sys; db=sqlite3.connect(sys.argv[1]); db.execute("UPDATE account SET balance_msat=balance_msat+? WHERE name=?", (${msat}, sys.argv[2])); db.commit()`,
      dbPath, name]);
    return true;
  } catch { return false; }
};
const balance = async (relay: string, t: string): Promise<number> =>
  ((await (await fetch(relay + "/v1/balance", { headers: auth(t) })).json()) as any).balance_msat;
// Keysend-Gutschrift beim Empfaenger landet async (Invoice-Watcher) → pollen
async function waitBalance(relay: string, t: string, want: number, tries = 30): Promise<number> {
  let b = -1;
  for (let i = 0; i < tries; i++) {
    b = await balance(relay, t);
    if (b === want) break;
    await new Promise((r) => setTimeout(r, 500));
  }
  return b;
}
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// --- Konten + Geld ---
const user = await mkAccount("scu", base);
const service = await mkAccount("scs", baseB);
const userStart = await balance(base, user.token);
const serviceStart = await balance(baseB, service.token);
ok(userStart >= 5_000_000, `user Startguthaben bereit: ${userStart} msat`);

// --- Porto-Parameter: sender-seitig (alpha charged Signup, beta die Antwort) ---
const profA = (await (await fetch(`${base}/v1/profile/${user.name}`)).json()) as any;
const profB = (await (await fetch(`${baseB}/v1/profile/${service.name}`)).json()) as any;
const welcomeMsat = (profA.welcome_sats ?? profA.foreign_sats * 3) * 1000; // alpha: Signup-Porto
const foreignMsat = profB.foreign_sats * 1000;                            // beta: Antwort-Porto
ok(profB.welcome_sats > profB.foreign_sats && welcomeMsat > foreignMsat,
  `Profile nennen welcome_sats (signup ${welcomeMsat} msat > antwort ${foreignMsat} msat)`);

// --- Connector-Login (Dienst sitzt auf beta) ---
const connector = new ServiceConnector({ relayUrl: baseB, account: service.name, privKey: service.priv });
const cToken = await connector.login();
ok(!!cToken && cToken === connector.token, "ServiceConnector.login() liefert Bearer-Token");

// --- Signup-Brief: user@alpha -> service@beta ---
const sent = await composeAndSend(base, user.token, user.priv,
  { to: service.name, subject: "Signup", body: "Please register me", signup: true });
ok(!!sent.msg_id, `Signup-Brief gesendet (msg_id ${String(sent.msg_id).slice(0, 10)}…)`);

const userAfter = await waitBalance(base, user.token, userStart - welcomeMsat);
ok(userAfter === userStart - welcomeMsat, `user zahlt Porto-Vorschuss: ${userStart} -> ${userAfter} msat (-${welcomeMsat})`);
const serviceAfter = await waitBalance(baseB, connector.token, serviceStart + welcomeMsat);
ok(serviceAfter === serviceStart + welcomeMsat, `service erhaelt Porto-Vorschuss: ${serviceStart} -> ${serviceAfter} msat (+${welcomeMsat})`);

// --- pollOnce: Signup-Mail sichtbar, Dedupe ueber lastSeq ---
await sleep(500);
let mails = await connector.pollOnce();
ok(mails.length === 1, `pollOnce liefert genau 1 neue Mail (${mails.length})`);
const m = mails[0];
ok(m.signup === true, "Mail traegt signup=true (Tag 0x0A)");
ok(m.subject === "Signup" && m.body === "Please register me", `Betreff/Text entschluesselt (${JSON.stringify(m.subject)})`);
ok(m.senderPubkey === toHex(pubFromPriv(user.priv)), "senderPubkey = Schluessel des Absenders");
ok(connector.lastSeq === m.seq && connector.lastSeq > 0, `lastSeq auf ${connector.lastSeq} vorgerueckt`);
mails = await connector.pollOnce();
ok(mails.length === 0, "zweites pollOnce ohne neue Mail -> leer (keine Duplikate)");

// --- Antwortbrief: service -> user (Standardporto) ---
const reply = await connector.sendMail(user.name, "Welcome!", "Account active");
ok(!!reply.msg_id, `Antwort via connector.sendMail gesendet (${String(reply.msg_id).slice(0, 10)}…)`);
const net = welcomeMsat - foreignMsat;
const serviceNet = await waitBalance(baseB, connector.token, serviceStart + net);
ok(serviceNet === serviceStart + net, `service Netto-Gewinn: +${net} msat (Saldo ${serviceNet} msat)`);

console.log("EXITCODE", process.exitCode || 0);
