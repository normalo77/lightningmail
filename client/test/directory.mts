// Etappe B: Directory-Integration gegen laufendes Relay (spec §7d).
// Ablauf: npx tsx test/directory.mts   (RELAY= ueberschreibbar, Default alpha 127.0.0.1:8443)
//
// Guthaben: der Test legt Konten per API an und laedt Testgeld direkt in die
// SQLite (BMAIL_DB, Default /var/lib/bmail/alpha/ledger.db) — Skill-Rezept.
// Ohne python3/DB-Zugriff werden die Kauf-Checks uebersprungen (SKIP).
import { newPrivKey, pubFromPriv, authSign, toHex } from "../src/crypto";
import { buildCardBytes, signCardBytes, makeConsent, cardToB64, cardFields, cardFromB64, verifyCard, cardHash } from "../src/directory";
import { execFileSync } from "node:child_process";

const base = process.env.RELAY || "http://127.0.0.1:8443";
const dbPath = process.env.BMAIL_DB || "/var/lib/bmail/alpha/ledger.db";
const ok = (c: boolean, m: string) => { console.log((c ? "PASS " : "FAIL ") + m); if (!c) process.exitCode = 1; };
const skip = (m: string) => console.log("SKIP " + m);

const post = (path: string, body: any) => fetch(base + path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });

async function mkAccount(tag: string) {
  const priv = newPrivKey();
  const name = `${tag}${Date.now().toString(36)}${Math.floor(Math.random() * 1e4).toString(36)}`.slice(0, 32);
  const r = await post("/v1/account", { name, pubkey: toHex(pubFromPriv(priv)) });
  if (!r.ok) throw new Error(`account ${name}: ${r.status} ${await r.text()}`);
  const a = await post("/v1/auth", { address: name, pubkey_hex: toHex(pubFromPriv(priv)), sig: toHex(authSign(priv, name)) });
  if (!a.ok) throw new Error(`auth ${name}: ${a.status}`);
  return { name, priv, token: ((await a.json()) as any).token as string };
}

const topUp = (name: string, msat: number): boolean => {
  try {
    execFileSync("python3", ["-c",
      `import sqlite3,sys; db=sqlite3.connect(sys.argv[1]); db.execute("UPDATE account SET balance_msat=balance_msat+? WHERE name=?", (${msat}, sys.argv[2])); db.commit(); print(db.execute("SELECT balance_msat FROM account WHERE name=?", (sys.argv[2],)).fetchone()[0])`,
      dbPath, name]);
    return true;
  } catch { return false; }
};

// --- Konten ---
const seller = await mkAccount("dirsel");
const buyer = await mkAccount("dirbuy");
const stranger = await mkAccount("dirstr");
console.log(`seller=${seller.name} buyer=${buyer.name} relay=${base}`);

// --- PUT /v1/profile Validierung ---
const auth = (t: string, extra: Record<string, string> = {}) => ({ "Content-Type": "application/json", Authorization: `Bearer ${t}`, ...extra });
const fields = { name: "Testseller", email: "s@example.org", note: "hello directory" };
const cardBytes = buildCardBytes(fields);
const sig = signCardBytes(seller.priv, cardBytes);
const consent = makeConsent(cardBytes);
const put = (tok: string, body: any) => fetch(base + "/v1/profile", { method: "PUT", headers: auth(tok), body: JSON.stringify(body) });

let r = await put(seller.token, { card_b64: cardToB64(cardBytes), sig, consent, price_meur: 25 });
ok(r.status === 200, `PUT eigene Karte -> 200 (${r.status})`);
const putResp = await r.json() as any;
ok(putResp.card_hash === cardHash(cardBytes), "card_hash = sha256(Kartenbytes)");

// Signatur mit falschem Key -> 403
r = await put(stranger.token, { card_b64: cardToB64(cardBytes), sig, consent, price_meur: 25 });
ok(r.status === 403, `PUT mit fremder Signatur -> 403 (${r.status})`);

// Consent-Feld passt nicht zur Karte -> 400
r = await put(seller.token, { card_b64: cardToB64(cardBytes), sig, consent: { ...consent, fields: ["name"] }, price_meur: 25 });
ok(r.status === 400, `PUT consent.fields != Kartenfelder -> 400 (${r.status})`);

// Consent-Version falsch -> 400
r = await put(seller.token, { card_b64: cardToB64(cardBytes), sig, consent: { ...consent, v: "gdpr0" }, price_meur: 25 });
ok(r.status === 400, `PUT consent.v != gdpr1 -> 400 (${r.status})`);

// Unauth -> 401
r = await fetch(base + "/v1/profile", { method: "PUT", headers: { "Content-Type": "application/json" }, body: "{}" });
ok(r.status === 401, `PUT ohne Token -> 401 (${r.status})`);

// --- Gratis-Lookup ---
r = await fetch(`${base}/v1/profile/${seller.name}`);
let look = await r.json() as any;
ok(r.status === 200 && look.has_card === true && look.pubkey === toHex(pubFromPriv(seller.priv)), "Gratis-Lookup: Key + has_card");
ok(look.total_meur === look.price_meur + look.fee_meur && look.price_meur === 25, `Lookup-Preise: total=${look.total_meur} price=${look.price_meur} fee=${look.fee_meur}`);
ok(look.card_b64 === undefined, "Gratis-Lookup verrät keinen Karteninhalt");

// --- Karten-Kauf ---
const canMoney = topUp(buyer.name, 10_000_000); // 10k sats Testgeld
if (!canMoney) {
  skip(`Kauf-Checks (kein sqlite-Zugriff auf ${dbPath})`);
} else {
  // GET vor Kauf -> 402 mit Angebot
  r = await fetch(`${base}/v1/profile/${seller.name}/card`, { headers: auth(buyer.token) });
  const offer = await r.json() as any;
  ok(r.status === 402 && offer.card_hash === putResp.card_hash && offer.total_meur > 0, `GET card ungekauft -> 402 + Angebot (${r.status})`);

  // POST Kauf
  r = await fetch(`${base}/v1/profile/${seller.name}/card`, { method: "POST", headers: auth(buyer.token) });
  const bought = await r.json() as any;
  ok(r.status === 200 && bought.purchased === true && bought.paid?.fresh === true, `POST card -> 200, fresh=true (${r.status})`);
  ok(verifyCard(bought.pubkey, cardFromB64(bought.card_b64), bought.sig), "Kartensignatur client-seitig gültig (BIP340)");
  ok(JSON.stringify(cardFields(bought)) === JSON.stringify(fields), "Karteninhalt = veröffentlichte Felder");
  const paidMsat = bought.paid?.total_msat ?? 0;
  ok(paidMsat > 0 && bought.paid?.seller_msat > 0 && bought.paid?.seller_msat <= paidMsat, `Split: paid=${paidMsat} seller=${bought.paid?.seller_msat} fee=${paidMsat - (bought.paid?.seller_msat ?? 0)}`);

  // Dedup: nochmal kaufen kostet nichts
  const balR = await fetch(base + "/v1/balance", { headers: auth(buyer.token) });
  const bal1 = (await balR.json() as any).balance_msat;
  r = await fetch(`${base}/v1/profile/${seller.name}/card`, { method: "POST", headers: auth(buyer.token) });
  const again = await r.json() as any;
  const bal2 = ((await (await fetch(base + "/v1/balance", { headers: auth(buyer.token) })).json()) as any).balance_msat;
  ok(r.status === 200 && again.paid?.fresh === false && bal1 === bal2, `Dedup: 2. Kauf fresh=false, Guthaben unverändert (${bal1}=${bal2})`);

  // GET nach Kauf -> 200 ohne neue Buchung
  r = await fetch(`${base}/v1/profile/${seller.name}/card`, { headers: auth(buyer.token) });
  ok(r.status === 200 && (await r.json() as any).purchased === true, "GET card nach Kauf -> 200");

  // Fremder ohne Kauf -> weiter 402
  r = await fetch(`${base}/v1/profile/${seller.name}/card`, { headers: auth(stranger.token) });
  ok(r.status === 402, `GET card (Unbeteiligter) -> 402 (${r.status})`);

  // Kauf ohne Guthaben -> 402 (Angebot) statt 500
  const poor = await mkAccount("dirpoor");
  r = await fetch(`${base}/v1/profile/${seller.name}/card`, { method: "POST", headers: auth(poor.token) });
  ok(r.status === 402, `POST card ohne Guthaben -> 402 (${r.status})`);

  // ?cur=ltc -> 400 (§26: Etappe B kennt nur btc)
  r = await fetch(`${base}/v1/profile/${seller.name}/card?cur=ltc`, { method: "POST", headers: auth(buyer.token) });
  ok(r.status === 400, `POST card ?cur=ltc -> 400 (${r.status})`);

  // Steuerstempel (§25 G1): card_in des Sellers muss Kurs-Snapshot tragen,
  // wenn das Relay einen Kurs hat (manual_eur_per_btc im Regtest-Config).
  const hasRate = !!(bought.paid?.rate?.meur_per_btc > 0);
  if (hasRate) {
    try {
      const eur = execFileSync("python3", ["-c",
        `import sqlite3,sys; db=sqlite3.connect(sys.argv[1]);
row = db.execute("""SELECT t.kind, t.currency, t.eur_micro, t.rate_src FROM txlog t JOIN account a ON a.id=t.account_id WHERE a.name=? AND t.kind='card_in' ORDER BY t.id DESC LIMIT 1""", (sys.argv[2],)).fetchone()
print("|".join(str(x) for x in row))`,
        dbPath, seller.name]).toString().trim();
      const [kind, currency, eurMicro, rateSrc] = eur.split("|");
      ok(kind === "card_in" && currency === "btc" && Number(eurMicro) > 0 && rateSrc === "manual",
        `Steuerstempel card_in: eur_micro=${eurMicro} currency=${currency} rate_src=${rateSrc}`);
    } catch (e: any) { skip("Steuerstempel-Prüfung (sqlite): " + String(e.message).slice(0, 80)); }
  } else {
    skip("Steuerstempel-Prüfung (Relay ohne Kurs konfiguriert)");
  }
}

// --- DELETE = DSGVO-Löschung ---
{
  const r1 = await fetch(base + "/v1/profile", { method: "DELETE", headers: auth(seller.token) });
  ok(r1.status === 200, `DELETE eigene Karte -> 200 (${r1.status})`);
  const r2 = await fetch(`${base}/v1/profile/${seller.name}`);
  const look2 = await r2.json() as any;
  ok(r2.status === 200 && look2.has_card === false, "Lookup nach DELETE: Key bleibt, has_card=false");
  const r3 = await fetch(`${base}/v1/profile/${seller.name}/card`, { headers: auth(buyer.token) });
  const r4 = await fetch(`${base}/v1/profile/${seller.name}/card`, { headers: auth(stranger.token) });
  ok(r3.status === 410, `card GET nach DELETE (Zahler) -> 410 Achtungs-Note (${r3.status})`);
  ok(r4.status === 404, `card GET nach DELETE (Fremder) -> 404 (${r4.status})`);
}

// --- 429-Budget fuer anonyme Massen-Lookups ---
{
  const burst: number[] = [];
  for (let i = 0; i < 80; i++) {
    burst.push((await fetch(`${base}/v1/profile/${seller.name}`)).status);
  }
  ok(burst.includes(429), `80 anonyme Lookups -> mindestens ein 429 (${burst.filter(s => s === 429).length}×429)`);
  ok(burst[0] === 200, "erster Lookup bleibt 200");
}

console.log("EXITCODE", process.exitCode || 0);
