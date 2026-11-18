// provision-card-seller.mts — UI-Abnahme Etappe B: legt 'kartler' auf RELAY an
// und veroeffentlicht eine signierte Karte. Einweg-Testlaufdaten.
import { newPrivKey, pubFromPriv, authSign, toHex } from "../src/crypto";
import { buildCardBytes, signCardBytes, makeConsent, cardToB64 } from "../src/directory";

const base = process.env.RELAY || "http://127.0.0.1:8443";
const priv = newPrivKey();
const name = "kartler";

let r = await fetch(base + "/v1/account", { method: "POST", headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ name, pubkey: toHex(pubFromPriv(priv)) }) });
if (!r.ok && r.status !== 409) throw new Error("account: " + r.status + " " + await r.text());
console.log("account:", r.status === 409 ? "existiert schon (neuer Key passt NICHT)" : "angelegt");
if (r.status === 409) process.exit(1);

r = await fetch(base + "/v1/auth", { method: "POST", headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ address: name, pubkey_hex: toHex(pubFromPriv(priv)), sig: toHex(authSign(priv, name)) }) });
const token = ((await r.json()) as any).token;
if (!token) throw new Error("auth fehlgeschlagen");

const fields = { name: "Kartenleger", given: "Karl", org: "Auskunftei GmbH", email: "karl@example.org" };
const b = buildCardBytes(fields);
r = await fetch(base + "/v1/profile", { method: "PUT",
  headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
  body: JSON.stringify({ card_b64: cardToB64(b), sig: signCardBytes(priv, b), consent: makeConsent(b), price_meur: 25 }) });
console.log("profile PUT:", r.status, await r.text());
const look = await (await fetch(base + "/v1/profile/" + name)).json();
console.log("lookup:", JSON.stringify(look));
