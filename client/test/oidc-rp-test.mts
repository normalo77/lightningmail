// oidc-rp-test.mts — IdP-Abnahme: simuliert einen Standard-OIDC-Dienst (RP)
// gegen das laufende Relay — Discovery, Authorization-Code + PKCE (S256),
// ES256-JWT-Verify via WebCrypto gegen JWKS, bmail-BIP340-Claim, UserInfo,
// Code-Replay. Login-Schritt der PWA wird per Bearer-Token nachgestellt.
// Ablauf: npx tsx test/oidc-rp-test.mts   (RELAY= ueberschreibbar)
import { newPrivKey, pubFromPriv, authSign, toHex, fromHex, schnorr, sha256, verifySchnorr } from "../src/crypto";

const base = process.env.RELAY || "http://127.0.0.1:8443";
const ok = (c: boolean, m: string) => { console.log((c ? "PASS " : "FAIL ") + m); if (!c) process.exitCode = 1; };

const b64u = (b: ArrayBuffer | Uint8Array) =>
  btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

// --- Konto anlegen + Bearer-Token (steht fuer den PWA-Login-Schritt) ---
const priv = newPrivKey();
const name = "oidc" + Date.now().toString(36);
let r = await fetch(base + "/v1/account", { method: "POST", headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ name, pubkey: toHex(pubFromPriv(priv)) }) });
if (!r.ok) throw new Error("account: " + r.status);
r = await fetch(base + "/v1/auth", { method: "POST", headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ address: name, pubkey_hex: toHex(pubFromPriv(priv)), sig: toHex(authSign(priv, name)) }) });
const token = ((await r.json()) as any).token as string;
if (!token) throw new Error("auth fehlgeschlagen");

// --- 1. Discovery ---
const disc = await (await fetch(base + "/.well-known/openid-configuration")).json() as any;
ok(!!disc.issuer && disc.token_endpoint?.endsWith("/oidc/token"), `Discovery: issuer=${disc.issuer}`);
const ep = (abs: string) => base + abs.replace(disc.issuer, ""); // lokal gegen 127.0.0.1 statt Tunnel

// --- 2. RP: PKCE + Authorization Request ---
const verifier = b64u(crypto.getRandomValues(new Uint8Array(48)));
const challenge = b64u(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)));
const state = b64u(crypto.getRandomValues(new Uint8Array(9)));
const redirectUri = disc.issuer + "/oidc/demo-callback.html"; // registrierte Demo-Callback
const authUrl = ep(disc.authorization_endpoint) + "?" + new URLSearchParams({
  response_type: "code", client_id: "demo",
  redirect_uri: redirectUri,
  scope: "openid email profile", state, nonce: "n-tsx",
  code_challenge: challenge, code_challenge_method: "S256",
});
r = await fetch(authUrl, { redirect: "manual" });
const loc = r.headers.get("location") || "";
ok(r.status === 302 && loc.includes("sid="), `Auth-Request -> 302 Login (${r.status})`);
const sid = new URL(loc).searchParams.get("sid")!;

// --- 3. PWA-Login-Schritt: Bearer gegen Challenge ---
r = await fetch(ep(disc.issuer) + "/oidc/auth/login", { method: "POST",
  headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
  body: JSON.stringify({ sid }) });
const lj = await r.json() as any;
ok(r.status === 200 && !!lj.challenge_b64, `auth/login -> Challenge (${r.status})`);
const addrDomain = disc.issuer.replace(/^https?:\/\/[^.]+\./, ""); // relay-X.<domain> → <domain>
ok(lj.address === `${name}@lightningmail.app` || lj.address === `${name}@${addrDomain}`,
  `Adresse im Consent: ${lj.address}`);

// --- 4. BIP340-Signatur der Challenge mit dem Mailbox-Key ---
const chBytes = Uint8Array.from(atob(lj.challenge_b64), (c) => c.charCodeAt(0));
const sig = toHex(schnorr.sign(new Uint8Array(sha256(chBytes)), priv));
r = await fetch(ep(disc.issuer) + "/oidc/auth/sign", { method: "POST",
  headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
  body: JSON.stringify({ sid, sig }) });
const sj = await r.json() as any;
ok(r.status === 200 && sj.redirect?.includes("code="), `auth/sign -> Redirect mit Code (${r.status})`);
const ru = new URL(sj.redirect);
const code = ru.searchParams.get("code")!;
ok(ru.searchParams.get("state") === state, "state im Redirect stimmt (CSRF)");

// --- 5. Token-Exchange + ES256-Verify gegen JWKS ---
r = await fetch(ep(disc.token_endpoint), { method: "POST",
  headers: { "Content-Type": "application/x-www-form-urlencoded" },
  body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: ru.origin + ru.pathname,
    client_id: "demo", code_verifier: verifier }) });
const tok = await r.json() as any;
ok(r.status === 200 && !!tok.id_token && tok.token_type === "Bearer", `Token-Endpoint -> id_token (${r.status})`);
const [h64, p64, s64] = String(tok.id_token).split(".");
const b64json = (s: string) => JSON.parse(new TextDecoder().decode(
  Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0))));
const claims = b64json(p64);
ok(claims.iss === disc.issuer && claims.aud === "demo" && claims.nonce === "n-tsx", "Claims iss/aud/nonce");
ok(claims.sub === lj.address && claims.email === lj.address && claims.email_verified === true,
  `sub/email = ${claims.sub}, email_verified=true`);
const jwks = await (await fetch(ep(disc.jwks_uri))).json() as any;
const hdr = b64json(h64);
const k = jwks.keys.find((x: any) => x.kid === hdr.kid);
ok(!!k && hdr.alg === "ES256", `JWKS-Key gefunden (kid=${hdr.kid}, alg=${hdr.alg})`);
const key = await crypto.subtle.importKey("jwk", { kty: k.kty, crv: k.crv, x: k.x, y: k.y, ext: true },
  { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
const sigOk = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key,
  Uint8Array.from(atob(s64.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0)),
  new TextEncoder().encode(h64 + "." + p64));
ok(sigOk, "ID-Token-Signatur gültig (ES256 via WebCrypto/JWKS)");

// --- 6. bmail-Föderations-Claim: BIP340 über der Challenge, Pubkey = Kontokkey ---
const bm = claims.bmail;
ok(!!bm && bm.pubkey === toHex(pubFromPriv(priv)) && bm.alg === "bip340-sha256", "bmail-Claim: Pubkey = Mailbox-Key");
ok(verifySchnorr(fromHex(bm.pubkey), chBytes, fromHex(bm.sig)), "bmail-Signatur über Challenge gültig (BIP340)");

// --- 7. UserInfo ---
r = await fetch(ep(disc.userinfo_endpoint), { headers: { Authorization: `Bearer ${tok.access_token}` } });
const ui = await r.json() as any;
ok(r.status === 200 && ui.sub === claims.sub && ui.email_verified === true, `UserInfo 200 (${ui.sub})`);

// --- 8. Code-Replay ---
r = await fetch(ep(disc.token_endpoint), { method: "POST",
  headers: { "Content-Type": "application/x-www-form-urlencoded" },
  body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: ru.origin + ru.pathname,
    client_id: "demo", code_verifier: verifier }) });
ok(r.status === 400, `Code-Replay -> 400 (${r.status})`);

console.log("EXITCODE", process.exitCode || 0);
