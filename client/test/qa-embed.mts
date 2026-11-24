// qa-embed.mts — Embed-Kit E2E: Account auf relay-a, echter OIDC-Flow
// (auth->login->sign->code), dann Verifikation ueber den Produktiv-RP
// https://lightningmail.app/api/embed/verify. Ausfuehrung: npx tsx qa-embed.mts
import { newPrivKey, pubFromPriv, authSign, toHex, schnorr, sha256 } from "../src/crypto";

const ISS = process.env.ISS || "https://relay-a.lightningmail.app";
const RP = process.env.RP || "https://lightningmail.app";
const CLIENT_ID = RP + ""; // origin, ohne Pfad
const REDIRECT = RP + "/embed-demo";
const ok = (c: unknown, m: string) => { console.log((c ? "PASS " : "FAIL ") + m); if (!c) process.exit(1); };

const b64u = (b: Uint8Array) => btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const rnd = (n: number) => { const b = new Uint8Array(n); crypto.getRandomValues(b); return b; };

const priv = newPrivKey();
const pub = toHex(pubFromPriv(priv));
const name = "embed" + Date.now().toString(36);
let r = await fetch(ISS + "/v1/account", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name, pubkey: pub }) });
ok(r.ok, `account ${name} angelegt (${r.status})`);
r = await fetch(ISS + "/v1/auth", { method: "POST", headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ address: name, pubkey_hex: pub, sig: toHex(authSign(priv, name)) }) });
const bearer = ((await r.json()) as any).token as string;
ok(!!bearer, "bearer token");

const verifier = b64u(rnd(48));
const challenge = b64u(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))));
const state = b64u(rnd(9)), nonce = b64u(rnd(12));
const q = new URLSearchParams({ response_type: "code", client_id: CLIENT_ID, redirect_uri: REDIRECT,
  scope: "openid email", state, nonce, code_challenge: challenge, code_challenge_method: "S256" });
r = await fetch(ISS + "/oidc/auth?" + q, { redirect: "manual" });
const sid = new URL(r.headers.get("location") || "").searchParams.get("sid");
ok(r.status === 302 && sid, `auth request -> consent (${r.status})`);

r = await fetch(ISS + "/oidc/auth/login", { method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${bearer}` }, body: JSON.stringify({ sid }) });
const lj = await r.json() as any;
ok(r.ok && !!lj.challenge_b64, `login -> challenge ${lj.address}`);

const ch = Uint8Array.from(atob(lj.challenge_b64), (c) => c.charCodeAt(0));
r = await fetch(ISS + "/oidc/auth/sign", { method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${bearer}` },
  body: JSON.stringify({ sid, sig: toHex(schnorr.sign(new Uint8Array(sha256(ch)), priv)) }) });
const sj = await r.json() as any;
ok(r.ok && (sj.redirect || "").includes("code="), "sign -> code redirect");
const code = new URL(sj.redirect).searchParams.get("code")!;

r = await fetch(RP + "/api/embed/verify", { method: "POST", headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ code, verifier, nonce, client_id: CLIENT_ID, redirect_uri: REDIRECT, issuer: ISS }) });
const v = await r.json() as any;
ok(r.ok && v.claims?.email === `${name}@lightningmail.app`, `produktiv-RP verifiziert: ${JSON.stringify(v.claims?.email || v.error)}`);
ok(v.claims?.email_verified === true && !!v.claims?.bmail, "email_verified + bmail-Claim");
console.log("bmail claim pubkey:", v.claims.bmail?.pubkey?.slice?.(0, 16) || JSON.stringify(v.claims.bmail).slice(0, 40));

// Wiedervorlage desselben Codes muss scheitern
r = await fetch(RP + "/api/embed/verify", { method: "POST", headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ code, verifier, nonce, client_id: CLIENT_ID, redirect_uri: REDIRECT, issuer: ISS }) });
ok(!r.ok, "code replay abgelehnt (RP-Antwort " + r.status + ")");
