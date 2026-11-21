package relaysrv

// oidcDemoPage = embedded demo RP (Relying Party) to click through:
// starts the authorization code flow with PKCE against this relay, exchanges
// the code for tokens and verifies the ID token (ES256 via WebCrypto
// against /oidc/jwks). Pure static JS — no build dependency.
const oidcDemoPage = `<!doctype html>
<html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Demo-Dienst — Sign in with lightningmail</title>
<style>
 body{font-family:"MS Sans Serif",Arial,sans-serif;background:#008080;margin:0;padding:24px;font-size:13px}
 .window{background:#c0c0c0;border:2px outset #dfdfdf;max-width:640px;margin:0 auto;box-shadow:2px 2px 0 #000}
 .title-bar{background:linear-gradient(90deg,#000080,#1084d0);color:#fff;padding:3px 6px;font-weight:700}
 .body{padding:12px}
 button{font:inherit;padding:4px 12px;border:2px outset #dfdfdf;background:#c0c0c0;cursor:pointer;min-height:32px}
 button:active{border-style:inset}
 pre{background:#fff;border:2px inset #dfdfdf;padding:8px;white-space:pre-wrap;word-break:break-all;font-size:11px;max-height:260px;overflow:auto}
 .ok{color:#006400;font-weight:700}.bad{color:#8b0000;font-weight:700}
 .meta{color:#444;font-size:12px}
</style></head><body>
<div class="window"><div class="title-bar">🔐 Demo-Dienst — „Mit lightningmail anmelden"</div>
<div class="body">
<p class="meta">Diese Seite spielt einen fremden Dienst (Relying Party): Authorization-Code-Flow
mit PKCE (S256), Standard-OIDC — kein Lightning-Wissen nötig. Der <b>bmail-Claim</b> im ID-Token
trägt zusätzlich den BIP340-Föderationsbeweis (Mailbox-Pubkey + Signatur über die Login-Challenge).</p>
<p><button id="go">Mit lightningmail anmelden</button></p>
<div id="out"></div>
</div></div>
<script>
var REDIRECT = location.origin + "/oidc/demo-callback.html";
var CLIENT = "demo";
function b64u(buf){ return btoa(String.fromCharCode.apply(null, new Uint8Array(buf))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,""); }
function rnd(n){ var b = new Uint8Array(n); crypto.getRandomValues(b); return b64u(b); }
async function sha256b64u(s){ var d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)); return b64u(d); }
function out(html){ document.getElementById("out").innerHTML = html; }

async function start(){
  var verifier = rnd(48);
  var challenge = await sha256b64u(verifier);
  sessionStorage.setItem("oidc_verifier", verifier);
  sessionStorage.setItem("oidc_state", rnd(12));
  var p = new URLSearchParams({
    response_type: "code", client_id: CLIENT, redirect_uri: REDIRECT,
    scope: "openid email profile", state: sessionStorage.getItem("oidc_state"),
    nonce: rnd(12), code_challenge: challenge, code_challenge_method: "S256"
  });
  location.href = "/oidc/auth?" + p.toString();
}

async function exchange(code, state){
  var verifier = sessionStorage.getItem("oidc_verifier");
  var expectState = sessionStorage.getItem("oidc_state");
  sessionStorage.removeItem("oidc_verifier"); sessionStorage.removeItem("oidc_state");
  if (state !== expectState) { out('<p class="bad">✗ state stimmt nicht (CSRF-Schutz)</p>'); return; }
  var body = new URLSearchParams({ grant_type:"authorization_code", code:code, redirect_uri:REDIRECT, client_id:CLIENT, code_verifier:verifier });
  var tr = await fetch("/oidc/token", { method:"POST", headers:{"Content-Type":"application/x-www-form-urlencoded"}, body:body });
  var tok = await tr.json();
  if (!tr.ok) { out('<p class="bad">Token-Endpoint: ' + JSON.stringify(tok) + '</p>'); return; }
  var parts = tok.id_token.split(".");
  var claims = JSON.parse(decodeURIComponent(escape(atob(parts[1].replace(/-/g,"+").replace(/_/g,"/")))));
  // ES256-Signatur gegen JWKS verifizieren (WebCrypto, Standard)
  var sigOk = false, sigNote = "";
  try {
    var hdr = JSON.parse(decodeURIComponent(escape(atob(parts[0].replace(/-/g,"+").replace(/_/g,"/")))));
    var jwks = await (await fetch("/oidc/jwks")).json();
    var k = jwks.keys.filter(function(x){return x.kid===hdr.kid;})[0];
    var key = await crypto.subtle.importKey("jwk", {kty:k.kty,crv:k.crv,x:k.x,y:k.y,ext:true}, {name:"ECDSA",namedCurve:"P-256"}, false, ["verify"]);
    var sig = Uint8Array.from(atob(parts[2].replace(/-/g,"+").replace(/_/g,"/")), function(c){return c.charCodeAt(0);});
    sigOk = await crypto.subtle.verify({name:"ECDSA",hash:"SHA-256"}, key, sig, new TextEncoder().encode(parts[0]+"."+parts[1]));
  } catch(e){ sigNote = String(e); }
  var ui = await fetch("/oidc/userinfo", { headers: { Authorization: "***"+tok.access_token } });
  var uiClaims = await ui.json();
  var html = '<p class="ok">✓ Angemeldet! ID-Token empfangen und Signatur ' + (sigOk ? '<span class="ok">gültig (ES256/JWKS)</span>' : '<span class="bad">UNGÜLTIG</span> ' + sigNote) + '</p>';
  html += '<p><b>Claims:</b></p><pre>' + JSON.stringify(claims, null, 2) + '</pre>';
  html += '<p><b>UserInfo:</b> ' + (ui.ok ? '<span class="ok">200</span>' : '<span class="bad">'+ui.status+'</span>') + '</p><pre>' + JSON.stringify(uiClaims, null, 2) + '</pre>';
  if (claims.bmail) {
    html += '<p class="meta">bmail-Föderationsbeweis: Pubkey ' + claims.bmail.pubkey.slice(0,12) + '… — BIP340-Signatur über die Login-Challenge. Dienste verifizieren Pubkey↔Adresse via Directory (GET /v1/profile/' + (claims.preferred_username||"") + ') und die Signatur mit einer secp256k1-Bibliothek.</p>';
  }
  out(html);
}

document.getElementById("go").onclick = start;
var qs = new URLSearchParams(location.search);
if (qs.get("code")) { exchange(qs.get("code"), qs.get("state")); }
else if (qs.get("error")) { out('<p class="bad">Fehler: ' + qs.get("error") + '</p>'); }
</script></body></html>`
