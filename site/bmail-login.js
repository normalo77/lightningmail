// bmail-login.js — „Sign in with lightningmail“ als eine Datei.
// Kein Build, keine Abhängigkeiten. https://lightningmail.app/embed
//
// Einbau:
//   <script src="/bmail-login.js" defer></script>
//   <bmail-login issuer="https://relay-a.lightningmail.app" label="Mit lightningmail anmelden"></bmail-login>
//
// Der Klick startet einen sauberen OIDC-Flow (PKCE S256, state, nonce) als Popup;
// das Popup landet auf redirect_uri (Eure Callback-Seite), die mit
// bmailLogin.finishPopup() Code+verifier an UNSEREN Server schickt — die
// Verifikation passiert serverseitig (CORS-frei, Client-Secrets gibt es nicht).
// Beendet wird der Login mit bmailLogin.success(claims) / .fail(reason).
window.bmailLogin = (() => {
  const SS_KEY = "bmail-…h-";
  const rand = (n) => {
    const b = new Uint8Array(n);
    crypto.getRandomValues(b);
    return b;
  };
  const b64u = (b) =>
    btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

  async function start(opts) {
    const issuer = (opts.issuer || "").replace(/\/+$/, "");
    if (!issuer) throw new Error("bmail-login: issuer fehlt");
    // Kein Discovery-Fetch noetig: /oidc/auth ist fester Teil des Profils
    // (Discovery gibt es natuerlich trotzdem, serverseitig: /.well-known/...).
    const verifier = b64u(rand(48));
    const challenge = b64u(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)));
    const state = b64u(rand(16));
    const nonce = b64u(rand(12));
    const redirect = opts.redirect || location.origin + location.pathname;
    sessionStorage.setItem(SS_KEY + state, JSON.stringify({ verifier, nonce, issuer }));
    const q = new URLSearchParams({
      response_type: "code",
      client_id: opts.client_id || location.origin,
      redirect_uri: redirect,
      scope: opts.scope || "openid email",
      state,
      nonce,
      code_challenge: challenge,
      code_challenge_method: "S256",
    });
    return { url: issuer + "/oidc/auth?" + q, state };
  }

  // Popup-Modus: opener-Seite ruft das hier am Button-Klick.
  async function popup(opts) {
    const { url } = await start(opts);
    const w = window.open(url, "bmail_login", "width=480,height=640");
    if (!w) {
      location.href = url; // Popup blockiert -> klassischer Redirect
      return new Promise(() => {});
    }
    return new Promise((resolve, reject) => {
      const on = (ev) => {
        // Callback-Seite läuft auf UNSERER Origin (redirect_uri) — postMessage
        // akzeptieren wir ausschließlich von ihr, nie vom Relay.
        if (ev.origin !== location.origin) return;
        if (ev.data && ev.data.bmail_login) {
          window.removeEventListener("message", on);
          ev.data.bmail_login.ok ? resolve(ev.data.bmail_login.claims) : reject(ev.data.bmail_login.error);
        }
      };
      window.addEventListener("message", on);
    });
  }

  // Callback-Seite (im Popup geöffnet, gleiche URL mit ?code=&state=):
  // übergibt Code+verifier an den eigenen Server und meldet das Ergebnis
  // zurück zum opener. serverVerify ist eine function(code, verifier, state,
  // nonce) => Promise<{claims}|throw — nur diese Zeile Code ist Euer Backend.
  async function finishPopup(serverVerify) {
    if (!opener || !window.opener) return null;
    const q = new URLSearchParams(location.search);
    const code = q.get("code"), state = q.get("state");
    // opener und Callback-Seite teilen sich die Origin (redirect_uri-Pflicht);
    // postMessage geht NIE an eine aus Params/Rerrer gewonnene Herkunft.
    const post = (msg) => {
      try { window.opener.postMessage(msg, location.origin); window.close(); } catch (e) {}
    };
    if (q.get("error")) return post({ bmail_login: { ok: false, error: q.get("error") } });
    if (!code || !state) return null;
    const saved = JSON.parse(sessionStorage.getItem(SS_KEY + state) || "null");
    if (!saved) return post({ bmail_login: { ok: false, error: "state unbekannt" } });
    sessionStorage.removeItem(SS_KEY + state);
    try {
      const claims = await serverVerify(code, saved.verifier, state, saved.nonce, saved.issuer);
      post({ bmail_login: { ok: true, claims } });
    } catch (e) {
      post({ bmail_login: { ok: false, error: String(e && e.message || e) } });
    }
    return "done";
  }

  // Custom Element: <bmail-login issuer="..." label="..." redirect="..."></bmail-login>
  class El extends HTMLElement {
    connectedCallback() {
      const b = document.createElement("button");
      b.type = "button";
      b.className = "bmail-btn";
      b.textContent = this.getAttribute("label") || "⚡ Sign in with lightningmail";
      b.style.cssText =
        "font:600 15px/1 system-ui;padding:12px 20px;border:0;border-radius:10px;cursor:pointer;" +
        "background:#f7931a;color:#fff";
      b.onclick = async () => {
        b.disabled = true;
        try {
          const claims = await popup({
            issuer: this.getAttribute("issuer"),
            client_id: this.getAttribute("client_id"),
            redirect: this.getAttribute("redirect"),
            scope: this.getAttribute("scope"),
          });
          this.dispatchEvent(new CustomEvent("bmail-login", { detail: { claims }, bubbles: true }));
        } catch (e) {
          this.dispatchEvent(new CustomEvent("bmail-login-error", { detail: { error: String(e) }, bubbles: true }));
        }
        b.disabled = false;
      };
      this.appendChild(b);
    }
  }
  if (!customElements.get("bmail-login")) customElements.define("bmail-login", El);

  return { start, popup, finishPopup };
})();
