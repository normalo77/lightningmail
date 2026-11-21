// OIDC IdP (Etappe "IdP", CONCEPT §21/§29): "Sign in with lightningmail".
//
// Authorization code flow + PKCE (S256 mandatory, public clients — no secret,
// no DCR, no refresh_token: shortcuts v0.1, upgrade path: RFC 7591 +
// offline_access once real services connect).
//
// Two separate crypto worlds (§21, deliberately):
//   - IdP signing key: ES256/P-256 (industry standard, in every
//     OIDC library), generated + stored in data_dir/idp_es256.pem.
//   - Federation proof: BIP340 signature of the MAILBOX key (secp256k1) over
//     a server challenge, created in the browser (E2E: the relay never sees
//     the private mailbox key). Lands as bmail claim in the ID token; services
//     verify signature + pubkey binding via the directory (§4.2 level 3).
//
// Login runs through the PWA in OIDC mode (?oidc=&sid=): existing
// login mechanics (passkey PRF/file/auto-login) → bearer token →
// /oidc/auth/login returns challenge → browser signs → /oidc/auth/sign →
// redirect with code. CORS for the PWA origin(s) = webauthn.origins.
package relaysrv

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lightningmail/relay/internal/config"
	"github.com/lightningmail/relay/internal/crypto"
	"github.com/lightningmail/relay/internal/ledger"
)

var errOidcNotConfigured = errors.New("oidc: not configured (relay.yaml oidc.issuer fehlt)")

const (
	oidcSessionTTL = 10 * time.Minute
	oidcCodeTTL    = 2 * time.Minute
	oidcTokenTTL   = time.Hour
)

// --- Session/code/token stores (in-memory, single process — like waSessions;
// shortcut: externalize for multi-instance relays) ---

type oidcSession struct {
	clientID      string
	redirectURI   string
	scope         string
	state         string
	nonce         string
	codeChallenge string
	account       string // after /oidc/auth/login
	challenge     []byte // after /oidc/auth/login
	sig           string // after /oidc/auth/sign
	expires       time.Time
	done          bool
	// Micro-paywall (OIDC micropayment): RP demands pay_sats for pay_item,
	// payment goes to pay_to (local accounts only), debited at sign.
	paySats int64
	payTo   string
	payItem string
	paid    bool
}

type oidcCode struct {
	session *oidcSession // Parameter + account + challenge + sig
	used    bool
	expires time.Time
}

type oidcToken struct {
	account string
	expires time.Time
	paySats int64
	payTo   string
	payItem string
	paid    bool
}

type oidcState struct {
	mu      sync.Mutex
	sess    map[string]*oidcSession
	codes   map[string]*oidcCode
	tokens  map[string]*oidcToken
	key     *ecdsa.PrivateKey
	kid     string
	keyPath string
}

func newOIDCState(dataDir string) *oidcState {
	return &oidcState{
		sess:    map[string]*oidcSession{},
		codes:   map[string]*oidcCode{},
		tokens:  map[string]*oidcToken{},
		keyPath: dataDir + "/idp_es256.pem",
	}
}

// ensureKey loads or generates the IdP ES256 key (lazy, once).
func (o *oidcState) ensureKey() error {
	if o.key != nil {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.key != nil {
		return nil
	}
	if data, err := os.ReadFile(o.keyPath); err == nil {
		block, _ := pem.Decode(data)
		if block != nil {
			if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
				if ec, ok := k.(*ecdsa.PrivateKey); ok && ec.Curve == elliptic.P256() {
					o.key = ec
					o.deriveKid()
					return nil
				}
			}
		}
		return errors.New("oidc: idp_es256.pem unlesbar/kaputt")
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return err
	}
	if err := os.WriteFile(o.keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		return err
	}
	o.key = k
	o.deriveKid()
	return nil
}

func (o *oidcState) deriveKid() {
	pub := sha256.Sum256(elliptic.Marshal(o.key.Curve, o.key.PublicKey.X, o.key.PublicKey.Y))
	o.kid = hex.EncodeToString(pub[:8])
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// --- JWT (ES256, hand-rolled: Header.Payload.r||s — JWS-conformant 32+32 bytes) ---

func (o *oidcState) signJWT(claims map[string]any) (string, error) {
	if err := o.ensureKey(); err != nil {
		return "", err
	}
	hdr, _ := json.Marshal(map[string]any{"alg": "ES256", "typ": "JWT", "kid": o.kid})
	body, _ := json.Marshal(claims)
	signing := b64u(hdr) + "." + b64u(body)
	d := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, o.key, d[:])
	if err != nil {
		return "", err
	}
	sig := append(pad32(r.Bytes()), pad32(s.Bytes())...)
	return signing + "." + b64u(sig), nil
}

func pad32(b []byte) []byte {
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

// --- PKCE (S256) ---

func pkceOK(verifier, challenge string) bool {
	if verifier == "" || challenge == "" {
		return false
	}
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:]) == challenge
}

// --- config helpers ---

func (s *Server) oidcIssuer() string { return strings.TrimSuffix(s.cfg.Oidc.Issuer, "/") }

func (s *Server) oidcClient(id, redirectURI string) *config.OidcClient {
	for i := range s.cfg.Oidc.Clients {
		if s.cfg.Oidc.Clients[i].ID == id {
			return &s.cfg.Oidc.Clients[i]
		}
	}
	// Stateless public client (web federation without pre-registration):
	// when client_id is an https URL (or http on localhost/127.0.0.1)
	// and redirect_uri has exactly the same origin (scheme + host), the
	// service is admitted dynamically; the consent screen shows the hostname.
	cu, err1 := url.Parse(id)
	ru, err2 := url.Parse(redirectURI)
	if err1 != nil || err2 != nil || cu.Host == "" || ru.Host == "" {
		return nil
	}
	local := cu.Hostname() == "localhost" || strings.HasPrefix(cu.Hostname(), "127.")
	if cu.Scheme != "https" && !(cu.Scheme == "http" && local) {
		return nil
	}
	if cu.Scheme != ru.Scheme || !strings.EqualFold(cu.Host, ru.Host) {
		return nil
	}
	return &config.OidcClient{
		ID:           id,
		Name:         cu.Host,
		RedirectURIs: []string{redirectURI},
	}
}

func (s *Server) oidcDomain() string {
	if s.cfg.Oidc.AddressDomain != "" {
		return s.cfg.Oidc.AddressDomain
	}
	if u, err := url.Parse(s.oidcIssuer()); err == nil && u.Host != "" {
		return u.Host
	}
	return "localhost"
}

// oidcCORS: PWA origin(s) from webauthn.origins; OPTIONS is answered.
// Returning true = the request was handled (preflight).
func (s *Server) oidcCORS(w http.ResponseWriter, r *http.Request) bool {
	origin := r.Header.Get("Origin")
	for _, o := range s.cfg.WebAuthn.Origins {
		if o == origin {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			w.Header().Set("Access-Control-Max-Age", "600")
			break
		}
	}
	if r.Method == http.MethodOptions {
		w.WriteHeader(204)
		return true
	}
	return false
}

func oidcJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// --- router (under /oidc/) ---

func (s *Server) handleOIDCRouter(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Oidc.Issuer == "" {
		http.Error(w, `{"error":"`+errOidcNotConfigured.Error()+`"}`, 503)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/oidc/")
	switch {
	case path == "auth" && r.Method == http.MethodGet:
		s.oidcAuth(w, r)
	case path == "auth/login":
		if s.oidcCORS(w, r) {
			return
		}
		s.oidcAuthLogin(w, r)
	case path == "auth/sign":
		if s.oidcCORS(w, r) {
			return
		}
		s.oidcAuthSign(w, r)
	case path == "token" && r.Method == http.MethodPost:
		s.oidcToken(w, r)
	case path == "userinfo" && r.Method == http.MethodGet:
		s.oidcUserinfo(w, r)
	case path == "jwks" && r.Method == http.MethodGet:
		s.oidcJWKS(w, r)
	case path == "demo-callback.html" && r.Method == http.MethodGet:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(oidcDemoPage))
	default:
		http.Error(w, `{"error":"not found"}`, 404)
	}
}

// --- GET /.well-known/openid-configuration ---

func (s *Server) handleOIDCDiscovery(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Oidc.Issuer == "" {
		http.Error(w, `{"error":"`+errOidcNotConfigured.Error()+`"}`, 503)
		return
	}
	iss := s.oidcIssuer()
	oidcJSON(w, 200, map[string]any{
		"issuer":                                iss,
		"authorization_endpoint":                iss + "/oidc/auth",
		"token_endpoint":                        iss + "/oidc/token",
		"userinfo_endpoint":                     iss + "/oidc/userinfo",
		"jwks_uri":                              iss + "/oidc/jwks",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"ES256"},
		"scopes_supported":                      []string{"openid", "email", "profile"},
		"token_endpoint_auth_methods_supported": []string{"none"},
		"code_challenge_methods_supported":      []string{"S256"},
		"claims_supported": []string{"iss", "sub", "aud", "exp", "iat", "auth_time",
			"nonce", "email", "email_verified", "preferred_username", "bmail"},
	})
}

// --- GET /oidc/jwks ---

func (s *Server) oidcJWKS(w http.ResponseWriter, r *http.Request) {
	st := s.oidc
	if err := st.ensureKey(); err != nil {
		http.Error(w, `{"error":"key"}`, 500)
		return
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	oidcJSON(w, 200, map[string]any{"keys": []any{map[string]any{
		"kty": "EC", "crv": "P-256", "use": "sig", "alg": "ES256", "kid": st.kid,
		"x": b64u(pad32(st.key.PublicKey.X.Bytes())),
		"y": b64u(pad32(st.key.PublicKey.Y.Bytes())),
	}}})
}

// --- GET /oidc/auth (Authorization Request) ---

func (s *Server) oidcAuth(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	bad := func(msg string) { http.Error(w, `{"error":"invalid_request","detail":"`+msg+`"}`, 400) }
	if q.Get("response_type") != "code" {
		bad("response_type muss 'code' sein")
		return
	}
	ru := q.Get("redirect_uri")
	client := s.oidcClient(q.Get("client_id"), ru)
	if client == nil {
		bad("unbekannter client_id oder redirect_uri-Origin weicht ab")
		return
	}
	okRU := false
	for _, u := range client.RedirectURIs {
		if u == ru {
			okRU = true
		}
	}
	if !okRU {
		bad("redirect_uri nicht registriert")
		return
	}
	if !strings.Contains(q.Get("scope"), "openid") {
		bad("scope muss 'openid' enthalten")
		return
	}
	if q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
		bad("PKCE S256 ist Pflicht")
		return
	}
	if s.cfg.Oidc.LoginPage == "" {
		bad("oidc.login_page nicht konfiguriert")
		return
	}
	paySats, _ := strconv.ParseInt(q.Get("pay_sats"), 10, 64)
	if paySats < 0 || paySats > 1_000_000 {
		bad("pay_sats muss zwischen 0 und 1000000 liegen")
		return
	}
	payTo := strings.TrimSpace(q.Get("pay_to"))
	payItem := strings.TrimSpace(q.Get("pay_item"))
	sid := randHex(16)
	now := time.Now()
	st := s.oidc
	st.mu.Lock()
	for k, v := range st.sess { // opportunistic TTL maintenance
		if v.expires.Before(now) {
			delete(st.sess, k)
		}
	}
	st.sess[sid] = &oidcSession{
		clientID: q.Get("client_id"), redirectURI: ru, scope: q.Get("scope"),
		state: q.Get("state"), nonce: q.Get("nonce"), codeChallenge: q.Get("code_challenge"),
		expires: now.Add(oidcSessionTTL),
		paySats: paySats, payTo: payTo, payItem: payItem,
	}
	st.mu.Unlock()
	sep := "?"
	if strings.Contains(s.cfg.Oidc.LoginPage, "?") {
		sep = "&"
	}
	http.Redirect(w, r, s.cfg.Oidc.LoginPage+sep+"oidc="+url.QueryEscape(s.oidcIssuer())+"&sid="+sid, http.StatusFound)
}

func (s *Server) oidcSessionGet(sid string) *oidcSession {
	st := s.oidc
	st.mu.Lock()
	defer st.mu.Unlock()
	sess, ok := st.sess[sid]
	if !ok || sess.expires.Before(time.Now()) || sess.done {
		return nil
	}
	return sess
}

// --- POST /oidc/auth/login (bearer from the normal relay login) ---

func (s *Server) oidcAuthLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, 405)
		return
	}
	var body struct {
		SID string `json:"sid"`
	}
	json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body)
	sess := s.oidcSessionGet(body.SID)
	if sess == nil {
		oidcJSON(w, 400, map[string]any{"error": "session ungueltig oder abgelaufen"})
		return
	}
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	account, err := s.ledger.LookupToken(tok)
	if err != nil || account == "" {
		oidcJSON(w, 401, map[string]any{"error": "unauthorized — bitte beim richtigen Relay anmelden"})
		return
	}
	// Challenge: fresh 32 random bytes. Client signs BIP340 over
	// sha256(challenge) — exactly the Verify(pub, challenge, sig) pattern.
	challenge := make([]byte, 32)
	rand.Read(challenge)
	st := s.oidc
	st.mu.Lock()
	sess.account = account
	sess.challenge = challenge
	st.mu.Unlock()
	client := s.oidcClient(sess.clientID, sess.redirectURI)
	clientName := sess.clientID
	if client != nil && client.Name != "" {
		clientName = client.Name
	}
	oidcJSON(w, 200, map[string]any{
		"challenge_b64": base64.StdEncoding.EncodeToString(challenge),
		"client_name":   clientName,
		"address":       account + "@" + s.oidcDomain(),
		"pay_sats":      sess.paySats,
		"pay_to":        sess.payTo,
		"pay_item":      sess.payItem,
	})
}

// --- POST /oidc/auth/sign (BIP340 of the mailbox key) ---

func (s *Server) oidcAuthSign(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, 405)
		return
	}
	var body struct {
		SID  string `json:"sid"`
		Sig  string `json:"sig"`
		Deny bool   `json:"deny"`
	}
	json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&body)
	sess := s.oidcSessionGet(body.SID)
	if sess == nil || sess.account == "" || len(sess.challenge) == 0 {
		oidcJSON(w, 400, map[string]any{"error": "session ungueltig oder noch nicht angemeldet"})
		return
	}
	redir := func(params string) {
		sep := "?"
		if strings.Contains(sess.redirectURI, "?") {
			sep = "&"
		}
		st := s.oidc
		st.mu.Lock()
		sess.done = true
		st.mu.Unlock()
		oidcJSON(w, 200, map[string]any{"redirect": sess.redirectURI + sep + params})
	}
	if body.Deny {
		redir("error=access_denied&state=" + url.QueryEscape(sess.state))
		return
	}
	acct, err := s.ledger.GetAccount(sess.account)
	if err != nil {
		oidcJSON(w, 500, map[string]any{"error": "account"})
		return
	}
	sig, err := hex.DecodeString(body.Sig)
	if err != nil || len(sig) != 64 {
		oidcJSON(w, 400, map[string]any{"error": "sig muss 64-Byte-BIP340-hex sein"})
		return
	}
	pub, err := crypto.ParsePubKey(acct.MailboxPubkey)
	if err != nil {
		oidcJSON(w, 500, map[string]any{"error": "pubkey"})
		return
	}
	if err := crypto.Verify(pub, sess.challenge, sig); err != nil {
		oidcJSON(w, 403, map[string]any{"error": "Mailbox-Key-Signatur ungueltig"})
		return
	}
	// Micro-paywall: charge only after a valid signature (consent covered).
	if sess.paySats > 0 {
		payMsat := sess.paySats * 1000
		if err := s.ledger.ApplyDeltaMeta(sess.account, -payMsat, ledger.KindPostageOut, "oidc-pay:"+sess.payItem, "btc", s.ratePtr()); err != nil {
			if errors.Is(err, ledger.ErrInsufficient) {
				oidcJSON(w, 402, map[string]any{"error": "Guthaben reicht für diese Zahlung nicht aus"})
				return
			}
			oidcJSON(w, 500, map[string]any{"error": "zahlung fehlgeschlagen"})
			return
		}
		if sess.payTo != "" && sess.payTo != sess.account {
			if _, err := s.ledger.GetAccount(sess.payTo); err == nil {
				s.ledger.ApplyDeltaMeta(sess.payTo, payMsat, ledger.KindPostageIn, "oidc-pay:"+sess.payItem+":"+sess.account, "btc", s.ratePtr())
			}
		}
		st := s.oidc
		st.mu.Lock()
		sess.paid = true
		st.mu.Unlock()
	}
	code := randHex(32)
	st := s.oidc
	st.mu.Lock()
	sess.sig = body.Sig
	st.codes[code] = &oidcCode{session: sess, expires: time.Now().Add(oidcCodeTTL)}
	st.mu.Unlock()
	redir("code=" + code + "&state=" + url.QueryEscape(sess.state))
}

// --- POST /oidc/token ---

func (s *Server) oidcToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oidcJSON(w, 400, map[string]any{"error": "invalid_request"})
		return
	}
	fail := func(code, desc string) { oidcJSON(w, 400, map[string]any{"error": code, "error_description": desc}) }
	if r.FormValue("grant_type") != "authorization_code" {
		fail("unsupported_grant_type", "nur authorization_code")
		return
	}
	codeStr := r.FormValue("code")
	st := s.oidc
	st.mu.Lock()
	ce, ok := st.codes[codeStr]
	if ok {
		delete(st.codes, codeStr) // single-use, even on error
	}
	st.mu.Unlock()
	if !ok || ce.expires.Before(time.Now()) || ce.used {
		fail("invalid_grant", "code ungueltig, abgelaufen oder bereits eingelöst")
		return
	}
	ce.used = true
	sess := ce.session
	if r.FormValue("client_id") != sess.clientID || r.FormValue("redirect_uri") != sess.redirectURI {
		fail("invalid_grant", "client_id/redirect_uri passen nicht zum code")
		return
	}
	if !pkceOK(r.FormValue("code_verifier"), sess.codeChallenge) {
		fail("invalid_grant", "PKCE-Verifier passt nicht")
		return
	}
	acct, err := s.ledger.GetAccount(sess.account)
	if err != nil {
		fail("invalid_grant", "konto weg")
		return
	}
	now := time.Now()
	addr := sess.account + "@" + s.oidcDomain()
	bmail := map[string]any{
		"pubkey":    hex.EncodeToString(acct.MailboxPubkey),
		"sig":       sess.sig,
		"challenge": base64.StdEncoding.EncodeToString(sess.challenge),
		"alg":       "bip340-sha256",
	}
	if sess.paid && sess.paySats > 0 {
		bmail["paid_sats"] = sess.paySats
		bmail["paid_to"] = sess.payTo
		bmail["paid_item"] = sess.payItem
	}
	claims := map[string]any{
		"iss": s.oidcIssuer(), "sub": addr, "aud": sess.clientID,
		"exp": now.Add(oidcTokenTTL).Unix(), "iat": now.Unix(), "auth_time": now.Unix(),
		"email": addr, "email_verified": true, "preferred_username": sess.account,
		"bmail": bmail,
	}
	if sess.nonce != "" {
		claims["nonce"] = sess.nonce
	}
	idToken, err := st.signJWT(claims)
	if err != nil {
		oidcJSON(w, 500, map[string]any{"error": "server_error", "error_description": "id_token"})
		return
	}
	access := randHex(24)
	st.mu.Lock()
	for k, v := range st.tokens {
		if v.expires.Before(now) {
			delete(st.tokens, k)
		}
	}
	st.tokens[access] = &oidcToken{account: sess.account, expires: now.Add(oidcTokenTTL),
		paySats: sess.paySats, payTo: sess.payTo, payItem: sess.payItem, paid: sess.paid}
	st.mu.Unlock()
	oidcJSON(w, 200, map[string]any{
		"access_token": access, "token_type": "Bearer",
		"expires_in": int(oidcTokenTTL.Seconds()), "id_token": idToken,
	})
}

// --- GET /oidc/userinfo ---

func (s *Server) oidcUserinfo(w http.ResponseWriter, r *http.Request) {
	access := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	st := s.oidc
	st.mu.Lock()
	te, ok := st.tokens[access]
	st.mu.Unlock()
	if !ok || te.expires.Before(time.Now()) {
		w.Header().Set("WWW-Authenticate", "Bearer")
		oidcJSON(w, 401, map[string]any{"error": "invalid_token"})
		return
	}
	addr := te.account + "@" + s.oidcDomain()
	claims := map[string]any{
		"sub": addr, "email": addr, "email_verified": true, "preferred_username": te.account,
	}
	if acct, err := s.ledger.GetAccount(te.account); err == nil {
		bmail := map[string]any{"pubkey": hex.EncodeToString(acct.MailboxPubkey)}
		if te.paid && te.paySats > 0 {
			bmail["paid_sats"] = te.paySats
			bmail["paid_to"] = te.payTo
			bmail["paid_item"] = te.payItem
		}
		claims["bmail"] = bmail
	}
	oidcJSON(w, 200, claims)
}
