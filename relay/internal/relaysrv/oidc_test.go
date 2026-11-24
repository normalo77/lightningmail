// IdP/OIDC flow fully in-process: discovery → auth request → login (bearer)
// → BIP340 challenge signature → code → token (PKCE, ES256 verify) → userinfo,
// plus negative paths (replay, foreign signature, wrong verifier, broken parameters).
package relaysrv

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightningmail/relay/internal/config"
	"github.com/lightningmail/lm1/crypto"
	"github.com/lightningmail/relay/internal/ledger"
	"github.com/lightningmail/relay/internal/postage"
	"github.com/lightningmail/relay/internal/rates"
)

const oidcTestYAML = `
name: t
listen_addr: 127.0.0.1:0
data_dir: %s
lnd:
  rpc_host: 127.0.0.1:1
  tls_cert_path: /nonexistent
  macaroon_path: /nonexistent
postage:
  foreign_sats: 10
  min_sats: 1
oidc:
  issuer: "https://idp.test"
  login_page: "https://ui.test/app/"
  clients:
    - id: demo
      name: Demo-Dienst
      redirect_uris:
        - "https://idp.test/oidc/demo-callback.html"
`

func newOIDCTestServer(t *testing.T) (*Server, *btcec.PrivateKey) {
	t.Helper()
	cfg, err := config.ParseConfig([]byte(strings.Replace(oidcTestYAML, "%s", t.TempDir(), 1)))
	if err != nil {
		t.Fatal(err)
	}
	l, err := ledger.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	priv, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pub := crypto.PublicBytes(priv)
	if _, err := l.CreateAccount("alice", pub[:], ledger.DefaultQuotaBytes); err != nil {
		t.Fatal(err)
	}
	if err := l.StoreToken("tok123", "alice"); err != nil {
		t.Fatal(err)
	}
	srv := New(cfg, l, nil, postage.New(cfg), rates.NewFeed("", 0))
	return srv, priv
}

func (s *Server) do(t *testing.T, method, target string, jsonBody any, formBody url.Values, tok string) *httptest.ResponseRecorder {
	t.Helper()
	var rd io.Reader
	if jsonBody != nil {
		b, _ := json.Marshal(jsonBody)
		rd = bytes.NewReader(b)
	} else if formBody != nil {
		rd = strings.NewReader(formBody.Encode())
	}
	r := httptest.NewRequest(method, target, rd)
	if jsonBody != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	if formBody != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if tok != "" {
		r.Header.Set("Authorization", "Bearer "+tok)
	}
	w := httptest.NewRecorder()
	s.handleOIDCRouter(w, r)
	return w
}

const testVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

func authQuery(verifier string) url.Values {
	h := sha256.Sum256([]byte(verifier))
	return url.Values{
		"response_type": {"code"}, "client_id": {"demo"},
		"redirect_uri": {"https://idp.test/oidc/demo-callback.html"},
		"scope":        {"openid email"},
		"state":        {"xyz"}, "nonce": {"n1"},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(h[:])},
		"code_challenge_method": {"S256"},
	}
}

// startFlow: Auth-Request → sid; Login → Challenge; Sign → Code.
func startFlow(t *testing.T, srv *Server, priv *btcec.PrivateKey, verifier string, sigOverride string) (sid, code string, challenge []byte) {
	t.Helper()
	w := srv.do(t, "GET", "/oidc/auth?"+authQuery(verifier).Encode(), nil, nil, "")
	if w.Code != http.StatusFound {
		t.Fatalf("auth: %d %s", w.Code, w.Body.String())
	}
	loc := w.Result().Header.Get("Location")
	if !strings.HasPrefix(loc, "https://ui.test/app/?oidc=https%3A%2F%2Fidp.test&sid=") {
		t.Fatalf("auth Location falsch: %s", loc)
	}
	lu, _ := url.Parse(loc)
	sid = lu.Query().Get("sid")
	if sid == "" {
		t.Fatal("keine sid im Redirect")
	}
	w = srv.do(t, "POST", "/oidc/auth/login", map[string]string{"sid": sid}, nil, "tok123")
	if w.Code != 200 {
		t.Fatalf("login: %d %s", w.Code, w.Body.String())
	}
	var lj map[string]any
	json.Unmarshal(w.Body.Bytes(), &lj)
	if lj["address"] != "alice@idp.test" || lj["client_name"] != "Demo-Dienst" {
		t.Fatalf("login-Antwort: %v", lj)
	}
	challenge, err := base64.StdEncoding.DecodeString(lj["challenge_b64"].(string))
	if err != nil || len(challenge) != 32 {
		t.Fatalf("challenge: %v", err)
	}
	sig := sigOverride
	if sig == "" {
		s, err := crypto.Sign(priv, challenge)
		if err != nil {
			t.Fatal(err)
		}
		sig = hex.EncodeToString(s)
	}
	w = srv.do(t, "POST", "/oidc/auth/sign", map[string]string{"sid": sid, "sig": sig}, nil, "")
	if w.Code != 200 {
		t.Fatalf("sign: %d %s", w.Code, w.Body.String())
	}
	var sj map[string]string
	json.Unmarshal(w.Body.Bytes(), &sj)
	ru, err := url.Parse(sj["redirect"])
	if err != nil {
		t.Fatal(err)
	}
	if ru.Query().Get("state") != "xyz" {
		t.Fatalf("state fehlt im Redirect: %s", sj["redirect"])
	}
	return sid, ru.Query().Get("code"), challenge
}

func TestOIDCDiscoveryAndJWKS(t *testing.T) {
	srv, _ := newOIDCTestServer(t)
	w := httptest.NewRecorder()
	srv.handleOIDCDiscovery(w, httptest.NewRequest("GET", "/.well-known/openid-configuration", nil))
	var disc map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &disc); err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]string{
		"issuer": "https://idp.test", "token_endpoint": "https://idp.test/oidc/token",
		"authorization_endpoint": "https://idp.test/oidc/auth", "jwks_uri": "https://idp.test/oidc/jwks",
		"userinfo_endpoint": "https://idp.test/oidc/userinfo",
	} {
		if disc[k] != want {
			t.Errorf("discovery %s = %v, want %s", k, disc[k], want)
		}
	}
	w = srv.do(t, "GET", "/oidc/jwks", nil, nil, "")
	var jwks struct {
		Keys []map[string]string `json:"keys"`
	}
	json.Unmarshal(w.Body.Bytes(), &jwks)
	if len(jwks.Keys) != 1 || jwks.Keys[0]["kty"] != "EC" || jwks.Keys[0]["alg"] != "ES256" || jwks.Keys[0]["kid"] == "" {
		t.Fatalf("jwks: %s", w.Body.String())
	}
}

func TestOIDCFullFlow(t *testing.T) {
	srv, priv := newOIDCTestServer(t)
	_, code, challenge := startFlow(t, srv, priv, testVerifier, "")
	if code == "" {
		t.Fatal("kein code")
	}

	// Token-Exchange
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {"https://idp.test/oidc/demo-callback.html"}, "client_id": {"demo"},
		"code_verifier": {testVerifier}}
	w := srv.do(t, "POST", "/oidc/token", nil, form, "")
	if w.Code != 200 {
		t.Fatalf("token: %d %s", w.Code, w.Body.String())
	}
	var tok map[string]any
	json.Unmarshal(w.Body.Bytes(), &tok)
	idTok, _ := tok["id_token"].(string)
	access, _ := tok["access_token"].(string)
	if idTok == "" || access == "" || tok["token_type"] != "Bearer" {
		t.Fatalf("token-Antwort: %v", tok)
	}

	// ID token: verify the ES256 signature against the IdP key
	parts := strings.Split(idTok, ".")
	if len(parts) != 3 {
		t.Fatal("id_token kein JWT")
	}
	sigb, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sigb) != 64 {
		t.Fatalf("sig: %v", err)
	}
	d := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(&srv.oidc.key.PublicKey, d[:], new(big.Int).SetBytes(sigb[:32]), new(big.Int).SetBytes(sigb[32:])) {
		t.Fatal("ES256-Signatur ungueltig")
	}
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims map[string]any
	json.Unmarshal(payload, &claims)
	if claims["iss"] != "https://idp.test" || claims["sub"] != "alice@idp.test" ||
		claims["aud"] != "demo" || claims["nonce"] != "n1" || claims["email"] != "alice@idp.test" ||
		claims["email_verified"] != true || claims["preferred_username"] != "alice" {
		t.Fatalf("claims: %v", claims)
	}
	bm, ok := claims["bmail"].(map[string]any)
	if !ok {
		t.Fatal("bmail-Claim fehlt")
	}
	pub := crypto.PublicBytes(priv)
	if bm["pubkey"] != hex.EncodeToString(pub[:]) || bm["alg"] != "bip340-sha256" {
		t.Fatalf("bmail-Claim: %v", bm)
	}
	// bmail signature must be valid over the server challenge
	bmSig, _ := hex.DecodeString(bm["sig"].(string))
	pubkey, _ := crypto.ParsePubKey(pub[:])
	if err := crypto.Verify(pubkey, challenge, bmSig); err != nil {
		t.Fatalf("bmail-Sig ungueltig: %v", err)
	}

	// code replay must fail (single-use)
	w = srv.do(t, "POST", "/oidc/token", nil, form, "")
	if w.Code != 400 {
		t.Fatalf("code-replay: %d", w.Code)
	}

	// userinfo with access token
	r := httptest.NewRequest("GET", "/oidc/userinfo", nil)
	r.Header.Set("Authorization", "Bearer "+access)
	w = httptest.NewRecorder()
	srv.handleOIDCRouter(w, r)
	if w.Code != 200 {
		t.Fatalf("userinfo: %d", w.Code)
	}
	var ui map[string]any
	json.Unmarshal(w.Body.Bytes(), &ui)
	if ui["sub"] != "alice@idp.test" || ui["email_verified"] != true {
		t.Fatalf("userinfo-claims: %v", ui)
	}
	// userinfo without/with a broken token
	r = httptest.NewRequest("GET", "/oidc/userinfo", nil)
	w = httptest.NewRecorder()
	srv.handleOIDCRouter(w, r)
	if w.Code != 401 {
		t.Fatalf("userinfo ohne Token: %d", w.Code)
	}
}

func TestOIDCNegativePaths(t *testing.T) {
	srv, priv := newOIDCTestServer(t)

	// wrong verifier → invalid_grant
	_, code, _ := startFlow(t, srv, priv, testVerifier, "")
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {"https://idp.test/oidc/demo-callback.html"}, "client_id": {"demo"},
		"code_verifier": {"falscher-verifier"}}
	w := srv.do(t, "POST", "/oidc/token", nil, form, "")
	if w.Code != 400 {
		t.Fatalf("falscher verifier: %d", w.Code)
	}

	// foreign key signs the challenge → 403
	other, _ := crypto.GenerateKeyPair()
	// via a real flow: fetch login, sign with the wrong key
	w = srv.do(t, "GET", "/oidc/auth?"+authQuery(testVerifier).Encode(), nil, nil, "")
	loc := w.Result().Header.Get("Location")
	lu, _ := url.Parse(loc)
	sid := lu.Query().Get("sid")
	w = srv.do(t, "POST", "/oidc/auth/login", map[string]string{"sid": sid}, nil, "tok123")
	var lj map[string]any
	json.Unmarshal(w.Body.Bytes(), &lj)
	ch, _ := base64.StdEncoding.DecodeString(lj["challenge_b64"].(string))
	badSig, _ := crypto.Sign(other, ch)
	w = srv.do(t, "POST", "/oidc/auth/sign", map[string]string{"sid": sid, "sig": hex.EncodeToString(badSig)}, nil, "")
	if w.Code != 403 {
		t.Fatalf("fremde Signatur: %d", w.Code)
	}

	// login with invalid token → 401
	w = srv.do(t, "POST", "/oidc/auth/login", map[string]string{"sid": sid}, nil, "ungueltig")
	if w.Code != 401 {
		t.Fatalf("login falscher token: %d", w.Code)
	}

	// unknown sid → 400
	w = srv.do(t, "POST", "/oidc/auth/login", map[string]string{"sid": "gibtsnicht"}, nil, "tok123")
	if w.Code != 400 {
		t.Fatalf("unbekannte sid: %d", w.Code)
	}

	// auth request: unknown client, wrong redirect_uri, missing PKCE
	for i, mut := range []func(q url.Values){
		func(q url.Values) { q.Set("client_id", "unbekannt") },
		func(q url.Values) { q.Set("redirect_uri", "https://evil.example/cb") },
		func(q url.Values) { q.Del("code_challenge") },
		func(q url.Values) { q.Set("code_challenge_method", "plain") },
		func(q url.Values) { q.Set("scope", "email") },
		func(q url.Values) { q.Set("response_type", "token") },
	} {
		q := authQuery(testVerifier)
		mut(q)
		w := srv.do(t, "GET", "/oidc/auth?"+q.Encode(), nil, nil, "")
		if w.Code != 400 {
			t.Fatalf("mutierter Auth-Request #%d → %d, want 400", i, w.Code)
		}
	}

	// deny path: access_denied instead of code
	w = srv.do(t, "GET", "/oidc/auth?"+authQuery(testVerifier).Encode(), nil, nil, "")
	lu2, _ := url.Parse(w.Result().Header.Get("Location"))
	sid2 := lu2.Query().Get("sid")
	srv.do(t, "POST", "/oidc/auth/login", map[string]string{"sid": sid2}, nil, "tok123")
	w = srv.do(t, "POST", "/oidc/auth/sign", map[string]any{"sid": sid2, "deny": true}, nil, "")
	var sj map[string]string
	json.Unmarshal(w.Body.Bytes(), &sj)
	if !strings.Contains(sj["redirect"], "error=access_denied") || !strings.Contains(sj["redirect"], "state=xyz") {
		t.Fatalf("deny-redirect: %s", sj["redirect"])
	}
}

func TestOIDCNotConfigured(t *testing.T) {
	cfg, err := config.ParseConfig([]byte(strings.Replace(oidcTestYAML, "%s", t.TempDir(), 1)))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Oidc.Issuer = ""
	l, _ := ledger.Open(":memory:")
	defer l.Close()
	srv := New(cfg, l, nil, postage.New(cfg), rates.NewFeed("", 0))
	w := srv.do(t, "GET", "/oidc/jwks", nil, nil, "")
	if w.Code != 503 {
		t.Fatalf("ohne oidc.issuer: %d, want 503", w.Code)
	}
}

func TestPkceAndPad(t *testing.T) {
	h := sha256.Sum256([]byte(testVerifier))
	ch := base64.RawURLEncoding.EncodeToString(h[:])
	if !pkceOK(testVerifier, ch) {
		t.Fatal("pkceOK(true) falsch")
	}
	if pkceOK("falsch", ch) || pkceOK("", ch) || pkceOK(testVerifier, "") {
		t.Fatal("pkceOK muss bei Mismatch/leer false sein")
	}
	if got := pad32(big.NewInt(7).Bytes()); len(got) != 32 || got[31] != 7 {
		t.Fatalf("pad32: %v", got)
	}
}

// TestOIDCPaywall: pay_sats=5&pay_item=art-1&pay_to=bob → alice −5,000 msat,
// bob +5,000 msat, paid_sats/paid_item in the id_token bmail claim and in /oidc/userinfo.
func TestOIDCPaywall(t *testing.T) {
	srv, priv := newOIDCTestServer(t)
	bobPriv, _ := crypto.GenerateKeyPair()
	bobPub := crypto.PublicBytes(bobPriv)
	if _, err := srv.ledger.CreateAccount("bob", bobPub[:], ledger.DefaultQuotaBytes); err != nil {
		t.Fatal(err)
	}
	if err := srv.ledger.ApplyDeltaMeta("alice", 1_000_000, ledger.KindTopup, "test-faucet", "btc", nil); err != nil {
		t.Fatal(err)
	}
	aliceBefore, _ := srv.ledger.Balance("alice")

	q := authQuery(testVerifier)
	q.Set("pay_sats", "5")
	q.Set("pay_item", "art-1")
	q.Set("pay_to", "bob")
	w := srv.do(t, "GET", "/oidc/auth?"+q.Encode(), nil, nil, "")
	if w.Code != http.StatusFound {
		t.Fatalf("auth: %d %s", w.Code, w.Body.String())
	}
	lu, _ := url.Parse(w.Result().Header.Get("Location"))
	sid := lu.Query().Get("sid")

	// login response must mirror the paywall parameters
	w = srv.do(t, "POST", "/oidc/auth/login", map[string]string{"sid": sid}, nil, "tok123")
	if w.Code != 200 {
		t.Fatalf("login: %d %s", w.Code, w.Body.String())
	}
	var lj map[string]any
	json.Unmarshal(w.Body.Bytes(), &lj)
	if lj["pay_sats"].(float64) != 5 || lj["pay_item"] != "art-1" || lj["pay_to"] != "bob" {
		t.Fatalf("login pay-Parameter: %v", lj)
	}
	ch, _ := base64.StdEncoding.DecodeString(lj["challenge_b64"].(string))
	sig, _ := crypto.Sign(priv, ch)
	w = srv.do(t, "POST", "/oidc/auth/sign", map[string]string{"sid": sid, "sig": hex.EncodeToString(sig)}, nil, "")
	if w.Code != 200 {
		t.Fatalf("sign: %d %s", w.Code, w.Body.String())
	}
	var sj map[string]string
	json.Unmarshal(w.Body.Bytes(), &sj)
	ru, _ := url.Parse(sj["redirect"])
	code := ru.Query().Get("code")

	// money movement: alice −5,000 msat, bob +5,000 msat
	aliceAfter, _ := srv.ledger.Balance("alice")
	bobAfter, _ := srv.ledger.Balance("bob")
	if aliceBefore-aliceAfter != 5_000 {
		t.Fatalf("alice delta = %d msat, want 5000", aliceBefore-aliceAfter)
	}
	if bobAfter != 5_000 {
		t.Fatalf("bob balance = %d msat, want 5000", bobAfter)
	}

	// token: bmail claim with paid_sats/paid_item
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {"https://idp.test/oidc/demo-callback.html"}, "client_id": {"demo"},
		"code_verifier": {testVerifier}}
	w = srv.do(t, "POST", "/oidc/token", nil, form, "")
	if w.Code != 200 {
		t.Fatalf("token: %d %s", w.Code, w.Body.String())
	}
	var tok map[string]any
	json.Unmarshal(w.Body.Bytes(), &tok)
	parts := strings.Split(tok["id_token"].(string), ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims map[string]any
	json.Unmarshal(payload, &claims)
	bm := claims["bmail"].(map[string]any)
	if bm["paid_sats"].(float64) != 5 || bm["paid_item"] != "art-1" || bm["paid_to"] != "bob" {
		t.Fatalf("id_token bmail-Claim: %v", bm)
	}

	// userinfo: the same paid_* fields
	w = srv.do(t, "GET", "/oidc/userinfo", nil, nil, tok["access_token"].(string))
	if w.Code != 200 {
		t.Fatalf("userinfo: %d", w.Code)
	}
	var ui map[string]any
	json.Unmarshal(w.Body.Bytes(), &ui)
	uib := ui["bmail"].(map[string]any)
	if uib["paid_sats"].(float64) != 5 || uib["paid_item"] != "art-1" {
		t.Fatalf("userinfo bmail: %v", uib)
	}

	// pay_sats > upper limit → 400
	q.Set("pay_sats", "1000001")
	w = srv.do(t, "GET", "/oidc/auth?"+q.Encode(), nil, nil, "")
	if w.Code != 400 {
		t.Fatalf("pay_sats zu groß: %d, want 400", w.Code)
	}
}

func TestOIDCStatelessOriginClient(t *testing.T) {
	srv, priv := newOIDCTestServer(t)
	h := sha256.Sum256([]byte(testVerifier))
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {"https://shop.example.org"},
		"redirect_uri":          {"https://shop.example.org/auth/callback"},
		"scope":                 {"openid email"},
		"state":                 {"s1"},
		"nonce":                 {"n2"},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(h[:])},
		"code_challenge_method": {"S256"},
	}
	// 1. same HTTPS origin without pre-registration → 302
	w := srv.do(t, "GET", "/oidc/auth?"+q.Encode(), nil, nil, "")
	if w.Code != http.StatusFound {
		t.Fatalf("stateless client: %d %s", w.Code, w.Body.String())
	}
	lu, _ := url.Parse(w.Result().Header.Get("Location"))
	sid := lu.Query().Get("sid")
	w = srv.do(t, "POST", "/oidc/auth/login", map[string]string{"sid": sid}, nil, "tok123")
	var lj map[string]any
	json.Unmarshal(w.Body.Bytes(), &lj)
	if lj["client_name"] != "shop.example.org" {
		t.Fatalf("client_name = %v, want shop.example.org", lj["client_name"])
	}
	ch, _ := base64.StdEncoding.DecodeString(lj["challenge_b64"].(string))
	sig, _ := crypto.Sign(priv, ch)
	w = srv.do(t, "POST", "/oidc/auth/sign", map[string]string{"sid": sid, "sig": hex.EncodeToString(sig)}, nil, "")
	var sj map[string]string
	json.Unmarshal(w.Body.Bytes(), &sj)
	ru, _ := url.Parse(sj["redirect"])
	code := ru.Query().Get("code")
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"https://shop.example.org/auth/callback"},
		"client_id":     {"https://shop.example.org"},
		"code_verifier": {testVerifier},
	}
	w = srv.do(t, "POST", "/oidc/token", nil, form, "")
	if w.Code != 200 {
		t.Fatalf("stateless token: %d %s", w.Code, w.Body.String())
	}

	// 2. differing redirect_uri origin → 400
	q.Set("redirect_uri", "https://evil.example.org/cb")
	w = srv.do(t, "GET", "/oidc/auth?"+q.Encode(), nil, nil, "")
	if w.Code != 400 {
		t.Fatalf("cross-origin redirect_uri akzeptiert: %d", w.Code)
	}

	// 3. plain HTTP on a foreign host → 400
	q.Set("client_id", "http://shop.example.org")
	q.Set("redirect_uri", "http://shop.example.org/cb")
	w = srv.do(t, "GET", "/oidc/auth?"+q.Encode(), nil, nil, "")
	if w.Code != 400 {
		t.Fatalf("plain http remote client_id akzeptiert: %d", w.Code)
	}
}
