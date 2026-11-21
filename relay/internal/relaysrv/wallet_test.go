// Wallet handlers: /v1/topup, /v1/withdraw (validation, without LND) +
// LUD-16 /.well-known/lnurlp/{name} (metadata, 404, amount limits).
package relaysrv

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lightningmail/relay/internal/config"
	"github.com/lightningmail/relay/internal/crypto"
	"github.com/lightningmail/relay/internal/ledger"
	"github.com/lightningmail/relay/internal/postage"
	"github.com/lightningmail/relay/internal/rates"
)

const walletTestYAML = `
name: relaytest
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
  issuer: https://relay.test
`

func walletServer(t *testing.T) *Server {
	t.Helper()
	cfg, err := config.ParseConfig([]byte(strings.Replace(walletTestYAML, "%s", t.TempDir(), 1)))
	if err != nil {
		t.Fatal(err)
	}
	l, err := ledger.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	priv, _ := crypto.GenerateKeyPair()
	pub := crypto.PublicBytes(priv)
	if _, err := l.CreateAccount("alice", pub[:], ledger.DefaultQuotaBytes); err != nil {
		t.Fatal(err)
	}
	if err := l.StoreToken("tok1", "alice"); err != nil {
		t.Fatal(err)
	}
	return New(cfg, l, nil, postage.New(cfg), rates.NewFeed("", 0)) // ln=nil: LND paths → 503/ERROR
}

func TestLNURLPMetadata(t *testing.T) {
	srv := walletServer(t)
	w := httptest.NewRecorder()
	srv.handleLNURLP(w, httptest.NewRequest("GET", "/.well-known/lnurlp/alice", nil))
	if w.Code != 200 {
		t.Fatalf("status: %d %s", w.Code, w.Body.String())
	}
	var j map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &j); err != nil {
		t.Fatal(err)
	}
	if j["tag"] != "payRequest" {
		t.Fatalf("tag: %v", j)
	}
	if j["callback"] != "https://relay.test/.well-known/lnurlp/alice" {
		t.Fatalf("callback: %v", j["callback"])
	}
	if j["minSendable"].(float64) != 1000 || j["maxSendable"].(float64) != 10_000_000_000 {
		t.Fatalf("sendable: %v", j)
	}
	meta := j["metadata"].(string)
	if !strings.Contains(meta, "alice@relay.test") || !strings.Contains(meta, "text/plain") {
		t.Fatalf("metadata: %s", meta)
	}
}

func TestLNURLPUnknownUser(t *testing.T) {
	srv := walletServer(t)
	w := httptest.NewRecorder()
	srv.handleLNURLP(w, httptest.NewRequest("GET", "/.well-known/lnurlp/nobody", nil))
	if w.Code != 404 {
		t.Fatalf("status: %d", w.Code)
	}
}

func TestLNURLPAmountValidation(t *testing.T) {
	srv := walletServer(t)
	for _, amt := range []string{"500", "abc", "99999999999999"} { // <min, broken, >max
		w := httptest.NewRecorder()
		srv.handleLNURLP(w, httptest.NewRequest("GET", "/.well-known/lnurlp/alice?amount="+amt, nil))
		if w.Code != 400 {
			t.Fatalf("amount=%s: %d %s", amt, w.Code, w.Body.String())
		}
	}
	// valid amount, but no LND → LUD-conformant ERROR response
	w := httptest.NewRecorder()
	srv.handleLNURLP(w, httptest.NewRequest("GET", "/.well-known/lnurlp/alice?amount=5000", nil))
	var j map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &j); err != nil {
		t.Fatal(err)
	}
	if j["status"] != "ERROR" || !strings.Contains(j["reason"].(string), "LND") {
		t.Fatalf("ohne LND: %v", j)
	}
}

func TestTopupValidation(t *testing.T) {
	srv := walletServer(t)
	do := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/v1/topup", strings.NewReader(body))
		r.Header.Set("X-Bmail-Account", "alice")
		w := httptest.NewRecorder()
		srv.handleTopup(w, r)
		return w
	}
	for _, body := range []string{`{}`, `{"amount_sats":0}`, `{"amount_sats":-5}`, `{"amount_sats":20000000}`, `kaputt`} {
		if w := do(body); w.Code != 400 {
			t.Fatalf("%s: %d %s", body, w.Code, w.Body.String())
		}
	}
	if w := do(`{"amount_sats":1000}`); w.Code != 503 { // valid, but ln=nil
		t.Fatalf("ohne LND: %d %s", w.Code, w.Body.String())
	}
	if w := do(`{"amount_sats":10000000}`); w.Code != 503 { // upper limit inclusive
		t.Fatalf("max-Betrag ohne LND: %d", w.Code)
	}
}

func TestWithdrawValidation(t *testing.T) {
	srv := walletServer(t)
	do := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/v1/withdraw", strings.NewReader(body))
		r.Header.Set("X-Bmail-Account", "alice")
		w := httptest.NewRecorder()
		srv.handleWithdraw(w, r)
		return w
	}
	for _, body := range []string{`{}`, `{"payment_request":"  "}`, `kaputt`} {
		if w := do(body); w.Code != 400 {
			t.Fatalf("%s: %d %s", body, w.Code, w.Body.String())
		}
	}
	if w := do(`{"payment_request":"lnbcrt1xyz"}`); w.Code != 503 { // ln=nil
		t.Fatalf("ohne LND: %d %s", w.Code, w.Body.String())
	}
}

func TestWalletRoutesNeedAuth(t *testing.T) {
	srv := walletServer(t)
	// auth middleware: without token 401, with token "alice" passed through
	for _, path := range []string{"/v1/topup", "/v1/withdraw"} {
		r := httptest.NewRequest("POST", path, strings.NewReader(`{}`))
		w := httptest.NewRecorder()
		srv.auth(srv.handleTopup)(w, r)
		if w.Code != 401 {
			t.Fatalf("%s ohne Token: %d", path, w.Code)
		}
	}
	if acct, err := srv.ledger.LookupToken("tok1"); err != nil || acct != "alice" {
		t.Fatalf("token lookup: %v %s", err, acct)
	}
}
