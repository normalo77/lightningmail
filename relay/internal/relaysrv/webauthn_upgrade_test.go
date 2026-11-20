package relaysrv

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lightningmail/relay/internal/crypto"
	"github.com/lightningmail/relay/internal/ledger"
)

// §21 PRF-Selbstheilung: POST /v1/webauthn/wrap-upgrade (auth) hebt den Wrap
// einer eigenen Credential auf LMKEY1$PRF$, ohne den Passphrase-Fallback zu zerstoeren.
func TestWAWrapUpgrade(t *testing.T) {
	srv, priv := newOIDCTestServer(t)

	pub := crypto.PublicBytes(priv)
	pubHex := hex.EncodeToString(pub[:])
	sig, err := crypto.Sign(priv, crypto.AuthDigest([]byte("bmail-auth-v1:alice")))
	if err != nil {
		t.Fatal(err)
	}
	abody, _ := json.Marshal(map[string]string{"address": "alice", "pubkey_hex": pubHex, "sig": hex.EncodeToString(sig[:])})
	arec := httptest.NewRecorder()
	srv.handleAuth(arec, httptest.NewRequest(http.MethodPost, "/v1/auth", bytes.NewReader(abody)))
	var out map[string]string
	_ = json.Unmarshal(arec.Body.Bytes(), &out)
	if out["token"] == "" {
		t.Fatalf("kein Token: %s", arec.Body.String())
	}

	if err := srv.ledger.WAStoreCredential(ledger.WACredential{CredID: "TESTCRED1", Account: "alice", Name: "test", PublicKey: pub[:]}); err != nil {
		t.Fatal(err)
	}
	if err := srv.ledger.WAStoreWraps("TESTCRED1", "", "LMKEY1$salt$nonce$ct"); err != nil {
		t.Fatal(err)
	}

	// unauthentifiziert -> 401
	bad, _ := json.Marshal(map[string]string{"cred_id": "TESTCRED1", "wrap_prf": "LMKEY1$PRF$n$c"})
	rec := httptest.NewRecorder()
	srv.auth(srv.handleWAWrapUpgrade)(rec, httptest.NewRequest(http.MethodPost, "/v1/webauthn/wrap-upgrade", bytes.NewReader(bad)))
	if rec.Code != 401 {
		t.Fatalf("no-auth: got %d, want 401", rec.Code)
	}

	post := func(cred, wrap string, want int) {
		b, _ := json.Marshal(map[string]string{"cred_id": cred, "wrap_prf": wrap})
		req := httptest.NewRequest(http.MethodPost, "/v1/webauthn/wrap-upgrade", bytes.NewReader(b))
		req.Header.Set("Auth"+"orization", "Bearer "+out["token"])
		rec := httptest.NewRecorder()
		srv.auth(srv.handleWAWrapUpgrade)(rec, req)
		if rec.Code != want {
			t.Fatalf("cred=%q wrap=%.16q: got %d, want %d (%s)", cred, wrap, rec.Code, want, rec.Body.String())
		}
	}
	post("TESTCRED1", "LMKEY1$wrongformat", 400)
	post("GHOSTCRED", "LMKEY1$PRF$n$c", 404)
	post("TESTCRED1", "LMKEY1$PRF$abc$def", 200)

	prf, pass, err := srv.ledger.WAGetWraps("TESTCRED1")
	if err != nil {
		t.Fatal(err)
	}
	if prf != "LMKEY1$PRF$abc$def" {
		t.Fatalf("wrap_prf nicht gehoben: %q", prf)
	}
	if pass != "LMKEY1$salt$nonce$ct" {
		t.Fatalf("wrap_pass-Fallback verloren: %q", pass)
	}
}
