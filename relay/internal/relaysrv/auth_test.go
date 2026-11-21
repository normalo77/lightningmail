package relaysrv

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lightningmail/lm1/crypto"
)

func TestAuthPubkeyAutoLookup(t *testing.T) {
	srv, priv := newOIDCTestServer(t)

	pub := crypto.PublicBytes(priv)
	pubHex := hex.EncodeToString(pub[:])
	digest := crypto.AuthDigest([]byte("bmail-auth-v1:" + pubHex))
	sig, err := crypto.Sign(priv, digest)
	if err != nil {
		t.Fatal(err)
	}

	// 1. auto lookup without account name (address="") -> returns token + "alice"
	body, _ := json.Marshal(map[string]string{
		"address":    "",
		"pubkey_hex": pubHex,
		"sig":        hex.EncodeToString(sig[:]),
	})
	rec := httptest.NewRecorder()
	srv.handleAuth(rec, httptest.NewRequest(http.MethodPost, "/v1/auth", bytes.NewReader(body)))
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var out map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out["address"] != "alice" || out["token"] == "" {
		t.Fatalf("unexpected auth response: %+v", out)
	}

	// token works for authenticated endpoints
	reqBal := httptest.NewRequest(http.MethodGet, "/v1/balance", nil)
	reqBal.Header.Set("Auth"+"orization", "Bearer "+out["token"])
	recBal := httptest.NewRecorder()
	srv.auth(srv.handleBalance)(recBal, reqBal)
	if recBal.Code != 200 {
		t.Fatalf("balance with auto-lookup token failed: %d", recBal.Code)
	}

	// 2. unknown key with valid self-signature -> 404
	otherPriv, _ := crypto.GenerateKeyPair()
	otherPub := crypto.PublicBytes(otherPriv)
	otherHex := hex.EncodeToString(otherPub[:])
	otherSig, _ := crypto.Sign(otherPriv, crypto.AuthDigest([]byte("bmail-auth-v1:"+otherHex)))
	body2, _ := json.Marshal(map[string]string{
		"address":    "",
		"pubkey_hex": otherHex,
		"sig":        hex.EncodeToString(otherSig[:]),
	})
	rec2 := httptest.NewRecorder()
	srv.handleAuth(rec2, httptest.NewRequest(http.MethodPost, "/v1/auth", bytes.NewReader(body2)))
	if rec2.Code != 404 {
		t.Fatalf("expected 404 for unknown pubkey, got %d", rec2.Code)
	}

	// 3. forged signature for a known key -> 401
	body3, _ := json.Marshal(map[string]string{
		"address":    "",
		"pubkey_hex": pubHex,
		"sig":        hex.EncodeToString(otherSig[:]),
	})
	rec3 := httptest.NewRecorder()
	srv.handleAuth(rec3, httptest.NewRequest(http.MethodPost, "/v1/auth", bytes.NewReader(body3)))
	if rec3.Code != 401 {
		t.Fatalf("expected 401 for bad signature, got %d", rec3.Code)
	}
}
