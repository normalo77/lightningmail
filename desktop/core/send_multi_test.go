package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightningmail/lm1/crypto"
	"github.com/lightningmail/lm1/envelope"
)

// sendRec is one captured POST /v1/send.
type sendRec struct {
	to   string
	body []byte
}

// fanoutFixture mocks a relay: profile lookups answer from pubs, sends are
// captured. failProfile makes one recipient's profile 404.
func fanoutFixture(t *testing.T, pubs map[string]string, failProfile string) (*httptest.Server, *[]sendRec, *sync.Mutex) {
	t.Helper()
	var mu sync.Mutex
	sends := &[]sendRec{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && r.URL.Path == "/v1/auth":
			_ = json.NewEncoder(w).Encode(map[string]string{"token": "tok"})
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/v1/profile/"):
			name := strings.TrimPrefix(r.URL.Path, "/v1/profile/")
			name = strings.SplitN(name, "@", 2)[0]
			if name == failProfile {
				http.Error(w, "not found", 404)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"pubkey": pubs[name], "postage_sats": 5})
		case r.Method == "POST" && r.URL.Path == "/v1/send":
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			*sends = append(*sends, sendRec{to: r.URL.Query().Get("to"), body: body})
			mu.Unlock()
			w.WriteHeader(202)
			_ = json.NewEncoder(w).Encode(map[string]string{"msg_id": "", "status": "sent"})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, sends, &mu
}

// decodePayload decrypts one captured envelope with the recipient's key.
func decodePayload(t *testing.T, wire []byte, priv *btcec.PrivateKey) (envMsgID string, p map[string]any) {
	t.Helper()
	env, err := envelope.Decode(wire)
	if err != nil {
		t.Fatalf("envelope decode: %v", err)
	}
	aad := make([]byte, 64)
	copy(aad[:32], env.RecipientHash[:])
	copy(aad[32:], env.MsgID[:])
	pt, err := crypto.DecryptForRecipient(priv, env.EphemeralPubkey[:], env.PayloadCiphertext, aad)
	if err != nil {
		t.Fatalf("payload decrypt: %v", err)
	}
	if err := json.Unmarshal(pt, &p); err != nil {
		t.Fatalf("payload json: %v", err)
	}
	return hex.EncodeToString(env.MsgID[:]), p
}

func TestComposeAndSendFanOut(t *testing.T) {
	senderPriv, _ := btcec.NewPrivateKey()
	privB, _ := btcec.NewPrivateKey()
	privC, _ := btcec.NewPrivateKey()
	pubs := map[string]string{
		"bob":   hex.EncodeToString(privB.PubKey().SerializeCompressed()),
		"carol": hex.EncodeToString(privC.PubKey().SerializeCompressed()),
	}
	srv, sends, mu := fanoutFixture(t, pubs, "")
	c := NewClient(&Config{Relay: srv.URL, Name: "alice"}, senderPriv)

	res, err := ComposeAndSend(context.Background(), c, senderPriv, ComposeOpts{
		To: "bob, BOB", Cc: "carol;bob", From: "alice@x", Subject: "s", Body: "b",
	})
	if err != nil {
		t.Fatalf("ComposeAndSend: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(*sends) != 2 || (*sends)[0].to != "bob" || (*sends)[1].to != "carol" {
		t.Fatalf("fan-out sends = %+v, want [bob carol] (deduped)", *sends)
	}
	if len(res.Results) != 2 || !res.Results[0].OK || !res.Results[1].OK {
		t.Fatalf("results = %+v, want both ok", res.Results)
	}

	idB, pB := decodePayload(t, (*sends)[0].body, privB)
	idC, pC := decodePayload(t, (*sends)[1].body, privC)
	if idB == idC {
		t.Fatalf("fan-out envelopes must carry distinct msg_ids (relay uniqueness): both %s", idB)
	}
	for name, p := range map[string]map[string]any{"bob": pB, "carol": pC} {
		h, _ := p["headers"].(map[string]any)
		if h["To"] != "bob" || h["Cc"] != "carol" || h["From"] != "alice@x" {
			t.Fatalf("%s headers = %v, want To=bob Cc=carol From=alice@x", name, h)
		}
		if p["subject"] != "s" || p["body"] != "b" {
			t.Fatalf("%s payload = %v", name, p)
		}
	}
}

func TestComposeAndSendSingleNoCcHeader(t *testing.T) {
	senderPriv, _ := btcec.NewPrivateKey()
	privB, _ := btcec.NewPrivateKey()
	pubs := map[string]string{"bob": hex.EncodeToString(privB.PubKey().SerializeCompressed())}
	srv, sends, mu := fanoutFixture(t, pubs, "")
	c := NewClient(&Config{Relay: srv.URL, Name: "alice"}, senderPriv)

	if _, err := ComposeAndSend(context.Background(), c, senderPriv, ComposeOpts{To: " bob ", Subject: "x", Body: "y"}); err != nil {
		t.Fatalf("ComposeAndSend: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(*sends) != 1 || (*sends)[0].to != "bob" {
		t.Fatalf("sends = %+v, want one trimmed bob", *sends)
	}
	_, p := decodePayload(t, (*sends)[0].body, privB)
	h, _ := p["headers"].(map[string]any)
	if h["To"] != "bob" {
		t.Fatalf("headers = %v, want To=bob", h)
	}
	if _, hasCc := h["Cc"]; hasCc {
		t.Fatalf("empty CC must not appear in headers: %v", h)
	}
	if _, hasFrom := h["From"]; hasFrom {
		t.Fatalf("unset From must not appear in headers: %v", h)
	}
}

func TestComposeAndSendPartialFailure(t *testing.T) {
	senderPriv, _ := btcec.NewPrivateKey()
	privB, _ := btcec.NewPrivateKey()
	pubs := map[string]string{"bob": hex.EncodeToString(privB.PubKey().SerializeCompressed())}
	srv, sends, mu := fanoutFixture(t, pubs, "carol") // carol's profile 404s
	c := NewClient(&Config{Relay: srv.URL, Name: "alice"}, senderPriv)

	res, err := ComposeAndSend(context.Background(), c, senderPriv, ComposeOpts{To: "bob", Cc: "carol", Subject: "x", Body: "y"})
	if err != nil {
		t.Fatalf("partial failure must not error overall: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(*sends) != 1 {
		t.Fatalf("sends = %d, want 1 (only bob)", len(*sends))
	}
	if len(res.Results) != 2 || !res.Results[0].OK || res.Results[1].OK {
		t.Fatalf("results = %+v, want bob ok / carol failed", res.Results)
	}
	if res.Results[1].To != "carol" || res.Results[1].Err == "" {
		t.Fatalf("carol result must name the recipient and carry the error: %+v", res.Results[1])
	}
}

func TestComposeAndSendAllFail(t *testing.T) {
	senderPriv, _ := btcec.NewPrivateKey()
	srv, _, _ := fanoutFixture(t, map[string]string{}, "bob")
	c := NewClient(&Config{Relay: srv.URL, Name: "alice"}, senderPriv)

	_, err := ComposeAndSend(context.Background(), c, senderPriv, ComposeOpts{To: "bob", Subject: "x", Body: "y"})
	if err == nil {
		t.Fatal("all recipients failing must return an error")
	}
	if _, err := ComposeAndSend(context.Background(), c, senderPriv, ComposeOpts{To: " , ", Subject: "x"}); err == nil {
		t.Fatal("empty recipient list must error")
	}
}

// the AAD (recipient_hash || msg_id) must bind each fan-out copy to its own
// recipient hash — a copy re-addressed to another mailbox must not decrypt.
func TestFanOutAADBindsRecipient(t *testing.T) {
	senderPriv, _ := btcec.NewPrivateKey()
	privB, _ := btcec.NewPrivateKey()
	privC, _ := btcec.NewPrivateKey()
	pubs := map[string]string{
		"bob":   hex.EncodeToString(privB.PubKey().SerializeCompressed()),
		"carol": hex.EncodeToString(privC.PubKey().SerializeCompressed()),
	}
	srv, sends, mu := fanoutFixture(t, pubs, "")
	c := NewClient(&Config{Relay: srv.URL, Name: "alice"}, senderPriv)
	if _, err := ComposeAndSend(context.Background(), c, senderPriv, ComposeOpts{To: "bob", Cc: "carol", Subject: "s", Body: "b"}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	env, err := envelope.Decode((*sends)[0].body) // bob's envelope
	if err != nil {
		t.Fatal(err)
	}
	// decrypt with carol's key but bob's AAD: must fail (wrong shared secret)
	aad := make([]byte, 64)
	copy(aad[:32], env.RecipientHash[:])
	copy(aad[32:], env.MsgID[:])
	if _, err := crypto.DecryptForRecipient(privC, env.EphemeralPubkey[:], env.PayloadCiphertext, aad); err == nil {
		t.Fatal("cross-recipient decryption must fail")
	}
	// sanity: sha256 of the recipient pubkey is the envelope's recipient hash
	pubB := crypto.PublicBytes(privB)
	rh := sha256.Sum256(pubB[:])
	if rh != env.RecipientHash {
		t.Fatal("recipient hash mismatch")
	}
}
