package core

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
)

func TestParseTorSocks(t *testing.T) {
	valid := []struct{ in, want string }{
		{"", ""},
		{"127.0.0.1:9050", "socks5h://127.0.0.1:9050"},
		{"socks5://127.0.0.1:9050", "socks5h://127.0.0.1:9050"},
		{"socks5h://[::1]:9050", "socks5h://[::1]:9050"},
	}
	for _, tc := range valid {
		u, err := ParseTorSocks(tc.in)
		if err != nil {
			t.Fatalf("ParseTorSocks(%q) unexpected err: %v", tc.in, err)
		}
		got := ""
		if u != nil {
			got = u.String()
		}
		if got != tc.want {
			t.Fatalf("ParseTorSocks(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	invalid := []string{"127.0.0.1", ":9050", "127.0.0.1:0", "127.0.0.1:70000", "socks5://socks5://127.0.0.1:9050"}
	for _, in := range invalid {
		if _, err := ParseTorSocks(in); err == nil {
			t.Fatalf("ParseTorSocks(%q) succeeded, expected error", in)
		}
	}
}

func TestNewClientTorFailClosed(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	c := NewClient(&Config{Relay: srv.URL, Name: "alice", TorSocks: "bad-tor-addr"}, priv)
	if _, err := c.Balance(context.Background()); err == nil {
		t.Fatal("expected error for invalid tor_socks, got nil")
	}
	if hits.Load() != 0 {
		t.Fatalf("fail-open leak: server received %d direct requests despite invalid tor_socks", hits.Load())
	}
}

func TestComposeAndSendPreservesFederatedDomain(t *testing.T) {
	senderPriv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	recvPriv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	recvPubHex := hex.EncodeToString(recvPriv.PubKey().SerializeCompressed())

	var gotProfilePath, gotSendTo string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && r.URL.Path == "/v1/auth":
			_ = json.NewEncoder(w).Encode(map[string]string{"token": "tok"})
		case r.Method == "GET" && r.URL.Path == "/v1/profile/bob@other.example":
			gotProfilePath = r.URL.Path
			_ = json.NewEncoder(w).Encode(map[string]any{"pubkey": recvPubHex, "postage_sats": 5})
		case r.Method == "POST" && r.URL.Path == "/v1/send":
			gotSendTo = r.URL.Query().Get("to")
			w.WriteHeader(202)
			_ = json.NewEncoder(w).Encode(map[string]string{"msg_id": "abc", "status": "sent"})
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.String())
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := NewClient(&Config{Relay: srv.URL, Name: "alice"}, senderPriv)
	res, err := ComposeAndSend(context.Background(), c, senderPriv, ComposeOpts{
		To:      "bob@other.example",
		Subject: "Hi",
		Body:    "Federated test",
	})
	if err != nil {
		t.Fatalf("ComposeAndSend failed: %v", err)
	}
	if gotProfilePath != "/v1/profile/bob@other.example" {
		t.Fatalf("profile path = %q, want federated path", gotProfilePath)
	}
	if gotSendTo != "bob@other.example" {
		t.Fatalf("send to = %q, want bob@other.example", gotSendTo)
	}
	if res.MsgID != "abc" {
		t.Fatalf("msg_id = %q, want abc", res.MsgID)
	}
}
