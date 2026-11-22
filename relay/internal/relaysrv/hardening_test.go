package relaysrv

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lightningmail/lm1/crypto"
	"github.com/lightningmail/lm1/envelope"
	"github.com/lightningmail/relay/internal/config"
	"github.com/lightningmail/relay/internal/ledger"
	"github.com/lightningmail/relay/internal/postage"
	"github.com/lightningmail/relay/internal/rates"
)

func TestPostageFiveEuroCentsAndRoutingFee(t *testing.T) {
	// 5 EUR-cent (50 mEUR) at 53,900 EUR/BTC -> ceil(50*1e8/53900000) = 93 sats
	if got := PostageSatsFromMEur(50, 53_900_000); got != 93 {
		t.Fatalf("PostageSatsFromMEur(50, 53.9M) = %d, want 93", got)
	}
	// 5 EUR-cent at 100,000 EUR/BTC -> 50 sats
	if got := PostageSatsFromMEur(50, 100_000_000); got != 50 {
		t.Fatalf("PostageSatsFromMEur(50, 100M) = %d, want 50", got)
	}
	// 0.3% routing fee cap in msat
	if got := MaxRoutingFeeMsat(100); got != 300 {
		t.Fatalf("MaxRoutingFeeMsat(100) = %d, want 300", got)
	}
}

func TestSenderPaysActualRoutingFeeAndFiveCentPostage(t *testing.T) {
	f := spoolSetup(t)
	// Enable 5 EUR-cent postage with 100,000 EUR/BTC manual rate -> 50 sats base postage
	f.srv.cfg.Postage.ForeignMEur = 50
	f.srv.rateFeed = rates.NewFeed("", 100_000)

	// Simulate 75 msat actual routing fee (<= 0.3% of 50 sats = 150 msat)
	f.srv.keysendFn = func(ctx context.Context, dest string, amt int64, recs map[uint64][]byte) (string, int64, error) {
		if amt != 50 {
			t.Errorf("keysend amt = %d, want 50 (5 EUR-cent @ 100k EUR/BTC)", amt)
		}
		return "deadbeef", 75, nil // short preimage also tests no slice panic
	}

	envBin, _ := f.signedEnv(t)
	req, _ := http.NewRequest("POST", f.url+"/v1/send?to=bob@beta", bytes.NewReader(envBin))
	req.Header.Set("Authorization", "Bearer tok-a")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 202 {
		t.Fatalf("send status = %d, want 202", resp.StatusCode)
	}
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if int64(out["routing_fee_msat"].(float64)) != 75 {
		t.Fatalf("routing_fee_msat = %v, want 75", out["routing_fee_msat"])
	}
	// Balance should be reduced by exactly 50,000 msat postage + 75 msat fee
	bal, err := f.l.Balance("alice")
	if err != nil {
		t.Fatal(err)
	}
	want := spoolTopupMsat - 50_075
	if bal != want {
		t.Fatalf("alice balance = %d, want %d (delta %d)", bal, want, bal-want)
	}
}

func TestSingleRelayLocalDeliveryWithoutPeers(t *testing.T) {
	yaml := strings.Replace(spoolTestYAML, "%s", t.TempDir(), 1)
	cfg, err := config.ParseConfig([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	l, err := ledger.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	alicePriv, _ := crypto.GenerateKeyPair()
	alicePub := crypto.PublicBytes(alicePriv)
	bobPriv, _ := crypto.GenerateKeyPair()
	bobPub := crypto.PublicBytes(bobPriv)
	_, _ = l.CreateAccount("alice", alicePub[:], 0)
	bob, _ := l.CreateAccount("bob", bobPub[:], 0)
	_ = l.StoreToken("tok-a", "alice")
	_ = l.ApplyDelta("alice", 100_000, ledger.KindTopup, "init")

	srv := New(cfg, l, nil, postage.New(cfg), rates.NewFeed("", 0))
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	var msgID [32]byte
	rand.Read(msgID[:])
	env := &envelope.Envelope{
		RecipientHash:     bob.RecipientHash,
		MsgID:             msgID,
		SenderPubkey:      alicePub,
		Timestamp:         time.Now().Unix(),
		PayloadCiphertext: make([]byte, 40),
		EphemeralPubkey:   alicePub,
	}
	sig, _ := crypto.SignEnvelope(env, alicePriv)
	env.Signature = sig
	envBin, _ := env.MarshalBinary()

	req, _ := http.NewRequest("POST", ts.URL+"/v1/send?to=bob", bytes.NewReader(envBin))
	req.Header.Set("Authorization", "Bearer tok-a")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 202 {
		t.Fatalf("single-relay local send status = %d, want 202", resp.StatusCode)
	}
	msgs, err := l.ListMessages(bob.ID, 0, 10)
	if err != nil || len(msgs) != 1 || hex.EncodeToString(msgs[0].MsgID[:]) != hex.EncodeToString(msgID[:]) {
		t.Fatalf("bob inbox = %d msgs, err=%v", len(msgs), err)
	}
}

func TestPeerHTTPTorFailClosed(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	cfg := &config.Config{Tor: config.Tor{Socks5: "not-a-valid-socks"}}
	cl := cfg.PeerHTTP(2 * time.Second)
	if _, err := cl.Get(srv.URL); err == nil {
		t.Fatal("expected error for malformed tor.socks5, got nil")
	}
	if hits.Load() != 0 {
		t.Fatalf("fail-open leak: peer server got %d direct hits", hits.Load())
	}
}
