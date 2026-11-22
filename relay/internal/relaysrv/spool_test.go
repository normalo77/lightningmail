// Etappe R: Versand-Spool Unit-Tests. Delivery runs through the keysendFn
// seam (lnclient shells out to lncli, so "peer down/again" is modeled there);
// GetInfo hits a fake LND REST via httptest TLS server.
package relaysrv

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightningmail/lm1/crypto"
	"github.com/lightningmail/lm1/envelope"
	"github.com/lightningmail/relay/internal/config"
	"github.com/lightningmail/relay/internal/ledger"
	"github.com/lightningmail/relay/internal/lnclient"
	"github.com/lightningmail/relay/internal/postage"
	"github.com/lightningmail/relay/internal/rates"
)

const spoolTestYAML = `
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
`

const spoolTopupMsat = int64(1_000_000_000) // 1000 sats per account

type spoolFixture struct {
	srv         *Server
	l           *ledger.Ledger
	url         string
	alicePriv   *btcec.PrivateKey
	alicePub    [33]byte
	bobID       int64
	bobRecipH   [32]byte
	failKeysend bool
	delivered   int
}

func spoolSetup(t *testing.T) *spoolFixture {
	t.Helper()
	peerPub, _ := crypto.GenerateKeyPair()
	peerPubB := crypto.PublicBytes(peerPub)
	yaml := strings.Replace(spoolTestYAML, "%s", t.TempDir(), 1) +
		"\npeers:\n  - name: beta\n    url: http://127.0.0.1:9\n    node_pubkey: " +
		hex.EncodeToString(peerPubB[:]) + "\n"
	cfg, err := config.ParseConfig([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	l, err := ledger.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })

	f := &spoolFixture{l: l}
	f.alicePriv, _ = crypto.GenerateKeyPair()
	f.alicePub = crypto.PublicBytes(f.alicePriv)
	bobPriv, _ := crypto.GenerateKeyPair()
	bobPub := crypto.PublicBytes(bobPriv)
	if _, err := l.CreateAccount("alice", f.alicePub[:], 0); err != nil {
		t.Fatal(err)
	}
	bob, err := l.CreateAccount("bob", bobPub[:], 0)
	if err != nil {
		t.Fatal(err)
	}
	f.bobID, f.bobRecipH = bob.ID, bob.RecipientHash
	if err := l.StoreToken("tok-a", "alice"); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"alice", "bob"} {
		if err := l.ApplyDelta(n, spoolTopupMsat, ledger.KindTopup, "test-faucet"); err != nil {
			t.Fatal(err)
		}
	}

	// fake LND REST: /v1/getinfo answers; everything else 500
	fakeLND := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/getinfo" {
			io.WriteString(w, `{"identity_pubkey":"`+hex.EncodeToString(f.alicePub[:])+`"}`)
			return
		}
		http.Error(w, `{"error":"down"}`, 500)
	}))
	t.Cleanup(fakeLND.Close)
	host := strings.TrimPrefix(fakeLND.URL, "https://")

	f.srv = New(cfg, l, lnclient.New(lnclient.Config{RESTHost: host}), postage.New(cfg), rates.NewFeed("", 0))
	f.srv.keysendFn = f.fakeKeysend
	ts := httptest.NewServer(f.srv.routes())
	t.Cleanup(ts.Close)
	f.url = ts.URL
	return f
}

// fakeKeysend plays the peer: fail = "Empfaenger-Relay down", success inserts
// into bob's mailbox exactly like relayd's invoice interceptor (INSERT OR
// IGNORE = R0b idempotency) and counts settlements.
func (f *spoolFixture) fakeKeysend(ctx context.Context, dest string, amt int64, recs map[uint64][]byte) (string, error) {
	if f.failKeysend {
		return "", errors.New("keysend: no route (simulated peer down)")
	}
	env, err := envelope.Decode(recs[34349334])
	if err != nil {
		return "", err
	}
	_, inserted, err := f.l.PutMessage(env.MsgID, f.bobID, recs[34349334], amt*1000)
	if err != nil {
		return "", err
	}
	if inserted {
		f.delivered++
	}
	return hex.EncodeToString(env.MsgID[:]), nil
}

// signedEnv: real envelope alice -> bob, POSTed to /v1/send?to=bob@beta.
func (f *spoolFixture) signedEnv(t *testing.T) ([]byte, string) {
	t.Helper()
	var msgID [32]byte
	rand.Read(msgID[:])
	env := &envelope.Envelope{
		RecipientHash:     f.bobRecipH,
		MsgID:             msgID,
		SenderPubkey:      f.alicePub,
		Timestamp:         time.Now().Unix(),
		PayloadCiphertext: make([]byte, 40),
	}
	sig, err := crypto.SignEnvelope(env, f.alicePriv)
	if err != nil {
		t.Fatal(err)
	}
	env.Signature = sig
	bin, err := env.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return bin, hex.EncodeToString(msgID[:])
}

func (f *spoolFixture) post(t *testing.T, path, tok string, body []byte) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest("POST", f.url+path, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer"+" "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

func (f *spoolFixture) get(t *testing.T, path, tok string) (int, []byte) {
	t.Helper()
	req, _ := http.NewRequest("GET", f.url+path, nil)
	req.Header.Set("Authorization", "Bearer"+" "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

func aliceBal(t *testing.T, l *ledger.Ledger) int64 {
	t.Helper()
	b, err := l.Balance("alice")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestSpoolRetryDeliversExactlyOnce: peer down -> 202 pending row, NO refund;
// peer up -> exported ticker delivers, one mailbox row even on double tick
// (R0b idempotency + double-settle), row removed, outbox empty.
func TestSpoolRetryDeliversExactlyOnce(t *testing.T) {
	f := spoolSetup(t)
	f.failKeysend = true
	before := aliceBal(t, f.l)

	envBin, msgID := f.signedEnv(t)
	code, body := f.post(t, "/v1/send?to=bob@beta", "tok-a", envBin)
	if code != 202 || body["status"] != "pending" {
		t.Fatalf("expected 202 pending, got %d %v", code, body)
	}
	if bal := aliceBal(t, f.l); bal != before-10000 {
		t.Fatalf("postage must stay debited while pending: %d", bal)
	}
	due, err := f.l.SpoolDue(time.Now().Add(6*time.Minute).Unix(), 10)
	if err != nil || len(due) != 1 || due[0].MsgID != msgID || due[0].Sats != 10 {
		t.Fatalf("want 1 due row, got %v err %v", due, err)
	}
	// enqueue dedupe (msg_id UNIQUE): double POST of same mail while pending
	if _, b2 := f.post(t, "/v1/send?to=bob@beta", "tok-a", envBin); b2["error"] == nil {
		t.Fatal("duplicate msg_id must be rejected while pending")
	}
	if _, raw := f.get(t, "/health", "tok-a"); !strings.Contains(string(raw), `"spool":{"pending":1}`) {
		t.Fatalf("health missing spool count: %s", raw)
	}

	f.failKeysend = false
	f.srv.TickSpool(time.Unix(due[0].CreatedAt + 301, 0))
	if n, _ := f.l.SpoolPendingCount(); n != 0 {
		t.Fatalf("row must be deleted after delivery, pending=%d", n)
	}
	if f.delivered != 1 {
		t.Fatalf("want exactly 1 settlement, got %d", f.delivered)
	}
	f.srv.TickSpool(time.Unix(due[0].CreatedAt + 601, 0)) // double-fire scenario
	if f.delivered != 1 {
		t.Fatalf("second tick must not re-deliver: %d", f.delivered)
	}
	msgs, err := f.l.ListMessages(f.bobID, 0, 50)
	if err != nil || len(msgs) != 1 {
		t.Fatalf("mailbox wants exactly 1 row, got %d err %v", len(msgs), err)
	}
	if bal := aliceBal(t, f.l); bal != before-10000 {
		t.Fatalf("retry must not charge again: %d", bal)
	}
	_, raw := f.get(t, "/v1/outbox", "tok-a")
	if strings.TrimSpace(string(raw)) != "[]" {
		t.Fatalf("outbox after delivery must be empty: %s", raw)
	}
}

// TestSpoolDeadLetterRefund: retries keep failing; past retention the tick
// books exactly one fee refund 'dead-refund:<msg_id>' and the outbox shows dead.
func TestSpoolDeadLetterRefund(t *testing.T) {
	f := spoolSetup(t)
	f.failKeysend = true
	before := aliceBal(t, f.l)

	envBin, msgID := f.signedEnv(t)
	code, body := f.post(t, "/v1/send?to=bob@beta", "tok-a", envBin)
	if code != 202 || body["status"] != "pending" {
		t.Fatalf("expected 202 pending, got %d %v", code, body)
	}
	due, _ := f.l.SpoolDue(time.Now().Add(time.Hour).Unix(), 10)
	created := due[0].CreatedAt

	f.srv.TickSpool(time.Unix(created + 301, 0)) // failed attempt -> backoff grows
	due, _ = f.l.SpoolDue(created+300+1800+5, 10)
	if len(due) != 1 || due[0].Attempts != 1 {
		t.Fatalf("want attempts=1 after first failed retry: %+v", due)
	}

	// first tick past 14d retention: dead letter + refund
	f.srv.TickSpool(time.Unix(created + spoolRetentionSec + 1, 0))
	if n, _ := f.l.SpoolPendingCount(); n != 0 {
		t.Fatalf("no pending rows after retention, got %d", n)
	}
	if bal := aliceBal(t, f.l); bal != before {
		t.Fatalf("dead letter must refund exactly the postage: %d vs %d", bal, before)
	}
	hist, _ := f.l.History("alice", 50)
	refunds := 0
	for _, tx := range hist {
		if tx.Kind == ledger.KindFee && tx.Ref == "dead-refund:"+msgID {
			refunds++
		}
	}
	if refunds != 1 {
		t.Fatalf("want exactly one dead-refund booking, got %d", refunds)
	}
	_, raw := f.get(t, "/v1/outbox", "tok-a")
	var list []ledger.OutboxEntry
	json.Unmarshal(raw, &list)
	if len(list) != 1 || list[0].MsgID != msgID || list[0].Status != "dead" || list[0].Since != created {
		t.Fatalf("outbox must show dead entry: %s", raw)
	}

	f.srv.TickSpool(time.Unix(created + spoolRetentionSec + 2, 0)) // must not double-refund
	if bal := aliceBal(t, f.l); bal != before {
		t.Fatalf("double refund detected: %d", bal)
	}
}
