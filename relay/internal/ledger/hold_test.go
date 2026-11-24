package ledger

// Etappe TL (timelock post): envelope tag 0x0B keeps a delivered letter out
// of ListMessages until hold_until passes. PutMessage decodes best-effort;
// the sanity cap is 10 years from insertion.

import (
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightningmail/lm1/crypto"
	"github.com/lightningmail/lm1/envelope"
)

func holdEnv(t *testing.T, notBefore int64) []byte {
	t.Helper()
	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	e := &envelope.Envelope{
		RecipientHash:     sha256.Sum256([]byte("rcpt")),
		MsgID:             sha256.Sum256([]byte("msg-" + time.Now().String())),
		SenderPubkey:      crypto.PublicBytes(priv),
		Timestamp:         time.Now().Unix(),
		PayloadCiphertext: make([]byte, envelope.NonceLen+16),
		EphemeralPubkey:   crypto.PublicBytes(priv),
		NotBefore:         notBefore,
	}
	sig, err := crypto.SignEnvelope(e, priv)
	if err != nil {
		t.Fatal(err)
	}
	e.Signature = sig
	raw, err := e.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestHoldUntil(t *testing.T) {
	l, err := Open(t.TempDir() + "/ledger.db")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	pub := make([]byte, 33)
	_, _ = rand.Read(pub)
	acct, err := l.CreateAccount("holder", pub, 1<<20)
	if err != nil {
		t.Fatal(err)
	}

	// Past not_before is harmless: message is visible immediately.
	ePast := holdEnv(t, time.Now().Add(-time.Hour).Unix())
	if _, ins, err := l.PutMessage(sha256.Sum256([]byte("past")), acct.ID, ePast, 0); err != nil || !ins {
		t.Fatalf("put past: %v ins=%v", err, ins)
	}

	// Future not_before: stored but hidden.
	mid := sha256.Sum256([]byte("future"))
	if _, ins, err := l.PutMessage(mid, acct.ID, holdEnv(t, time.Now().Add(time.Hour).Unix()), 0); err != nil || !ins {
		t.Fatalf("put future: %v ins=%v", err, ins)
	}
	msgs, err := l.ListMessages(acct.ID, 0, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 {
		t.Fatalf("held letter leaked: got %d want 1", len(msgs))
	}

	// Time passes (simulated): now+1y release, message surfaces.
	if _, err := l.db.Exec(`UPDATE mailbox SET hold_until=? WHERE msg_id=?`,
		time.Now().Add(-time.Minute).Unix(), mid[:]); err != nil {
		t.Fatal(err)
	}
	msgs, _ = l.ListMessages(acct.ID, 0, 50)
	if len(msgs) != 2 {
		t.Fatalf("released letter still hidden: got %d want 2", len(msgs))
	}
}

func TestHoldCapTenYears(t *testing.T) {
	l, err := Open(t.TempDir() + "/ledger.db")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	pub := make([]byte, 33)
	_, _ = rand.Read(pub)
	acct, _ := l.CreateAccount("far", pub, 1<<20)
	mid := sha256.Sum256([]byte("farfuture"))
	far := time.Now().AddDate(99, 0, 0).Unix()
	if _, _, err := l.PutMessage(mid, acct.ID, holdEnv(t, far), 0); err != nil {
		t.Fatal(err)
	}
	var hold int64
	if err := l.db.QueryRow(`SELECT hold_until FROM mailbox WHERE msg_id=?`, mid[:]).Scan(&hold); err != nil {
		t.Fatal(err)
	}
	want := time.Now().Add(10 * 365 * 24 * time.Hour).Unix() // cap formula mirrors PutMessage
	if hold > want-600 && hold < want+600 {
		return
	}
	t.Fatalf("99-year hold not capped to ~10 years: hold=%d want~%d", hold, want)
}
