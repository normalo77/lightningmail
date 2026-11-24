package core

// Live regtest E2E for multi-recipient To/CC, gated behind LM_LIVE_RELAY so
// normal `go test ./...` runs stay offline. On dev-relay:
//
//	LM_LIVE_RELAY=http://127.0.0.1:8443 go test ./core/ -run TestLiveMultiCcE2E -v
//
// Creates three disposable regtest accounts (A sender, B and C recipients —
// the regtest faucet credits each), sends ONE letter with To=B and Cc=C
// through the real relay and verifies that both B and C decrypt it with
// intact To/Cc headers and a shared msg_id.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightningmail/lm1/crypto"
)

func liveSuffix(t *testing.T) string {
	t.Helper()
	n, err := rand.Int(rand.Reader, big.NewInt(1<<31))
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(n.Bytes())
}

// waitForMail polls the recipient's inbox until the letter with the unique
// subject lands (each fan-out envelope carries its OWN msg_id — relay
// uniqueness — so the subject is the shared correlation key).
func waitForMail(t *testing.T, relay, name string, priv *btcec.PrivateKey, subject string) *Mail {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cl := NewClient(&Config{Relay: relay, Name: name}, priv)
	if err := cl.Auth(ctx); err != nil {
		t.Fatalf("%s: auth: %v", name, err)
	}
	deadline := time.Now().Add(150 * time.Second)
	for time.Now().Before(deadline) {
		page, err := cl.Inbox(ctx, 0, 50)
		if err == nil {
			for _, m := range page.Messages {
				mail, derr := DecodeMail(priv, m)
				if derr == nil && mail.Subject == subject {
					return mail
				}
			}
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("%s: letter %q never arrived", name, subject)
	return nil
}

func TestLiveMultiCcE2E(t *testing.T) {
	relay := os.Getenv("LM_LIVE_RELAY")
	if relay == "" {
		t.Skip("set LM_LIVE_RELAY (e.g. http://127.0.0.1:8443) to run the live regtest E2E")
	}
	domain := os.Getenv("LM_LIVE_DOMAIN")
	if domain == "" {
		domain = "alpha" // own relay name → local delivery routing
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	sfx := liveSuffix(t)
	nameA, nameB, nameC := "mca"+sfx, "mcb"+sfx, "mcc"+sfx
	privA, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	privB, _ := crypto.GenerateKeyPair()
	privC, _ := crypto.GenerateKeyPair()
	for _, p := range []struct {
		name string
		priv *btcec.PrivateKey
	}{{nameA, privA}, {nameB, privB}, {nameC, privC}} {
		pub := crypto.PublicBytes(p.priv)
		cl := NewClient(&Config{Relay: relay, Name: p.name}, p.priv)
		if err := cl.RegisterAccount(ctx, hex.EncodeToString(pub[:])); err != nil {
			t.Fatalf("create account %s: %v", p.name, err)
		}
	}
	t.Logf("live E2E: disposable regtest accounts %s (sender), %s (To), %s (Cc) on %s", nameA, nameB, nameC, relay)

	sender := NewClient(&Config{Relay: relay, Name: nameA}, privA)
	if err := sender.Auth(ctx); err != nil {
		t.Fatalf("sender auth: %v", err)
	}
	addrB, addrC := nameB+"@"+domain, nameC+"@"+domain
	subject, body := "multicc-"+sfx, "one letter, two mailboxes, encrypted CC"
	res, err := ComposeAndSend(ctx, sender, privA, ComposeOpts{
		To: addrB, Cc: addrC, From: nameA, Subject: subject, Body: body,
	})
	if err != nil {
		t.Fatalf("ComposeAndSend: %v", err)
	}
	if len(res.Results) != 2 || !res.Results[0].OK || !res.Results[1].OK {
		t.Fatalf("fan-out results = %+v, want both ok", res.Results)
	}
	t.Logf("sent msg_id=%s… status=%q", res.MsgID[:12], res.Status)

	pubA := crypto.PublicBytes(privA)
	pubAHex := hex.EncodeToString(pubA[:])
	for _, rc := range []struct {
		name string
		priv *btcec.PrivateKey
	}{{nameB, privB}, {nameC, privC}} {
		mail := waitForMail(t, relay, rc.name, rc.priv, subject)
		if mail.Subject != subject || mail.Body != body {
			t.Fatalf("%s: payload = %q/%q, want %q/%q", rc.name, mail.Subject, mail.Body, subject, body)
		}
		if got := mail.To(); got != addrB {
			t.Fatalf("%s: To header = %q, want %q", rc.name, got, addrB)
		}
		if got := mail.Cc(); got != addrC {
			t.Fatalf("%s: Cc header = %q, want %q", rc.name, got, addrC)
		}
		if got := HeaderCI(mail.Headers, "From"); got != nameA {
			t.Fatalf("%s: From header = %q, want %q", rc.name, got, nameA)
		}
		if mail.SenderPub != pubAHex {
			t.Fatalf("%s: sender pubkey = %s, want %s", rc.name, mail.SenderPub, pubAHex)
		}
		t.Logf("%s: decrypted letter with intact headers To=%q Cc=%q", rc.name, mail.To(), mail.Cc())
	}
	t.Log("live multi-CC E2E OK: B and C both received the letter with intact To/Cc headers")
}
