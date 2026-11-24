package imapserver

// Live regtest E2E for Etappe B2, gated behind LM_BRIDGE_LIVE_RELAY so normal
// `go test ./...` runs stay offline. On dev-relay:
//
//	LM_BRIDGE_LIVE_RELAY=http://127.0.0.1:8443 \
//	  go test ./internal/imapserver/ -run TestLiveRelayIMAPE2E -v
//
// It creates two disposable regtest accounts (A = LM sender, B = bridge),
// sends one letter A→B through the real relay, then runs B's syncer plus IMAP
// server and verifies over a real IMAP wire connection:
//   - the letter arrives in INBOX, decrypted, with body and envelope intact
//   - marking it \Seen propagates into /v1/state on the real relay
//     (read[msg_id] = 1), without clobbering the rest of the state doc.
//
// Same-relay note (as in B1): delivery without LN keysend grants B no blob
// ACL, so the attachment blob fetch 403s — which is exactly the graceful
// placeholder path this Etappe must survive. The letter itself must still
// sync; the attachment degrades to a note part.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"

	"github.com/lightningmail/bridge/internal/relayclient"
	"github.com/lightningmail/lm1/crypto"
)

func randHex4Live(t *testing.T) string {
	t.Helper()
	n, err := rand.Int(rand.Reader, big.NewInt(1<<31))
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%08x", n.Int64())
}

func TestLiveRelayIMAPE2E(t *testing.T) {
	relayURL := os.Getenv("LM_BRIDGE_LIVE_RELAY")
	if relayURL == "" {
		t.Skip("set LM_BRIDGE_LIVE_RELAY (e.g. http://127.0.0.1:8443) to run the live regtest E2E")
	}
	domain := os.Getenv("LM_BRIDGE_LIVE_DOMAIN")
	if domain == "" {
		domain = "alpha"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	suffix := randHex4Live(t)
	nameA, nameB := "bi2a"+suffix, "bi2b"+suffix
	privA, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	privB, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pkA, pkB := crypto.PublicBytes(privA), crypto.PublicBytes(privB)
	pubA, pubB := hex.EncodeToString(pkA[:]), hex.EncodeToString(pkB[:])
	if err := relayclient.CreateAccount(ctx, relayURL, nameA, pubA); err != nil {
		t.Fatalf("create sender account: %v", err)
	}
	if err := relayclient.CreateAccount(ctx, relayURL, nameB, pubB); err != nil {
		t.Fatalf("create bridge account: %v", err)
	}
	t.Logf("live IMAP E2E: disposable regtest accounts %s (sender) and %s (bridge)", nameA, nameB)
	lmAddrB := nameB + "@" + domain

	// 1. A sends one LM letter with a small (inline) attachment to B.
	clientA := relayclient.New(relayURL, nameA, privA)
	if err := clientA.Login(ctx); err != nil {
		t.Fatalf("sender login: %v", err)
	}
	// Warm the profile path (cold onion circuits answer false 404s — known
	// regtest pitfall, same workaround as the B1 live test).
	var prof *relayclient.Profile
	for attempt := 0; attempt < 8; attempt++ {
		p, found, err := clientA.LookupProfile(ctx, lmAddrB)
		if err == nil && found {
			prof = p
			break
		}
		t.Logf("profile warmup %d: found=%v err=%v", attempt, found, err)
		time.Sleep(3 * time.Second)
	}
	if prof == nil {
		t.Fatalf("profile lookup for %s never succeeded", lmAddrB)
	}
	subject := "live imap " + suffix
	body := "Hello B2 from the live E2E " + suffix
	att := []byte("live attachment bytes " + suffix)
	res, err := clientA.SendMessage(ctx, lmAddrB, prof, &relayclient.Message{
		Subject:     subject,
		Body:        body,
		Headers:     map[string]string{"from": nameA + "@" + domain},
		Attachments: []relayclient.File{{Name: "note.txt", Bytes: att}},
	})
	if err != nil {
		t.Fatalf("send letter: %v", err)
	}
	msgID := res.MsgID
	t.Logf("letter sent: msg_id %s", msgID)

	// 2. B side: SQLite cache + syncer + IMAP server on a random port.
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	clientB := relayclient.New(relayURL, nameB, privB)
	syncer := NewSyncer(clientB, privB, store, nameB, time.Second)
	sctx, scancel := context.WithCancel(ctx)
	defer scancel()
	syncDone := make(chan struct{})
	go func() { defer close(syncDone); syncer.Run(sctx) }()
	defer func() { scancel(); <-syncDone }()

	bridgePass := randHex4Live(t) + randHex4Live(t)
	isrv := NewServer(Options{AuthUser: "bridge", AuthPass: bridgePass, Store: store})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go isrv.Serve(ln)
	defer isrv.Close()

	// 3. Real IMAP client: login, wait for the letter, fetch and verify.
	c, err := imapclient.DialInsecure(ln.Addr().String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Login("bridge", bridgePass).Wait(); err != nil {
		t.Fatalf("IMAP LOGIN: %v", err)
	}
	// Fresh regtest accounts also receive a signup letter, so the target may
	// not sit at seq 1: poll-fetch the full range until the msg_id shows up.
	// go-message's envelope parser strips the angle brackets from Message-ID
	wantMID := msgID + "@lmbridge"
	var found *imapclient.FetchMessageBuffer
	deadline := time.Now().Add(150 * time.Second)
	for found == nil {
		sel, err := c.Select("INBOX", nil).Wait()
		if err != nil {
			t.Fatalf("SELECT INBOX: %v", err)
		}
		if sel.NumMessages > 0 {
			nums := make([]uint32, sel.NumMessages)
			for i := range nums {
				nums[i] = uint32(i) + 1
			}
			fcmd := c.Fetch(imap.SeqSetNum(nums...), &imap.FetchOptions{
				UID: true, Flags: true, Envelope: true,
				BodySection: []*imap.FetchItemBodySection{{Peek: true}},
			})
			msgs, err := fcmd.Collect()
			if err != nil {
				t.Fatal(err)
			}
			for _, m := range msgs {
				if m.Envelope != nil && m.Envelope.MessageID == wantMID {
					found = m
				}
			}
		}
		if found == nil {
			if time.Now().After(deadline) {
				t.Fatalf("syncer never delivered letter %s into INBOX", msgID)
			}
			time.Sleep(time.Second)
		}
	}
	if found.Envelope.Subject != subject {
		t.Fatalf("subject = %q, want %q", found.Envelope.Subject, subject)
	}
	if len(found.BodySection) != 1 {
		t.Fatalf("body sections = %d", len(found.BodySection))
	}
	raw := found.BodySection[0].Bytes
	if got := firstTextPart(t, raw); got != body {
		t.Fatalf("body = %q, want %q", got, body)
	}
	if !strings.Contains(string(raw), "note.txt") {
		t.Fatal("attachment name missing from the MIME structure")
	}
	// Same-relay delivery grants no blob ACL: the letter must survive with a
	// placeholder note instead of the real attachment bytes.
	if strings.Contains(string(raw), "not available from the relay") {
		t.Log("attachment blob was refused (same-relay ACL): placeholder path verified")
	}
	for _, fl := range found.Flags {
		if fl == imap.FlagSeen {
			t.Fatal("fresh letter must not be \\Seen")
		}
	}

	// 4. Mark \Seen over IMAP → the syncer must push it into /v1/state.
	if _, err := c.Store(imap.SeqSetNum(found.SeqNum),
		&imap.StoreFlags{Op: imap.StoreFlagsAdd, Flags: []imap.Flag{imap.FlagSeen}}, nil).Collect(); err != nil {
		t.Fatalf("STORE \\Seen: %v", err)
	}
	stateDeadline := time.Now().Add(90 * time.Second)
	for {
		st, err := clientB.GetState(ctx)
		if err != nil {
			t.Fatalf("GET /v1/state: %v", err)
		}
		if st.Doc.Read()[msgID] == 1 {
			t.Logf("live E2E OK: \\Seen propagated to /v1/state (version %d)", st.Version)
			break
		}
		if time.Now().After(stateDeadline) {
			t.Fatalf("read flag never reached /v1/state (version %d, read=%v)", st.Version, st.Doc.Read())
		}
		time.Sleep(2 * time.Second)
	}
	if err := c.Logout().Wait(); err != nil {
		t.Fatalf("LOGOUT: %v", err)
	}
}
