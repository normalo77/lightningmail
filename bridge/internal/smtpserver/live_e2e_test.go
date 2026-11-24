package smtpserver

// Live regtest E2E for Etappe B1, gated behind LM_BRIDGE_LIVE_RELAY so normal
// `go test ./...` runs stay offline. On dev-relay:
//
//	LM_BRIDGE_LIVE_RELAY=http://127.0.0.1:8443 \
//	  go test ./internal/smtpserver/ -run TestLiveRelayMixedE2E -v
//
// It creates two disposable regtest accounts (A = bridge sender, B = LM
// recipient), submits one MIXED mail (LM recipient + classic recipient, with
// a 1.2 MiB attachment to force the chunked upload path) through the real
// bridge server, then verifies:
//   - B decrypts subject/body/attachment byte-identically from /v1/inbox
//   - the classic mock received a copy WITHOUT the LM address and WITH the
//     configured Reply-To.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"

	"github.com/lightningmail/bridge/internal/relayclient"
	"github.com/lightningmail/lm1/crypto"
)

// --- mock classic SMTP collector ------------------------------------------------

type classicMsg struct {
	From string
	To   []string
	Raw  []byte
}

type collectorBackend struct {
	mu  sync.Mutex
	got []classicMsg
}

func (b *collectorBackend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	return &collectorSession{b: b}, nil
}

type collectorSession struct {
	b    *collectorBackend
	from string
	tos  []string
}

func (s *collectorSession) Reset()                                      { s.from = ""; s.tos = nil }
func (s *collectorSession) Logout() error                               { return nil }
func (s *collectorSession) Mail(from string, o *smtp.MailOptions) error { s.from = from; return nil }
func (s *collectorSession) Rcpt(to string, o *smtp.RcptOptions) error {
	s.tos = append(s.tos, to)
	return nil
}
func (s *collectorSession) Data(r io.Reader) error {
	raw, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	s.b.mu.Lock()
	s.b.got = append(s.b.got, classicMsg{From: s.from, To: append([]string(nil), s.tos...), Raw: raw})
	s.b.mu.Unlock()
	return nil
}

func (b *collectorBackend) messages() []classicMsg {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]classicMsg(nil), b.got...)
}

// --- the live test ----------------------------------------------------------------

func TestLiveRelayMixedE2E(t *testing.T) {
	relayURL := os.Getenv("LM_BRIDGE_LIVE_RELAY")
	if relayURL == "" {
		t.Skip("set LM_BRIDGE_LIVE_RELAY (e.g. http://127.0.0.1:8443) to run the live regtest E2E")
	}
	// Topology: by default BOTH accounts live on the same relay (alpha).
	// Note: same-relay delivery skips LN keysend, and with it the relayd
	// mirrorBlobs ACL grant — a same-relay recipient therefore cannot pull
	// attachment blobs (pre-existing relay behaviour, not a bridge bug). In
	// that mode the attachment is verified via the uploading bridge account
	// (content-addressed sha256 identity). Set LM_BRIDGE_LIVE_RELAY_B (+
	// LM_BRIDGE_LIVE_DOMAIN) for the full cross-relay path where the
	// recipient decrypts AND downloads everything itself.
	relayBURL := os.Getenv("LM_BRIDGE_LIVE_RELAY_B")
	crossRelay := relayBURL != ""
	if !crossRelay {
		relayBURL = relayURL
	}
	domain := os.Getenv("LM_BRIDGE_LIVE_DOMAIN")
	if domain == "" {
		if crossRelay {
			domain = "beta"
		} else {
			domain = "alpha" // own relay name → local delivery routing
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	// unique suffix → fresh accounts every run (avoids stale-state collisions)
	suffix := randHex4(t)
	nameA, nameB := "br1a"+suffix, "br1b"+suffix

	privA, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	privB, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pkA := crypto.PublicBytes(privA)
	pkB := crypto.PublicBytes(privB)
	pubA := hex.EncodeToString(pkA[:])
	pubB := hex.EncodeToString(pkB[:])
	if err := relayclient.CreateAccount(ctx, relayURL, nameA, pubA); err != nil {
		t.Fatalf("create sender account: %v", err)
	}
	if err := relayclient.CreateAccount(ctx, relayBURL, nameB, pubB); err != nil {
		t.Fatalf("create recipient account: %v", err)
	}
	t.Logf("live E2E: disposable regtest accounts %s (bridge@%s) and %s (LM recipient@%s)", nameA, relayURL, nameB, relayBURL)
	lmAddr := nameB + "@" + domain

	// 1. mock classic upstream
	collector := &collectorBackend{}
	mockSrv := smtp.NewServer(collector)
	mockSrv.Domain = "mock-classic"
	mockSrv.AllowInsecureAuth = true
	mockSrv.MaxMessageBytes = 20 << 20
	mln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go mockSrv.Serve(mln)
	defer mockSrv.Close()
	mockPort, _ := strconv.Atoi(strings.Split(mln.Addr().String(), ":")[1])

	// 2. the real bridge server (LM side = live relay, classic side = mock)
	clientA := relayclient.New(relayURL, nameA, privA)
	if err := clientA.Login(ctx); err != nil {
		t.Fatalf("bridge login on live relay: %v", err)
	}
	// Warm the federated profile path: a cold tor/onion circuit makes the
	// relay's profile-loop time out and answer a false 404 (known regtest
	// pitfall). Retry until the peer profile resolves before submitting mail.
	var prof *relayclient.Profile
	for attempt := 0; attempt < 8; attempt++ {
		p, found, err := clientA.LookupProfile(ctx, lmAddr)
		if err == nil && found {
			prof = p
			break
		}
		t.Logf("profile warmup %d: found=%v err=%v", attempt, found, err)
		time.Sleep(3 * time.Second)
	}
	if prof == nil {
		t.Fatalf("federated profile lookup for %s never succeeded", lmAddr)
	}
	if prof.Pubkey != pubB {
		t.Fatalf("federated profile pubkey mismatch: got %s want %s", prof.Pubkey, pubB)
	}
	bridgePass := randHex4(t) + randHex4(t)
	srv := NewServer(Options{
		Addr:     "127.0.0.1:0",
		AuthUser: "bridge",
		AuthPass: bridgePass,
		Relay:    clientA,
		Upstream: &SMTPUpstream{Host: "127.0.0.1", Port: mockPort, TLSMode: "none"},
		ReplyTo:  "bridge@example.test",
	})
	bln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(bln)
	defer srv.Close()

	// 3. submit one MIXED mail with a chunk-worthy attachment
	//    To: classic, Cc: LM — so the classic copy must lose the Cc entirely.
	att := make([]byte, 1200*1024) // 1.2 MiB → 2 chunks + manifest on the relay
	if _, err := rand.Read(att); err != nil {
		t.Fatal(err)
	}
	subject := "live mixed " + suffix
	body := "Hello from the lmbridge live E2E, run " + suffix
	raw := mimeMessage(subject, body, "tester@world.example",
		"classic@world.example", lmAddr, "payload.bin", att)

	c, err := smtp.Dial(bln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Auth(sasl.NewPlainClient("", "bridge", bridgePass)); err != nil {
		t.Fatalf("bridge auth: %v", err)
	}
	if err := c.Mail("tester@world.example", nil); err != nil {
		t.Fatal(err)
	}
	if err := c.Rcpt("classic@world.example", nil); err != nil {
		t.Fatal(err)
	}
	if err := c.Rcpt(lmAddr, nil); err != nil {
		t.Fatalf("LM rcpt: %v", err)
	}
	w, err := c.Data()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("DATA rejected by bridge: %v", err)
	}
	if err := c.Quit(); err != nil {
		t.Fatal(err)
	}

	// 4. classic side: copy without the LM address, with our Reply-To
	deadline := time.Now().Add(15 * time.Second)
	var msgs []classicMsg
	for time.Now().Before(deadline) {
		if msgs = collector.messages(); len(msgs) >= 1 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if len(msgs) != 1 {
		t.Fatalf("classic mock got %d messages, want 1", len(msgs))
	}
	cm := msgs[0]
	if cm.From != "tester@world.example" || len(cm.To) != 1 || cm.To[0] != "classic@world.example" {
		t.Fatalf("classic envelope wrong: %+v", cm)
	}
	if bytes.Contains(cm.Raw, []byte(lmAddr)) || bytes.Contains(cm.Raw, []byte(nameB)) {
		t.Fatal("classic copy must not contain the LM address")
	}
	hdr, err := readHeader(cm.Raw)
	if err != nil {
		t.Fatal(err)
	}
	if got := hdr.Get("To"); got != "<classic@world.example>" {
		t.Fatalf("classic To = %q", got)
	}
	if got := hdr.Get("Cc"); got != "" {
		t.Fatalf("classic Cc = %q, want removed (held only the LM address)", got)
	}
	if got := hdr.Get("Reply-To"); got != "bridge@example.test" {
		t.Fatalf("classic Reply-To = %q", got)
	}
	if !bytes.Contains(cm.Raw, []byte(body)) {
		t.Fatal("classic copy lost the body")
	}

	// 5. LM side: B decrypts subject/body/attachment identically from the
	//    peer relay (delivery rides LN keysend; blobs arrive via the mirror).
	clientB := relayclient.New(relayBURL, nameB, privB)
	var page *relayclient.InboxPage
	inboxDeadline := time.Now().Add(120 * time.Second)
	for {
		page, err = clientB.Inbox(ctx, 0, 10)
		if err != nil {
			t.Fatalf("inbox: %v", err)
		}
		if len(page.Messages) > 0 {
			break
		}
		if time.Now().After(inboxDeadline) {
			t.Fatal("LM recipient inbox stayed empty (keysend not settled?)")
		}
		// keysend settles within ~1s once the HTLC arrives
		time.Sleep(time.Second)
	}
	mail0, err := relayclient.DecodeMail(privB, page.Messages[0]) // inbox is newest-first
	if err != nil {
		t.Fatalf("decode mail: %v", err)
	}
	if mail0.Subject != subject {
		t.Fatalf("subject = %q, want %q", mail0.Subject, subject)
	}
	if mail0.Body != body {
		t.Fatalf("body = %q, want %q", mail0.Body, body)
	}
	if len(mail0.Attachments) != 1 {
		t.Fatalf("attachments = %+v, want exactly 1", mail0.Attachments)
	}
	a := mail0.Attachments[0]
	if a.Name != "payload.bin" || a.Size != int64(len(att)) || !a.Chunked || a.Chunks != 2 {
		t.Fatalf("attachment meta = %+v", a)
	}
	// The receiving relay mirrors manifest + chunks asynchronously over its
	// peer link (onion in regtest) — poll until the ACL and slices land.
	// Same-relay mode: no mirror runs, so verify blob integrity through the
	// uploader account (sha256 content identity is what the recipient's
	// manifest refs assert).
	fetcher := clientB
	if !crossRelay {
		fetcher = clientA
	}
	var got []byte
	mirrorDeadline := time.Now().Add(180 * time.Second)
	for {
		got, err = fetcher.FetchAttachment(ctx, a)
		if err == nil {
			break
		}
		if time.Now().After(mirrorDeadline) {
			t.Fatalf("fetch chunked attachment: %v", err)
		}
		time.Sleep(5 * time.Second)
	}
	if !bytes.Equal(got, att) {
		t.Fatal("attachment bytes differ after relay roundtrip")
	}
	ccHdr := mail0.Headers["Cc"]
	if ccHdr == "" {
		ccHdr = mail0.Headers["cc"] // pre-canonicalization letters
	}
	if !strings.Contains(ccHdr, lmAddr) {
		t.Fatalf("LM copy lost original addressing: %+v", mail0.Headers)
	}
	if mail0.SenderPub != pubA {
		t.Fatalf("sender pubkey = %s, want %s", mail0.SenderPub, pubA)
	}
	t.Logf("live E2E OK: mixed delivery verified end-to-end (msg %s, %d-byte chunked attachment)", mail0.MsgID, len(att))
}

func randHex4(t *testing.T) string {
	t.Helper()
	n, err := rand.Int(rand.Reader, big.NewInt(1<<31))
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%08x", n.Int64())
}
