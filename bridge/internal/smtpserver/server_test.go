package smtpserver

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/textproto"
	"strings"
	"sync"
	"testing"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"

	"github.com/lightningmail/bridge/internal/relayclient"
)

// --- fakes ------------------------------------------------------------------

type sentRecord struct {
	To   string
	Prof *relayclient.Profile
	M    *relayclient.Message
}

type fakeRelay struct {
	mu        sync.Mutex
	profiles  map[string]*relayclient.Profile // addr → profile; missing = 404
	sent      []sentRecord
	lookupErr error
	sendErr   error
}

func (f *fakeRelay) LookupProfile(ctx context.Context, addr string) (*relayclient.Profile, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.lookupErr != nil {
		return nil, false, f.lookupErr
	}
	p, ok := f.profiles[addr]
	return p, ok, nil
}

func (f *fakeRelay) SendMessage(ctx context.Context, to string, prof *relayclient.Profile, m *relayclient.Message) (*relayclient.SendResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sendErr != nil {
		return nil, f.sendErr
	}
	f.sent = append(f.sent, sentRecord{To: to, Prof: prof, M: m})
	return &relayclient.SendResult{MsgID: "id-" + to, Status: "delivered"}, nil
}

func (f *fakeRelay) sentCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.sent)
}

type fwdRecord struct {
	From string
	To   []string
	Raw  []byte
}

type fakeUpstream struct {
	mu  sync.Mutex
	got []fwdRecord
	err error
}

func (u *fakeUpstream) Forward(ctx context.Context, from string, to []string, raw []byte) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.err != nil {
		return u.err
	}
	u.got = append(u.got, fwdRecord{From: from, To: append([]string(nil), to...), Raw: append([]byte(nil), raw...)})
	return nil
}

func (u *fakeUpstream) calls() []fwdRecord {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]fwdRecord(nil), u.got...)
}

// --- helpers ----------------------------------------------------------------

func newSess(relay Relay, up Upstream, replyTo string) *session {
	b := &backend{opts: Options{
		AuthUser: "bridge", AuthPass: "pw12345", // throwaway test credentials
		Relay: relay, Upstream: up, ReplyTo: replyTo,
	}}
	s, err := b.NewSession(nil)
	if err != nil {
		panic(err)
	}
	return s.(*session)
}

func lmProfile(addr string) *relayclient.Profile {
	return &relayclient.Profile{Address: addr, Pubkey: strings.Repeat("ab", 33)[:66]}
}

// mimeMessage builds a small RFC 5322 message; with attachment when attName != "".
func mimeMessage(subject, body, from, to, cc, attName string, attBytes []byte) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "From: %s\r\n", from)
	if to != "" {
		fmt.Fprintf(&b, "To: %s\r\n", to)
	}
	if cc != "" {
		fmt.Fprintf(&b, "Cc: %s\r\n", cc)
	}
	fmt.Fprintf(&b, "Subject: %s\r\nDate: Tue, 25 Nov 2026 10:00:00 +0100\r\n", subject)
	if attName == "" {
		b.WriteString("Content-Type: text/plain; charset=utf-8\r\n\r\n")
		b.WriteString(body + "\r\n")
		return b.Bytes()
	}
	const boundary = "BRIDGEBOUND"
	fmt.Fprintf(&b, "Content-Type: multipart/mixed; boundary=%s\r\n\r\n", boundary)
	fmt.Fprintf(&b, "--%s\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s\r\n", boundary, body)
	// RFC 5321 line-length limit: base64 must be wrapped (real MTAs use 76 cols)
	b64 := base64.StdEncoding.EncodeToString(attBytes)
	var wrapped strings.Builder
	for i := 0; i < len(b64); i += 76 {
		wrapped.WriteString(b64[i:min(i+76, len(b64))])
		wrapped.WriteString("\r\n")
	}
	fmt.Fprintf(&b, "--%s\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=%q\r\nContent-Transfer-Encoding: base64\r\n\r\n%s",
		boundary, attName, wrapped.String())
	fmt.Fprintf(&b, "--%s--\r\n", boundary)
	return b.Bytes()
}

func headerOf(t *testing.T, raw []byte) textproto.MIMEHeader {
	t.Helper()
	msg, err := readHeader(raw)
	if err != nil {
		t.Fatalf("parse forwarded message: %v", err)
	}
	return msg
}

func readHeader(raw []byte) (textproto.MIMEHeader, error) {
	off := findBodyOffset(raw)
	if off < 0 {
		return nil, errors.New("no header/body separator")
	}
	return textproto.NewReader(bufio.NewReader(bytes.NewReader(raw[:off]))).ReadMIMEHeader()
}

func smtpCode(t *testing.T, err error) int {
	t.Helper()
	var se *smtp.SMTPError
	if !errors.As(err, &se) {
		t.Fatalf("want *smtp.SMTPError, got %T: %v", err, err)
	}
	return se.Code
}

// --- auth tests ---------------------------------------------------------------

func TestMailRequiresAuth(t *testing.T) {
	s := newSess(&fakeRelay{}, nil, "")
	if err := s.Mail("x@y.z", nil); !errors.Is(err, smtp.ErrAuthRequired) {
		t.Fatalf("MAIL without AUTH must be rejected, got %v", err)
	}
	if err := s.Rcpt("x@y.z", nil); !errors.Is(err, smtp.ErrAuthRequired) {
		t.Fatalf("RCPT without AUTH must be rejected, got %v", err)
	}
	if err := s.Data(bytes.NewReader(nil)); !errors.Is(err, smtp.ErrAuthRequired) {
		t.Fatalf("DATA without AUTH must be rejected, got %v", err)
	}
}

func TestAuthPlainAcceptReject(t *testing.T) {
	s := newSess(&fakeRelay{}, nil, "")
	mech, err := s.Auth("PLAIN")
	if err != nil {
		t.Fatal(err)
	}
	// PLAIN wire form: \0username\0password — the mechanism is single-shot
	if _, _, err := mech.Next([]byte("\x00bridge\x00wrong-pw")); err == nil {
		t.Fatal("wrong password must be rejected")
	}
	if s.authed {
		t.Fatal("failed auth must not mark the session authenticated")
	}
	mech, err = s.Auth("PLAIN") // client retries with a fresh mechanism
	if err != nil {
		t.Fatal(err)
	}
	if _, done, err := mech.Next([]byte("\x00bridge\x00pw12345")); err != nil || !done {
		t.Fatalf("correct credentials rejected: done=%v err=%v", done, err)
	}
	if !s.authed {
		t.Fatal("session must be authenticated now")
	}
}

func TestAuthLoginFlow(t *testing.T) {
	s := newSess(&fakeRelay{}, nil, "")
	mech, err := s.Auth("LOGIN")
	if err != nil {
		t.Fatal(err)
	}
	chal, done, err := mech.Next(nil)
	if err != nil || done || string(chal) != "Username:" {
		t.Fatalf("step1: chal=%q done=%v err=%v", chal, done, err)
	}
	chal, done, err = mech.Next([]byte("bridge"))
	if err != nil || done || string(chal) != "Password:" {
		t.Fatalf("step2: chal=%q done=%v err=%v", chal, done, err)
	}
	if _, done, err = mech.Next([]byte("bad-pass")); err == nil {
		t.Fatal("wrong password must fail")
	}
	// LOGIN initial-response form: username rides along with AUTH LOGIN <b64>
	s2 := newSess(&fakeRelay{}, nil, "")
	mech2, _ := s2.Auth("LOGIN")
	if _, _, err := mech2.Next([]byte("bridge")); err != nil {
		t.Fatal(err)
	}
	if _, done, err := mech2.Next([]byte("pw12345")); err != nil || !done || !s2.authed {
		t.Fatalf("login initial-response form failed: done=%v err=%v", done, err)
	}
}

func TestAuthUnknownMechanism(t *testing.T) {
	s := newSess(&fakeRelay{}, nil, "")
	if _, err := s.Auth("CRAM-MD5"); !errors.Is(err, smtp.ErrAuthUnknownMechanism) {
		t.Fatalf("want ErrAuthUnknownMechanism, got %v", err)
	}
}

// --- MIME parsing tests -------------------------------------------------------

func TestParseMailPlainWithAttachment(t *testing.T) {
	att := []byte("BINARY\x00\x01\x02DATA")
	raw := mimeMessage("=?UTF-8?B?RsO2cnRyw6RmZmxpZw==?=", "hello body", "Ann <ann@world.example>",
		"bob@lm.example", "", "report.bin", att)
	p, err := parseMail(raw)
	if err != nil {
		t.Fatal(err)
	}
	if p.Subject != "Förträfflig" { // RFC 2047 B-encoding must be decoded
		t.Fatalf("subject = %q", p.Subject)
	}
	if p.Body != "hello body" || p.HTML {
		t.Fatalf("body = %q html=%v", p.Body, p.HTML)
	}
	if p.From != "Ann <ann@world.example>" {
		t.Fatalf("from = %q", p.From)
	}
	if len(p.Attachments) != 1 || p.Attachments[0].Name != "report.bin" || !bytes.Equal(p.Attachments[0].Bytes, att) {
		t.Fatalf("attachments = %+v", p.Attachments)
	}
}

func TestParseMailHTMLFallbackAndPlainPreference(t *testing.T) {
	htmlOnly := "From: a@b.c\r\nSubject: s\r\nContent-Type: text/html\r\n\r\n<p>hi</p>\r\n"
	p, err := parseMail([]byte(htmlOnly))
	if err != nil {
		t.Fatal(err)
	}
	if !p.HTML || p.Body != "<p>hi</p>" {
		t.Fatalf("html fallback broken: %+v", p)
	}
	alt := "From: a@b.c\r\nSubject: s\r\nContent-Type: multipart/alternative; boundary=BB\r\n\r\n" +
		"--BB\r\nContent-Type: text/html\r\n\r\n<p>hi</p>\r\n" +
		"--BB\r\nContent-Type: text/plain\r\n\r\nhi plain\r\n" +
		"--BB--\r\n"
	p, err = parseMail([]byte(alt))
	if err != nil {
		t.Fatal(err)
	}
	if p.HTML || p.Body != "hi plain" {
		t.Fatalf("plain must win over html: %+v", p)
	}
}

func TestParseMailRejectsGarbage(t *testing.T) {
	if _, err := parseMail([]byte("no headers no separator")); err == nil {
		t.Fatal("garbage must be rejected")
	}
}

// --- routing tests --------------------------------------------------------------

func mixedFixture(t *testing.T) (*fakeRelay, *fakeUpstream, *session) {
	fr := &fakeRelay{profiles: map[string]*relayclient.Profile{
		"lm1@alpha":      lmProfile("lm1@alpha"),
		"lm2@alpha":      lmProfile("lm2@alpha"),
		"bob@lm.example": lmProfile("bob@lm.example"),
	}}
	up := &fakeUpstream{}
	s := newSess(fr, up, "bridge@example.test")
	s.authed = true
	return fr, up, s
}

func submit(t *testing.T, s *session, from string, rcpts []string, raw []byte) error {
	t.Helper()
	if err := s.Mail(from, nil); err != nil {
		t.Fatalf("MAIL: %v", err)
	}
	for _, r := range rcpts {
		if err := s.Rcpt(r, nil); err != nil {
			return fmt.Errorf("RCPT %s: %w", r, err)
		}
	}
	return s.Data(bytes.NewReader(raw))
}

func TestRoutePureLM(t *testing.T) {
	fr, up, s := mixedFixture(t)
	raw := mimeMessage("subj", "body", "sender@world.example", "bob@lm.example", "", "a.txt", []byte("12345"))
	if err := submit(t, s, "sender@world.example", []string{"bob@lm.example"}, raw); err != nil {
		t.Fatalf("Data: %v", err)
	}
	if fr.sentCount() != 1 {
		t.Fatalf("lm sends = %d, want 1", fr.sentCount())
	}
	if len(up.calls()) != 0 {
		t.Fatal("upstream must not be called for pure LM mail")
	}
	rec := fr.sent[0]
	if rec.To != "bob@lm.example" || rec.M.Subject != "subj" || rec.M.Body != "body" {
		t.Fatalf("bad send record: %+v", rec)
	}
	if len(rec.M.Attachments) != 1 || rec.M.Attachments[0].Name != "a.txt" {
		t.Fatalf("bad attachments: %+v", rec.M.Attachments)
	}
	if rec.M.Headers["from"] != "sender@world.example" && !strings.Contains(rec.M.Headers["from"], "sender@world.example") {
		t.Fatalf("original From must ride in headers: %+v", rec.M.Headers)
	}
}

func TestRoutePureClassicForwardsVerbatim(t *testing.T) {
	fr, up, s := mixedFixture(t)
	_ = fr
	raw := mimeMessage("subj", "body", "sender@world.example", "classic@world.example", "", "", nil)
	if err := submit(t, s, "sender@world.example", []string{"classic@world.example"}, raw); err != nil {
		t.Fatalf("Data: %v", err)
	}
	if fr.sentCount() != 0 {
		t.Fatal("no LM sends for pure classic mail")
	}
	calls := up.calls()
	if len(calls) != 1 {
		t.Fatalf("upstream calls = %d, want 1", len(calls))
	}
	if !bytes.Equal(calls[0].Raw, raw) {
		t.Fatal("pure classic mail must be forwarded verbatim")
	}
	if calls[0].From != "sender@world.example" || calls[0].To[0] != "classic@world.example" {
		t.Fatalf("bad envelope: %+v", calls[0])
	}
}

func TestRouteMixedSplitsAndStripsLMAddresses(t *testing.T) {
	fr, up, s := mixedFixture(t)
	// To: one LM + one classic; Cc: one LM + one classic → each copy gets its half
	raw := mimeMessage("mixed subj", "mixed body", "sender@world.example",
		"lm1@alpha, classic@world.example", "lm2@alpha, other@world.example", "", nil)
	err := submit(t, s, "sender@world.example",
		[]string{"lm1@alpha", "classic@world.example", "lm2@alpha", "other@world.example"}, raw)
	if err != nil {
		t.Fatalf("Data: %v", err)
	}
	if fr.sentCount() != 2 {
		t.Fatalf("lm sends = %d, want 2", fr.sentCount())
	}
	// LM copies keep the ORIGINAL addressing visible to the LM recipient
	for _, rec := range fr.sent {
		if !strings.Contains(rec.M.Headers["To"], "lm1@alpha") || !strings.Contains(rec.M.Headers["Cc"], "lm2@alpha") {
			t.Fatalf("LM copy lost original addressing: %+v", rec.M.Headers)
		}
	}
	calls := up.calls()
	if len(calls) != 1 {
		t.Fatalf("upstream calls = %d, want 1", len(calls))
	}
	fwd := calls[0]
	if len(fwd.To) != 2 || fwd.To[0] != "classic@world.example" || fwd.To[1] != "other@world.example" {
		t.Fatalf("classic envelope rcpts = %+v", fwd.To)
	}
	hdr := headerOf(t, fwd.Raw)
	if got := hdr.Get("To"); got != "<classic@world.example>" {
		t.Fatalf("classic To = %q, LM address must be stripped", got)
	}
	if got := hdr.Get("Cc"); got != "<other@world.example>" {
		t.Fatalf("classic Cc = %q, LM address must be stripped", got)
	}
	if got := hdr.Get("Reply-To"); got != "bridge@example.test" {
		t.Fatalf("Reply-To = %q, want bridge@example.test", got)
	}
	if strings.Contains(string(fwd.Raw), "lm1@alpha") || strings.Contains(string(fwd.Raw), "lm2@alpha") {
		t.Fatal("classic copy must not contain any LM address")
	}
	if !bytes.Contains(fwd.Raw, []byte("mixed body")) {
		t.Fatal("classic copy lost the body")
	}
}

func TestMixedKeepsExistingReplyTo(t *testing.T) {
	fr, up, s := mixedFixture(t)
	raw := []byte("From: sender@world.example\r\nTo: bob@lm.example\r\nReply-To: original@world.example\r\nSubject: s\r\n\r\nbody\r\n")
	_ = fr
	if err := submit(t, s, "sender@world.example", []string{"bob@lm.example", "classic@world.example"}, raw); err != nil {
		t.Fatalf("Data: %v", err)
	}
	hdr := headerOf(t, up.calls()[0].Raw)
	if got := hdr.Get("Reply-To"); got != "original@world.example" {
		t.Fatalf("existing Reply-To must be kept, got %q", got)
	}
}

func TestLookupErrorIsTemporaryAndNeverFallsBack(t *testing.T) {
	fr, up, s := mixedFixture(t)
	fr.lookupErr = &relayclient.RelayError{Op: "profile", Status: 503, Body: "boom"}
	raw := mimeMessage("s", "b", "sender@world.example", "bob@lm.example", "", "", nil)
	err := submit(t, s, "sender@world.example", []string{"bob@lm.example"}, raw)
	code := smtpCode(t, err)
	if code < 400 || code > 499 {
		t.Fatalf("lookup 5xx must produce a 4xx SMTP error, got %d", code)
	}
	// the critical safety property: NOTHING may leak to classic SMTP
	if len(up.calls()) != 0 {
		t.Fatal("lookup failure must never fall back to classic delivery")
	}
	if fr.sentCount() != 0 {
		t.Fatal("nothing may be sent when the lookup failed")
	}
}

func TestLookupNetworkErrorIsTemporary(t *testing.T) {
	fr, up, s := mixedFixture(t)
	fr.lookupErr = errors.New("dial tcp: connection refused")
	raw := mimeMessage("s", "b", "sender@world.example", "bob@lm.example", "", "", nil)
	err := submit(t, s, "sender@world.example", []string{"bob@lm.example"}, raw)
	if code := smtpCode(t, err); code != 451 {
		t.Fatalf("network error → 451, got %d", code)
	}
	if len(up.calls()) != 0 {
		t.Fatal("no classic fallback on network errors")
	}
}

func TestClassicRecipientWithoutUpstreamRejected(t *testing.T) {
	fr := &fakeRelay{profiles: map[string]*relayclient.Profile{}}
	s := newSess(fr, nil, "")
	s.authed = true
	if err := s.Mail("sender@world.example", nil); err != nil {
		t.Fatal(err)
	}
	err := s.Rcpt("classic@world.example", nil)
	if code := smtpCode(t, err); code != 550 {
		t.Fatalf("classic rcpt without upstream → 550, got %d", code)
	}
}

func TestRelaySendErrorMapping(t *testing.T) {
	// temporary relay state (5xx/402) → SMTP 4xx; permanent (4xx) → SMTP 5xx
	for _, tc := range []struct {
		sendErr  error
		wantCode int
	}{
		{&relayclient.RelayError{Op: "send", Status: 503}, 451},
		{&relayclient.RelayError{Op: "send", Status: 402}, 451},
		{errors.New("dial tcp: refused"), 451},
		{&relayclient.RelayError{Op: "send", Status: 400}, 550},
	} {
		fr, up, s := mixedFixture(t)
		fr.sendErr = tc.sendErr
		raw := mimeMessage("s", "b", "sender@world.example", "bob@lm.example", "", "", nil)
		err := submit(t, s, "sender@world.example", []string{"bob@lm.example"}, raw)
		if code := smtpCode(t, err); code != tc.wantCode {
			t.Fatalf("sendErr %v → code %d, want %d", tc.sendErr, code, tc.wantCode)
		}
		if len(up.calls()) != 0 {
			t.Fatal("LM send failure must not reroute to classic")
		}
	}
}

func TestUpstreamFailureIsTemporary(t *testing.T) {
	fr, up, s := mixedFixture(t)
	up.err = errors.New("upstream down")
	raw := mimeMessage("s", "b", "sender@world.example", "classic@world.example", "", "", nil)
	err := submit(t, s, "sender@world.example", []string{"classic@world.example"}, raw)
	if code := smtpCode(t, err); code != 451 {
		t.Fatalf("upstream failure → 451, got %d", code)
	}
	_ = fr
}

func TestMalformedMessageRejected(t *testing.T) {
	fr, up, s := mixedFixture(t)
	err := submit(t, s, "sender@world.example", []string{"bob@lm.example"}, []byte("garbage without separator"))
	if code := smtpCode(t, err); code != 550 {
		t.Fatalf("malformed → 550, got %d", code)
	}
	_ = fr
	_ = up
}

func TestDuplicateRcptDeliversOnce(t *testing.T) {
	fr, up, s := mixedFixture(t)
	raw := mimeMessage("s", "b", "sender@world.example", "bob@lm.example", "", "", nil)
	if err := submit(t, s, "sender@world.example", []string{"bob@lm.example", "BOB@lm.example"}, raw); err != nil {
		t.Fatal(err)
	}
	if fr.sentCount() != 1 {
		t.Fatalf("duplicate rcpt delivered %d times", fr.sentCount())
	}
	_ = up
}

func TestNewServerDefaults(t *testing.T) {
	srv := NewServer(Options{Addr: "127.0.0.1:0"})
	if srv.MaxMessageBytes != defaultMaxMessageBytes {
		t.Fatalf("MaxMessageBytes = %d", srv.MaxMessageBytes)
	}
	if !srv.AllowInsecureAuth {
		t.Fatal("without TLS config, plain auth must be allowed (localhost mode)")
	}
	if srv.Domain != defaultDomain {
		t.Fatalf("Domain = %q", srv.Domain)
	}
}

// --- full wire test through a real TCP server -----------------------------------

func TestServerOverWire(t *testing.T) {
	fr := &fakeRelay{profiles: map[string]*relayclient.Profile{"bob@lm.example": lmProfile("bob@lm.example")}}
	up := &fakeUpstream{}
	srv := NewServer(Options{
		Addr: "127.0.0.1:0", AuthUser: "bridge", AuthPass: "pw12345",
		Relay: fr, Upstream: up, ReplyTo: "bridge@example.test",
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	defer srv.Close()

	c, err := smtp.Dial(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// wrong password first: server must refuse
	if err := c.Auth(sasl.NewPlainClient("", "bridge", "nope-nope")); err == nil {
		t.Fatal("wrong password accepted over the wire")
	}
	if err := c.Auth(sasl.NewPlainClient("", "bridge", "pw12345")); err != nil {
		t.Fatalf("auth: %v", err)
	}
	if err := c.Mail("sender@world.example", nil); err != nil {
		t.Fatal(err)
	}
	if err := c.Rcpt("bob@lm.example", nil); err != nil {
		t.Fatal(err)
	}
	if err := c.Rcpt("classic@world.example", nil); err != nil {
		t.Fatal(err)
	}
	raw := mimeMessage("wire subj", "wire body", "sender@world.example",
		"bob@lm.example", "classic@world.example", "w.txt", []byte("wire-att"))
	w, err := c.Data()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("data close: %v", err)
	}
	if err := c.Quit(); err != nil {
		t.Fatal(err)
	}

	if fr.sentCount() != 1 {
		t.Fatalf("lm sends = %d, want 1", fr.sentCount())
	}
	calls := up.calls()
	if len(calls) != 1 {
		t.Fatalf("upstream calls = %d, want 1", len(calls))
	}
	hdr := headerOf(t, calls[0].Raw)
	if got := hdr.Get("To"); got != "<classic@world.example>" {
		t.Fatalf("wire classic To = %q", got)
	}
	if got := hdr.Get("Reply-To"); got != "bridge@example.test" {
		t.Fatalf("wire Reply-To = %q", got)
	}
}

// unauthenticated MAIL over the wire must be refused with 530/5xx-ish
func TestServerOverWireRejectsUnauthenticated(t *testing.T) {
	fr := &fakeRelay{profiles: map[string]*relayclient.Profile{}}
	srv := NewServer(Options{Addr: "127.0.0.1:0", AuthUser: "u", AuthPass: "p", Relay: fr})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	defer srv.Close()

	c, err := smtp.Dial(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Mail("x@y.z", nil); err == nil {
		t.Fatal("MAIL before AUTH must be rejected")
	}
}
