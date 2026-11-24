package imapserver

import (
	"bytes"
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	netmail "net/mail"
	"strings"
	"testing"

	"github.com/lightningmail/bridge/internal/relayclient"
)

// decodePart base64-decodes one MIME part body.
func decodePart(t *testing.T, r io.Reader) []byte {
	t.Helper()
	raw, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	out, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(string(raw), "\r\n", ""))
	if err != nil {
		t.Fatalf("part is not valid base64: %v (%q)", err, raw)
	}
	return out
}

func TestBuildRFC822Plain(t *testing.T) {
	m := &relayclient.Mail{
		MsgID:      "abc123",
		Subject:    "Grüße from LM",
		Body:       "Hello äöü world",
		Headers:    map[string]string{"from": "alice@world.example", "to": "bob@lm"},
		ReceivedAt: 1700000000,
		SenderPub:  "02deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdead",
	}
	raw := BuildRFC822(m, "bob", nil)

	msg, err := netmail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("not a valid RFC-5322 message: %v\n%s", err, raw)
	}
	if got := msg.Header.Get("From"); got != "alice@world.example" {
		t.Fatalf("From = %q", got)
	}
	if got := msg.Header.Get("To"); got != "bob@lm" {
		t.Fatalf("To = %q", got)
	}
	// net/mail keeps the raw header; decode RFC 2047 like a client would
	subj, err := new(mime.WordDecoder).DecodeHeader(msg.Header.Get("Subject"))
	if err != nil || subj != "Grüße from LM" {
		t.Fatalf("Subject = %q (%v), want decoded umlauts", subj, err)
	}
	if got := msg.Header.Get("Message-ID"); got != "<abc123@lmbridge>" {
		t.Fatalf("Message-ID = %q", got)
	}
	date, err := netmail.ParseDate(msg.Header.Get("Date"))
	if err != nil || date.Unix() != 1700000000 {
		t.Fatalf("Date = %q (%v), want unix 1700000000", msg.Header.Get("Date"), err)
	}
	if ct := msg.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("Content-Type = %q", ct)
	}
	if got := string(decodePart(t, msg.Body)); got != "Hello äöü world" {
		t.Fatalf("body = %q", got)
	}
}

func TestBuildRFC822FallbackAddresses(t *testing.T) {
	m := &relayclient.Mail{MsgID: "id1", Subject: "s", Body: "b",
		Headers: map[string]string{}, ReceivedAt: 1, SenderPub: "02aabbccddeeff00112233"}
	raw := BuildRFC822(m, "carol", nil)
	msg, err := netmail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if got := msg.Header.Get("From"); got != "02aabbccddee@lm.local" {
		t.Fatalf("fallback From = %q (want pubkey-prefix convention)", got)
	}
	if got := msg.Header.Get("To"); got != "carol@lm.local" {
		t.Fatalf("fallback To = %q", got)
	}
}

func TestBuildRFC822Multipart(t *testing.T) {
	good := bytes.Repeat([]byte("ATT"), 100)
	m := &relayclient.Mail{MsgID: "m2", Subject: "with files", Body: "see attached",
		Headers: map[string]string{}, ReceivedAt: 1700000000, SenderPub: "02ff"}
	atts := []AttachmentBlob{
		{Att: relayclient.Attachment{Name: "payload.bin", Size: int64(len(good)), SHA256: "aa"}, Data: good},
		{Att: relayclient.Attachment{Name: "locked.bin", Size: 3, SHA256: "bb"}, Err: "relay blob get: 403 forbidden"},
	}
	raw := BuildRFC822(m, "bob", atts)

	msg, err := netmail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("not a valid message: %v", err)
	}
	ct := msg.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "multipart/mixed") {
		t.Fatalf("Content-Type = %q", ct)
	}
	_, params, err := mime.ParseMediaType(ct)
	if err != nil {
		t.Fatal(err)
	}
	mr := multipart.NewReader(msg.Body, params["boundary"])

	// part 1: the body
	p, err := mr.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	if got := string(decodePart(t, p)); got != "see attached" {
		t.Fatalf("body part = %q", got)
	}
	// part 2: the good attachment
	p, err = mr.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	if p.FileName() != "payload.bin" {
		t.Fatalf("attachment filename = %q", p.FileName())
	}
	if !bytes.Equal(decodePart(t, p), good) {
		t.Fatal("attachment bytes differ")
	}
	// part 3: honest placeholder for the refused blob
	p, err = mr.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	note, _ := io.ReadAll(p)
	if !strings.Contains(string(note), "locked.bin") || !strings.Contains(string(note), "not available") {
		t.Fatalf("placeholder part = %q", note)
	}
	if _, err := mr.NextPart(); err != io.EOF {
		t.Fatal("expected exactly 3 parts")
	}
}

func TestBuildRFC822HeaderInjection(t *testing.T) {
	m := &relayclient.Mail{MsgID: "m3", Subject: "ok\r\nBcc: evil@x", Body: "b",
		Headers: map[string]string{"from": "a@b\r\nX-Injected: 1"}, ReceivedAt: 1, SenderPub: "02aa"}
	raw := BuildRFC822(m, "bob", nil)
	if bytes.Contains(raw, []byte("\r\nBcc:")) || bytes.Contains(raw, []byte("\r\nX-Injected:")) {
		t.Fatalf("header injection survived sanitization:\n%s", raw)
	}
	if _, err := netmail.ReadMessage(bytes.NewReader(raw)); err != nil {
		t.Fatalf("sanitized message must stay parseable: %v", err)
	}
}

func TestBuildSentRFC822(t *testing.T) {
	rec := SentRecord{MsgID: "sent1", Ts: 1700000000, To: "dave@alpha", Subject: "hi", Body: "there"}
	raw := BuildSentRFC822(rec, "bob")
	msg, err := netmail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if got := msg.Header.Get("To"); got != "dave@alpha" {
		t.Fatalf("To = %q", got)
	}
	if got := msg.Header.Get("From"); got != "bob@lm.local" {
		t.Fatalf("From = %q", got)
	}
	if got := string(decodePart(t, msg.Body)); got != "there" {
		t.Fatalf("body = %q", got)
	}
}
