package imapserver

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	netmail "net/mail"
	"net/textproto"
	"strconv"
	"strings"
	"time"

	"github.com/lightningmail/bridge/internal/relayclient"
)

// AttachmentBlob is one payload attachment after the download attempt:
// exactly one of Data or Err is set.
type AttachmentBlob struct {
	Att  relayclient.Attachment
	Data []byte
	Err  string // why the blob is unavailable (403/missing on the relay)
}

// SentRecord is one LM letter the bridge delivered via SMTP.
type SentRecord struct {
	MsgID   string // hex, from the relay's /v1/send answer
	Ts      int64  // unix seconds
	To      string
	Subject string
	Body    string
}

// BuildRFC822 renders a decrypted LM letter as an RFC-5322 message. The LM
// envelope carries subject/body/attachments as JSON — no original MIME
// survives encryption — so this is the canonical form IMAP clients see:
// one text part (plaintext or HTML as sent), multipart/mixed when the letter
// has attachments.
func BuildRFC822(m *relayclient.Mail, account string, atts []AttachmentBlob) []byte {
	from := headerCI(m.Headers, "from")
	if from == "" {
		// Native LM senders have no mail address; the pubkey prefix is the
		// PWA display convention.
		from = shortPub(m.SenderPub) + "@lm.local"
	}
	to := headerCI(m.Headers, "to")
	if to == "" {
		to = account + "@lm.local"
	}
	date := time.Unix(m.ReceivedAt, 0)
	if hd := headerCI(m.Headers, "date"); hd != "" {
		if t, err := netmail.ParseDate(hd); err == nil {
			date = t // keep the sender's original Date when it parses
		}
	}
	var extra [][2]string
	if cc := headerCI(m.Headers, "cc"); cc != "" {
		extra = append(extra, [2]string{"Cc", cc})
	}
	if m.ReceivedSats > 0 {
		extra = append(extra, [2]string{"X-LM-Received-Sats", strconv.FormatInt(m.ReceivedSats, 10)})
	}
	return buildMessage(from, to, m.Subject, m.MsgID, date, m.Body, atts, extra)
}

// headerCI reads a payload header case-insensitively: canonical keys are
// "To"/"Cc"/"From" (PWA/desktop/bridge writers), but older letters carry
// lowercase ones.
func headerCI(h map[string]string, key string) string {
	if v, ok := h[key]; ok {
		return v
	}
	for k, v := range h {
		if strings.EqualFold(k, key) {
			return v
		}
	}
	return ""
}

// BuildSentRFC822 renders a locally sent letter for the Sent folder.
func BuildSentRFC822(rec SentRecord, account string) []byte {
	return buildMessage(account+"@lm.local", rec.To, rec.Subject, rec.MsgID,
		time.Unix(rec.Ts, 0), rec.Body, nil, nil)
}

func buildMessage(from, to, subject, msgID string, date time.Time, body string,
	atts []AttachmentBlob, extra [][2]string) []byte {
	var buf bytes.Buffer
	writeField(&buf, "From", from)
	writeField(&buf, "To", to)
	writeField(&buf, "Subject", subject)
	writeField(&buf, "Date", date.Format(time.RFC1123Z))
	writeField(&buf, "Message-ID", "<"+msgID+"@lmbridge>")
	for _, kv := range extra {
		writeField(&buf, kv[0], kv[1])
	}
	if len(atts) == 0 {
		writeTextPart(&buf, body)
		return buf.Bytes()
	}
	mw := multipart.NewWriter(&buf)
	writeField(&buf, "Content-Type", "multipart/mixed; boundary="+mw.Boundary())
	writeField(&buf, "MIME-Version", "1.0")
	buf.WriteString("\r\n")

	pw, err := mw.CreatePart(textproto.MIMEHeader{
		"Content-Type":              {bodyContentType(body) + "; charset=utf-8"},
		"Content-Transfer-Encoding": {"base64"},
	})
	if err == nil {
		writeBase64(pw, []byte(body))
	}
	for _, a := range atts {
		if a.Err != "" {
			// Honest placeholder: never pretend a refused/missing blob is the
			// file itself, and never stall the letter over it.
			pw, err := mw.CreatePart(textproto.MIMEHeader{
				"Content-Type": {"text/plain; charset=utf-8"},
			})
			if err == nil {
				fmt.Fprintf(pw, "LM attachment %q (%d bytes, sha256 %s) is not available from the relay: %s",
					a.Att.Name, a.Att.Size, a.Att.SHA256, a.Err)
			}
			continue
		}
		name := quotedParam(a.Att.Name)
		pw, err := mw.CreatePart(textproto.MIMEHeader{
			"Content-Type":              {"application/octet-stream; name=" + name},
			"Content-Disposition":       {"attachment; filename=" + name},
			"Content-Transfer-Encoding": {"base64"},
		})
		if err == nil {
			writeBase64(pw, a.Data)
		}
	}
	mw.Close()
	return buf.Bytes()
}

// writeField writes one header field. Values come from the (untrusted) letter
// payload, so CR/LF/NUL are replaced — they would allow header injection.
func writeField(buf *bytes.Buffer, key, val string) {
	val = strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == 0 {
			return ' '
		}
		return r
	}, val)
	if key == "Subject" && !isASCII(val) {
		val = mime.QEncoding.Encode("utf-8", val) // RFC 2047 for non-ASCII
	}
	buf.WriteString(key)
	buf.WriteString(": ")
	buf.WriteString(val)
	buf.WriteString("\r\n")
}

func writeTextPart(buf *bytes.Buffer, body string) {
	buf.WriteString("Content-Type: " + bodyContentType(body) + "; charset=utf-8\r\n")
	buf.WriteString("Content-Transfer-Encoding: base64\r\n")
	buf.WriteString("\r\n")
	writeBase64(buf, []byte(body))
}

// writeBase64 emits RFC 2045 base64 (lines capped at 76 chars, CRLF).
func writeBase64(w io.Writer, data []byte) {
	b := make([]byte, base64.StdEncoding.EncodedLen(len(data)))
	base64.StdEncoding.Encode(b, data)
	for len(b) > 0 {
		n := min(76, len(b))
		w.Write(b[:n])
		w.Write([]byte("\r\n"))
		b = b[n:]
	}
}

// bodyContentType detects obvious HTML so PWA/web letters render instead of
// showing markup. shortcut: prefix sniffing, no full parse — good enough for
// the two producers (plain textarea, web composer); upgrade if more arrive.
func bodyContentType(body string) string {
	t := strings.ToLower(strings.TrimSpace(body))
	if len(t) > 512 {
		t = t[:512]
	}
	for _, marker := range []string{"<!doctype html", "<html", "<div", "<p>", "<br"} {
		if strings.HasPrefix(t, marker) || strings.Contains(t, marker) {
			return "text/html"
		}
	}
	return "text/plain"
}

// quotedParam renders a filename/name parameter. shortcut: non-ASCII uses
// RFC 2047 inside quotes instead of full RFC 2231 — every mainstream client
// accepts it; upgrade if a picky MUA shows up.
func quotedParam(s string) string {
	if isASCII(s) && !strings.ContainsAny(s, `"\`) {
		return `"` + s + `"`
	}
	return `"` + mime.QEncoding.Encode("utf-8", s) + `"`
}

func shortPub(pubHex string) string {
	if len(pubHex) >= 12 {
		return pubHex[:12]
	}
	return pubHex
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 127 {
			return false
		}
	}
	return true
}
