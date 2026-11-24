// Minimal RFC 5322 / MIME reading on stdlib only (net/mail, mime/multipart):
// subject, preferred text body (plain beats html), attachments, and the raw
// body offset so classic copies can be rebuilt without re-encoding anything.
package smtpserver

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/textproto"
	"path/filepath"
	"sort"
	"strings"

	"github.com/lightningmail/bridge/internal/relayclient"
)

// ParsedMail is one submitted message, split for LM encryption and for the
// rebuilt classic copy.
type ParsedMail struct {
	Header  textproto.MIMEHeader
	Subject string // RFC 2047 decoded
	From    string // decoded From header value ("" when absent)
	To      string // raw To header as sent
	Cc      string // raw Cc header as sent
	Body    string // text/plain preferred
	HTML    bool   // true when Body came from a text/html fallback part
	// shortcut: body parts are taken as UTF-8 regardless of charset= labels;
	// add golang.org/x/text conversion when non-UTF8 charsets show up.
	Attachments []relayclient.File
	bodyOff     int // byte offset of the body inside the raw message
}

// parseMail reads headers via textproto (keeps raw values for the rebuild)
// and walks the MIME tree for text parts and attachments.
func parseMail(raw []byte) (*ParsedMail, error) {
	bodyOff := findBodyOffset(raw)
	if bodyOff < 0 {
		return nil, fmt.Errorf("no header/body separator found")
	}
	hdr, err := textproto.NewReader(bufio.NewReader(bytes.NewReader(raw[:bodyOff]))).ReadMIMEHeader()
	if err != nil {
		return nil, err
	}
	p := &ParsedMail{Header: hdr, bodyOff: bodyOff}
	dec := new(mime.WordDecoder)
	p.Subject = decodeHeaderValue(dec, hdr.Get("Subject"))
	p.From = decodeHeaderValue(dec, hdr.Get("From"))
	p.To = hdr.Get("To")
	p.Cc = hdr.Get("Cc")

	ct := hdr.Get("Content-Type")
	if ct == "" {
		ct = "text/plain; charset=us-ascii"
	}
	var plain, html string
	var atts []relayclient.File
	body := bytes.NewReader(raw[bodyOff:])
	if err := walkPart(ct, hdr.Get("Content-Transfer-Encoding"), hdr, body, &plain, &html, &atts); err != nil {
		return nil, err
	}
	switch {
	case plain != "":
		p.Body = plain
	case html != "":
		p.Body, p.HTML = html, true
	}
	for i := range atts {
		if atts[i].Name == "" {
			atts[i].Name = fmt.Sprintf("attachment-%d", i+1)
		}
	}
	p.Attachments = atts
	return p, nil
}

// walkPart descends multipart trees; leaf parts become body text or an
// attachment (filename or Content-Disposition: attachment wins over inline).
func walkPart(contentType, cte string, hdr textproto.MIMEHeader, r io.Reader,
	plain, html *string, atts *[]relayclient.File) error {
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType == "" {
		mediaType, params = "text/plain", nil
	}
	if strings.HasPrefix(mediaType, "multipart/") {
		boundary := params["boundary"]
		if boundary == "" {
			return fmt.Errorf("multipart part without boundary")
		}
		mr := multipart.NewReader(r, boundary)
		for {
			part, err := mr.NextPart()
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return err
			}
			pct := part.Header.Get("Content-Type")
			if pct == "" {
				pct = "text/plain; charset=us-ascii" // RFC 2046 default
			}
			err = walkPart(pct, part.Header.Get("Content-Transfer-Encoding"),
				part.Header, part, plain, html, atts)
			part.Close()
			if err != nil {
				return err
			}
		}
	}
	data, err := readWithCTE(r, cte)
	if err != nil {
		return err
	}
	name := attachmentName(hdr, params)
	disp := ""
	if d, _, err := mime.ParseMediaType(hdr.Get("Content-Disposition")); err == nil {
		disp = strings.ToLower(d)
	}
	if name != "" || disp == "attachment" {
		*atts = append(*atts, relayclient.File{Name: name, Bytes: data})
		return nil
	}
	switch mediaType {
	case "text/plain":
		if *plain == "" {
			// top-level bodies conventionally end in CRLF; multipart parts
			// already arrive trimmed by the boundary reader
			*plain = strings.TrimRight(string(data), "\r\n")
		}
	case "text/html":
		if *html == "" {
			*html = strings.TrimRight(string(data), "\r\n")
		}
	}
	// other inline types (e.g. text/calendar) are ignored in B1
	return nil
}

// attachmentName prefers the Content-Disposition filename, falls back to the
// Content-Type name parameter. Base() stops path traversal via ../ filenames.
func attachmentName(hdr textproto.MIMEHeader, ctParams map[string]string) string {
	if _, dparams, err := mime.ParseMediaType(hdr.Get("Content-Disposition")); err == nil {
		if fn := dparams["filename"]; fn != "" {
			return filepath.Base(fn)
		}
	}
	if n := ctParams["name"]; n != "" {
		return filepath.Base(n)
	}
	return ""
}

// readWithCTE decodes base64 / quoted-printable bodies; 7bit/8bit/binary pass
// through unchanged.
func readWithCTE(r io.Reader, cte string) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(cte)) {
	case "base64":
		return io.ReadAll(base64.NewDecoder(base64.StdEncoding, r))
	case "quoted-printable":
		return io.ReadAll(quotedprintable.NewReader(r))
	default:
		return io.ReadAll(r)
	}
}

func decodeHeaderValue(dec *mime.WordDecoder, v string) string {
	if v == "" {
		return ""
	}
	if s, err := dec.DecodeHeader(v); err == nil {
		return s
	}
	return v // not RFC 2047 — keep verbatim
}

// findBodyOffset locates the first empty line separating headers from body.
// shortcut: CRLF is searched before bare LF; messages mixing both line
// endings in the header block are pathological and land on the CRLF index.
func findBodyOffset(raw []byte) int {
	if i := bytes.Index(raw, []byte("\r\n\r\n")); i >= 0 {
		return i + 4
	}
	if i := bytes.Index(raw, []byte("\n\n")); i >= 0 {
		return i + 2
	}
	return -1
}

// classicCopy rebuilds the raw message for classic recipients: LM-only
// addresses are stripped from To/Cc and Reply-To is set when configured.
// Header values keep their original (possibly RFC 2047 encoded) form; the
// body bytes pass through verbatim so no encoding can break.
func classicCopy(raw []byte, p *ParsedMail, lmAddrs map[string]bool, classicFallback []string, replyTo string) ([]byte, error) {
	hdr := make(textproto.MIMEHeader, len(p.Header))
	for k, v := range p.Header {
		hdr[k] = append([]string(nil), v...)
	}
	rewriteAddrList(hdr, "To", lmAddrs, classicFallback)
	rewriteAddrList(hdr, "Cc", lmAddrs, nil)
	hdr.Del("Bcc")
	if replyTo != "" && hdr.Get("Reply-To") == "" {
		hdr.Set("Reply-To", replyTo)
	}

	var b bytes.Buffer
	if err := writeHeader(&b, hdr); err != nil {
		return nil, err
	}
	b.WriteString("\r\n")
	b.Write(raw[p.bodyOff:])
	return b.Bytes(), nil
}

// writeHeader serializes headers in sorted-key order (deterministic output;
// field order carries no meaning in RFC 5322).
func writeHeader(w io.Writer, hdr textproto.MIMEHeader) error {
	keys := make([]string, 0, len(hdr))
	for k := range hdr {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range hdr[k] {
			if strings.ContainsAny(v, "\r\n") {
				return fmt.Errorf("header %q contains a newline", k)
			}
			if _, err := fmt.Fprintf(w, "%s: %s\r\n", k, v); err != nil {
				return err
			}
		}
	}
	return nil
}

// joinAngle renders bare envelope addresses as canonical RFC 5322 addr-specs.
func joinAngle(addrs []string) string {
	parts := make([]string, len(addrs))
	for i, a := range addrs {
		parts[i] = "<" + a + ">"
	}
	return strings.Join(parts, ", ")
}

// rewriteAddrList filters drop-set addresses out of one address-list header.
// When the list ends up empty, fallback addresses replace it (To) or the
// header is removed entirely (Cc). An unparseable list is dropped wholesale
// rather than risking an LM address leaking into the classic copy.
func rewriteAddrList(hdr textproto.MIMEHeader, key string, drop map[string]bool, fallback []string) {
	raw := hdr.Get(key)
	if raw == "" {
		if key == "To" && len(fallback) > 0 {
			hdr.Set(key, joinAngle(fallback))
		}
		return
	}
	addrs, err := mail.ParseAddressList(raw)
	if err != nil {
		hdr.Del(key)
		if key == "To" && len(fallback) > 0 {
			hdr.Set(key, joinAngle(fallback))
		}
		return
	}
	kept := make([]string, 0, len(addrs))
	for _, a := range addrs {
		if !drop[strings.ToLower(a.Address)] {
			kept = append(kept, a.String()) // re-encodes display names as needed
		}
	}
	hdr.Del(key)
	switch {
	case len(kept) > 0:
		hdr.Set(key, strings.Join(kept, ", "))
	case len(fallback) > 0:
		hdr.Set(key, joinAngle(fallback))
	}
}
