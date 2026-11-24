package core

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightningmail/lm1/crypto"
	"github.com/lightningmail/lm1/envelope"
)

// Attachment is one payload attachment entry (send.ts attList shape).
type Attachment struct {
	SHA256  string `json:"sha256"`
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	Chunked bool   `json:"chunked,omitempty"`
	Chunks  int    `json:"chunks,omitempty"`
}

// Mail is a decoded inbox row, ready for list + reader.
type Mail struct {
	Seq          int64
	MsgID        string // hex, StateDoc read/deleted key
	Subject      string
	Body         string // raw: plaintext or HTML as sent
	Headers      map[string]string
	Attachments  []Attachment
	BlobRefs     []string // hex, fallback when payload has no attachments list
	ReceivedAt   int64
	ReceivedSats int64
	SenderPub    string // hex 33B compressed
	SenderShort  string // first 12 hex chars (PWA list convention)
	Signup       bool
}

// payload is the JSON inside tag 0x08 (lmcli send / send.ts composeAndSend).
type payload struct {
	Subject     string            `json:"subject"`
	Body        string            `json:"body"`
	Headers     map[string]string `json:"headers"`
	Attachments []Attachment      `json:"attachments"`
}

// To returns the canonical To header (case-insensitive: bridge mail from
// before canonicalization carries lowercase keys).
func (m *Mail) From() string { return HeaderCI(m.Headers, "From") }
func (m *Mail) To() string { return HeaderCI(m.Headers, "To") }

// Cc returns the canonical Cc header, "" when the letter had no CC.
func (m *Mail) Cc() string { return HeaderCI(m.Headers, "Cc") }

// DecodeMail decodes one inbox row: envelope (lm1) + ECIES payload decrypt
// with AAD = recipient_hash || msg_id (lmcli cmdInbox / main.ts refresh —
// byte-identical convention).
func DecodeMail(priv *btcec.PrivateKey, m InboxMessage) (*Mail, error) {
	envRaw, err := base64.StdEncoding.DecodeString(m.EnvelopeB64)
	if err != nil {
		return nil, fmt.Errorf("envelope b64: %w", err)
	}
	env, err := envelope.Decode(envRaw)
	if err != nil {
		return nil, fmt.Errorf("envelope: %w", err)
	}
	aad := make([]byte, 64)
	copy(aad[:32], env.RecipientHash[:])
	copy(aad[32:], env.MsgID[:])
	pt, err := crypto.DecryptForRecipient(priv, env.EphemeralPubkey[:], env.PayloadCiphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("payload decrypt: %w", err)
	}
	var p payload
	if err := json.Unmarshal(pt, &p); err != nil {
		return nil, fmt.Errorf("payload json: %w", err)
	}
	mail := &Mail{
		Seq:          m.Seq,
		MsgID:        hex.EncodeToString(env.MsgID[:]),
		Subject:      p.Subject,
		Body:         p.Body,
		Headers:      p.Headers,
		Attachments:  p.Attachments,
		ReceivedAt:   m.ReceivedAt,
		ReceivedSats: m.ReceivedSats,
		SenderPub:    hex.EncodeToString(env.SenderPubkey[:]),
		SenderShort:  hex.EncodeToString(env.SenderPubkey[:])[:12],
		Signup:       env.Signup,
	}
	for _, r := range env.BlobRefs {
		mail.BlobRefs = append(mail.BlobRefs, hex.EncodeToString(r[:]))
	}
	// main.ts refresh(): payload atts win; else fall back to the envelope refs
	if len(mail.Attachments) == 0 {
		for i, r := range mail.BlobRefs {
			mail.Attachments = append(mail.Attachments, Attachment{
				SHA256: r, Name: fmt.Sprintf("anhang-%d", i+1),
			})
		}
	}
	return mail, nil
}
