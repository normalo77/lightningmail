package core

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/lightningmail/lm1/crypto"
	"github.com/lightningmail/lm1/envelope"
)

// A6: mail decode roundtrip against real lm1 output — build an envelope the
// way lmcli/send.ts do (AAD = recipient_hash||msg_id), verify its signature
// like the relay does, then decode via DecodeMail.
func TestMailDecodeRoundtrip(t *testing.T) {
	recvPriv, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	sendPriv, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	recvPub := crypto.PublicBytes(recvPriv)
	recipientHash := sha256.Sum256(recvPub[:])

	var msgID [32]byte
	rand.Read(msgID[:])

	att := Attachment{SHA256: hex.EncodeToString(make([]byte, 32)), Name: "bild.png", Size: 2097152, Chunked: true, Chunks: 2}
	payloadJSON, _ := json.Marshal(map[string]any{
		"subject":     "Grüße <b>",
		"body":        "Mahlzeit!\nZweite Zeile.",
		"headers":     map[string]string{},
		"attachments": []Attachment{att},
	})
	aad := make([]byte, 64)
	copy(aad[:32], recipientHash[:])
	copy(aad[32:], msgID[:])
	ephPub, sealed, err := crypto.EncryptForRecipient(recvPriv.PubKey(), payloadJSON, aad)
	if err != nil {
		t.Fatal(err)
	}

	env := &envelope.Envelope{
		RecipientHash:     recipientHash,
		MsgID:             msgID,
		BlobRefs:          [][32]byte{{1}},
		SenderPubkey:      crypto.PublicBytes(sendPriv),
		Timestamp:         time.Now().Unix(),
		PayloadCiphertext: sealed,
		EphemeralPubkey:   ephPub,
	}
	sig, err := crypto.SignEnvelope(env, sendPriv)
	if err != nil {
		t.Fatal(err)
	}
	env.Signature = sig
	envBin, err := env.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	// relay-side signature check must pass on our fixture
	if err := crypto.VerifyEnvelope(env, env.SenderPubkey[:], sig); err != nil {
		t.Fatalf("fixture envelope sig invalid: %v", err)
	}

	m, err := DecodeMail(recvPriv, InboxMessage{
		Seq: 7, MsgIDB64: base64.StdEncoding.EncodeToString(msgID[:]),
		ReceivedAt: 1760000123, ReceivedSats: 10,
		EnvelopeB64: base64.StdEncoding.EncodeToString(envBin),
	})
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if m.Seq != 7 || m.MsgID != hex.EncodeToString(msgID[:]) {
		t.Errorf("id/seq wrong: %+v", m)
	}
	if m.Subject != "Grüße <b>" || m.Body != "Mahlzeit!\nZweite Zeile." {
		t.Errorf("payload wrong: %+v", m)
	}
	if len(m.Attachments) != 1 || m.Attachments[0].Name != "bild.png" || !m.Attachments[0].Chunked || m.Attachments[0].Chunks != 2 {
		t.Errorf("attachments wrong: %+v", m.Attachments)
	}
	sendPubBytes := crypto.PublicBytes(sendPriv)
	if m.SenderPub != hex.EncodeToString(sendPubBytes[:]) || m.SenderShort != m.SenderPub[:12] {
		t.Errorf("sender wrong: %s", m.SenderPub)
	}
	if m.ReceivedAt != 1760000123 || m.ReceivedSats != 10 {
		t.Errorf("inbox meta wrong: %+v", m)
	}
	if len(m.BlobRefs) != 1 || m.BlobRefs[0] != hex.EncodeToString([]byte(append([]byte{1}, make([]byte, 31)...))) {
		t.Errorf("blob refs wrong: %v", m.BlobRefs)
	}

	// wrong key -> decrypt error, no panic
	other, _ := crypto.GenerateKeyPair()
	if _, err := DecodeMail(other, InboxMessage{EnvelopeB64: base64.StdEncoding.EncodeToString(envBin)}); err == nil {
		t.Error("decrypt with wrong key must fail")
	}
	// garbage envelope -> error
	if _, err := DecodeMail(recvPriv, InboxMessage{EnvelopeB64: base64.StdEncoding.EncodeToString([]byte("LM1\x01junk"))}); err == nil {
		t.Error("garbage envelope must fail")
	}
}

// BlobRefs fallback: payload without attachments list -> refs become
// "anhang-N" attachments (main.ts refresh convention).
func TestMailBlobRefsFallback(t *testing.T) {
	recvPriv, _ := crypto.GenerateKeyPair()
	recvPub := crypto.PublicBytes(recvPriv)
	rh := sha256.Sum256(recvPub[:])
	var msgID [32]byte
	rand.Read(msgID[:])
	payloadJSON, _ := json.Marshal(map[string]any{"subject": "s", "body": "b", "headers": map[string]string{}})
	aad := make([]byte, 64)
	copy(aad[:32], rh[:])
	copy(aad[32:], msgID[:])
	eph, sealed, _ := crypto.EncryptForRecipient(recvPriv.PubKey(), payloadJSON, aad)
	ref := sha256.Sum256([]byte("blob"))
	env := &envelope.Envelope{
		RecipientHash: rh, MsgID: msgID, BlobRefs: [][32]byte{ref},
		SenderPubkey: recvPub, Timestamp: 1, PayloadCiphertext: sealed, EphemeralPubkey: eph,
	}
	sig, _ := crypto.SignEnvelope(env, recvPriv)
	env.Signature = sig
	envBin, _ := env.MarshalBinary()
	m, err := DecodeMail(recvPriv, InboxMessage{EnvelopeB64: base64.StdEncoding.EncodeToString(envBin)})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Attachments) != 1 || m.Attachments[0].Name != "anhang-1" || m.Attachments[0].SHA256 != hex.EncodeToString(ref[:]) {
		t.Errorf("fallback attachments wrong: %+v", m.Attachments)
	}
}
