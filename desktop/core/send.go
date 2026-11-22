package core

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightningmail/lm1/crypto"
	"github.com/lightningmail/lm1/envelope"
)

// ComposeOpts mirrors send.ts ComposeOpts: to, subject, body, attachments.
type ComposeOpts struct {
	To          string
	Subject     string
	Body        string
	Attachments []ComposeAttachment
	Signup      bool // first contact → welcome postage
	TipSats     int64
}

// ComposeAttachment is one file to attach (name + bytes).
type ComposeAttachment struct {
	Name  string
	Bytes []byte
}

// SendResult mirrors the send.ts composeAndSend return: msg_id, status, maybe receipt.
type SendResult struct {
	MsgID  string
	Status string
}

// ComposeAndSend builds + signs + posts one envelope — the full send.ts path.
// Steps: blob uploads (chunked or direct), profile lookup, ECIES encrypt with
// AAD = recipientHash||msgID, envelope encode + BIP340 sign, POST /v1/send.
func ComposeAndSend(ctx context.Context, c *Client, priv *btcec.PrivateKey, opts ComposeOpts) (*SendResult, error) {
	// 1. look up recipient pubkey (keep full name@domain for federated DNS/peer discovery)
	recip := strings.TrimSpace(opts.To)
	if recip == "" {
		return nil, fmt.Errorf("Empfänger fehlt")
	}
	prof, err := c.Profile(ctx, recip)
	if err != nil {
		return nil, fmt.Errorf("Profil nicht gefunden: %w", err)
	}
	recvPubBytes, err := hex.DecodeString(prof.Pubkey)
	if err != nil || len(recvPubBytes) != 33 {
		return nil, fmt.Errorf("ungültiger Empfänger-Pubkey")
	}
	recvPub, err := crypto.ParsePubKey(recvPubBytes)
	if err != nil {
		return nil, fmt.Errorf("Empfänger-Pubkey: %w", err)
	}

	// 2. upload attachments — chunked when >1 MiB, MANIFEST-ONLY refs
	blobRefs := make([][32]byte, 0)
	attList := make([]Attachment, 0, len(opts.Attachments))
	for _, a := range opts.Attachments {
		if NeedsChunking(len(a.Bytes)) {
			hashes := make([]string, 0)
			for _, chunk := range SplitChunks(a.Bytes) {
				sha, err := c.UploadBlob(ctx, chunk)
				if err != nil {
					return nil, fmt.Errorf("Anhang-Chunk %q: %w", a.Name, err)
				}
				hashes = append(hashes, sha)
			}
			man := Manifest{V: 1, Size: len(a.Bytes), Chunks: hashes}
			manRaw, err := ManifestBytes(man)
			if err != nil {
				return nil, fmt.Errorf("Manifest: %w", err)
			}
			msha, err := c.UploadBlob(ctx, manRaw)
			if err != nil {
				return nil, fmt.Errorf("Manifest-Upload %q: %w", a.Name, err)
			}
			var ref [32]byte
			mshaBytes, _ := hex.DecodeString(msha)
			copy(ref[:], mshaBytes)
			blobRefs = append(blobRefs, ref)
			attList = append(attList, Attachment{
				SHA256: msha, Name: a.Name, Size: int64(len(a.Bytes)),
				Chunked: true, Chunks: len(hashes),
			})
		} else {
			sha, err := c.UploadBlob(ctx, a.Bytes)
			if err != nil {
				return nil, fmt.Errorf("Anhang %q: %w", a.Name, err)
			}
			var ref [32]byte
			shaBytes, _ := hex.DecodeString(sha)
			copy(ref[:], shaBytes)
			blobRefs = append(blobRefs, ref)
			attList = append(attList, Attachment{
				SHA256: sha, Name: a.Name, Size: int64(len(a.Bytes)),
			})
		}
		if len(blobRefs) > MAX_REFS {
			return nil, fmt.Errorf("Zu viele Anhang-Scheiben (max %d)", MAX_REFS)
		}
	}

	// 3. ECIES encrypt payload (field names EXACTLY as send.ts:109-110)
	var msgID [32]byte
	rand.Read(msgID[:])
	rh := sha256.Sum256(recvPubBytes)
	aad := make([]byte, 64)
	copy(aad[:32], rh[:])
	copy(aad[32:], msgID[:])
	payloadJSON, err := json.Marshal(map[string]any{
		"subject":     opts.Subject,
		"body":        opts.Body,
		"headers":     map[string]string{},
		"attachments": attList,
	})
	if err != nil {
		return nil, fmt.Errorf("payload: %w", err)
	}
	eph, sealed, err := crypto.EncryptForRecipient(recvPub, payloadJSON, aad)
	if err != nil {
		return nil, fmt.Errorf("ECIES: %w", err)
	}

	// 4. build + sign envelope
	env := &envelope.Envelope{
		RecipientHash:     rh,
		MsgID:             msgID,
		BlobRefs:          blobRefs,
		SenderPubkey:      crypto.PublicBytes(priv),
		Timestamp:         time.Now().Unix(),
		PayloadCiphertext: sealed,
		EphemeralPubkey:   eph,
		Signup:            opts.Signup,
	}
	sig, err := crypto.SignEnvelope(env, priv)
	if err != nil {
		return nil, fmt.Errorf("Signatur: %w", err)
	}
	env.Signature = sig
	envBin, err := env.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("Envelope: %w", err)
	}

	// 5. POST /v1/send
	rspMsgID, status, err := c.SendRaw(ctx, opts.To, envBin)
	if err != nil {
		return nil, err
	}
	if rspMsgID == "" {
		rspMsgID = hex.EncodeToString(msgID[:])
	}
	return &SendResult{MsgID: rspMsgID, Status: status}, nil
}
