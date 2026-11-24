package core

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightningmail/lm1/crypto"
	"github.com/lightningmail/lm1/envelope"
)

// ComposeOpts mirrors send.ts ComposeOpts: to, cc, subject, body, attachments.
// To and Cc accept comma/semicolon-separated lists; the send fans out one
// standard 1:1 LM1 envelope per unique recipient (no wire-protocol change).
type ComposeOpts struct {
	To          string
	Cc          string
	From        string // optional sender address, rides encrypted (Reply-All target)
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

// RecipientResult is one recipient's outcome inside a fan-out send.
type RecipientResult struct {
	To     string
	OK     bool
	Status string
	Err    string
}

// SendResult mirrors the send.ts composeAndSend return: msg_id, status, maybe receipt.
type SendResult struct {
	MsgID  string
	Status string
	// Results reports every recipient of a fan-out; on partial failure the
	// caller sees exactly who succeeded and who did not.
	Results []RecipientResult
}

// ComposeAndSend builds + signs + posts one envelope per recipient — the full
// send.ts path. Steps: blob uploads (chunked or direct, once for all), then
// per recipient: profile lookup, ECIES encrypt with AAD = recipientHash||msgID,
// envelope encode + BIP340 sign, POST /v1/send. The canonical To/Cc (and From)
// strings travel inside the encrypted payload headers only — relays never see
// the CC list. All envelopes of one letter share the same msg_id.
func ComposeAndSend(ctx context.Context, c *Client, priv *btcec.PrivateKey, opts ComposeOpts) (*SendResult, error) {
	// 1. resolve the recipient list (To first, then CC not already in To)
	toList := ParseRecipients(opts.To)
	if len(toList) == 0 {
		return nil, fmt.Errorf("Empfänger fehlt")
	}
	all := UniqueRecipients(opts.To, opts.Cc)
	headers := map[string]string{"To": strings.Join(toList, ", ")}
	if ccList := extraRecipients(all, toList); len(ccList) > 0 {
		headers["Cc"] = strings.Join(ccList, ", ")
	}
	if opts.From != "" {
		headers["From"] = opts.From
	}

	// 2. upload attachments — chunked when >1 MiB, MANIFEST-ONLY refs
	// (once for the whole fan-out: the relay dedupes blobs by sha256)
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

	// 3. payload JSON is identical for every recipient (field names EXACTLY
	// as send.ts) — only the ECIES seal differs per pubkey
	payloadJSON, err := json.Marshal(map[string]any{
		"subject":     opts.Subject,
		"body":        opts.Body,
		"headers":     headers,
		"attachments": attList,
	})
	if err != nil {
		return nil, fmt.Errorf("payload: %w", err)
	}

	// 4. fan out one 1:1 envelope per recipient — each with its OWN msg_id:
	// the relay enforces msg_id uniqueness (409 duplicate), exactly like the
	// bridge's per-recipient relayclient.SendMessage
	results := make([]RecipientResult, 0, len(all))
	var failures []string
	firstOK := -1
	firstMsgID := ""
	for _, addr := range all {
		rr := RecipientResult{To: addr}
		var rspMsgID string
		prof, perr := c.Profile(ctx, addr) // full address: federated DNS/peer discovery
		if perr != nil {
			perr = fmt.Errorf("Profil nicht gefunden: %w", perr)
		} else {
			rspMsgID, rr.Status, perr = encryptSignPost(ctx, c, priv, prof, addr, payloadJSON, blobRefs, opts.Signup)
		}
		if perr != nil {
			rr.Err = perr.Error()
			failures = append(failures, addr+": "+perr.Error())
			results = append(results, rr)
			continue
		}
		rr.OK = true
		if firstOK < 0 {
			firstOK = len(results)
			firstMsgID = rspMsgID
		}
		results = append(results, rr)
	}
	if firstOK < 0 {
		if len(failures) == 1 {
			return nil, errors.New(strings.TrimPrefix(failures[0], all[0]+": "))
		}
		return nil, errors.New(strings.Join(failures, " | "))
	}
	out := &SendResult{MsgID: firstMsgID, Status: results[firstOK].Status, Results: results}
	for _, r := range results {
		if r.OK && r.Status == "pending" {
			out.Status = "pending" // one spooled hop marks the whole letter pending
		}
	}
	return out, nil
}

// extraRecipients returns the CC tail of the merged fan-out list.
func extraRecipients(all, toList []string) []string {
	if len(all) > len(toList) {
		return all[len(toList):]
	}
	return nil
}

// encryptSignPost seals the shared payload for one recipient with a fresh
// msg_id, signs the envelope and posts it (steps 3-5 of the old
// single-recipient path). Returns the relay's msg_id (or the local one).
func encryptSignPost(ctx context.Context, c *Client, priv *btcec.PrivateKey, prof *ProfileResult, addr string,
	payloadJSON []byte, blobRefs [][32]byte, signup bool) (msgIDHex, status string, err error) {
	recvPubBytes, err := hex.DecodeString(prof.Pubkey)
	if err != nil || len(recvPubBytes) != 33 {
		return "", "", fmt.Errorf("ungültiger Empfänger-Pubkey")
	}
	recvPub, err := crypto.ParsePubKey(recvPubBytes)
	if err != nil {
		return "", "", fmt.Errorf("Empfänger-Pubkey: %w", err)
	}
	var msgID [32]byte
	rand.Read(msgID[:])
	rh := sha256.Sum256(recvPubBytes)
	aad := make([]byte, 64)
	copy(aad[:32], rh[:])
	copy(aad[32:], msgID[:])
	eph, sealed, err := crypto.EncryptForRecipient(recvPub, payloadJSON, aad)
	if err != nil {
		return "", "", fmt.Errorf("ECIES: %w", err)
	}
	env := &envelope.Envelope{
		RecipientHash:     rh,
		MsgID:             msgID,
		BlobRefs:          blobRefs,
		SenderPubkey:      crypto.PublicBytes(priv),
		Timestamp:         time.Now().Unix(),
		PayloadCiphertext: sealed,
		EphemeralPubkey:   eph,
		Signup:            signup,
	}
	sig, err := crypto.SignEnvelope(env, priv)
	if err != nil {
		return "", "", fmt.Errorf("Signatur: %w", err)
	}
	env.Signature = sig
	envBin, err := env.MarshalBinary()
	if err != nil {
		return "", "", fmt.Errorf("Envelope: %w", err)
	}
	rspMsgID, status, err := c.SendRaw(ctx, addr, envBin)
	if err != nil {
		return "", "", err
	}
	if rspMsgID == "" {
		rspMsgID = hex.EncodeToString(msgID[:])
	}
	return rspMsgID, status, nil
}
