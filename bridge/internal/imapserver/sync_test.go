package imapserver

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/emersion/go-imap/v2"

	"github.com/lightningmail/bridge/internal/relayclient"
	"github.com/lightningmail/lm1/crypto"
	"github.com/lightningmail/lm1/envelope"
)

// sealLetter builds one wire-identical LM envelope (send.ts field schema,
// AAD = recipient_hash || msg_id) and returns its msg_id hex plus inbox row.
func sealLetter(t *testing.T, privSender, privRecv *btcec.PrivateKey, seq int64, subject, body string,
	atts []relayclient.Attachment, refs [][32]byte, receivedAt int64) (string, relayclient.InboxMessage) {
	t.Helper()
	payloadJSON, err := json.Marshal(map[string]any{
		"subject": subject, "body": body,
		"headers": map[string]string{}, "attachments": atts,
	})
	if err != nil {
		t.Fatal(err)
	}
	var msgID [32]byte
	if _, err := rand.Read(msgID[:]); err != nil {
		t.Fatal(err)
	}
	recvPub := crypto.PublicBytes(privRecv)
	rh := sha256.Sum256(recvPub[:])
	aad := make([]byte, 64)
	copy(aad[:32], rh[:])
	copy(aad[32:], msgID[:])
	eph, sealed, err := crypto.EncryptForRecipient(privRecv.PubKey(), payloadJSON, aad)
	if err != nil {
		t.Fatal(err)
	}
	env := &envelope.Envelope{
		RecipientHash:     rh,
		MsgID:             msgID,
		BlobRefs:          refs,
		SenderPubkey:      crypto.PublicBytes(privSender),
		Timestamp:         receivedAt,
		PayloadCiphertext: sealed,
		EphemeralPubkey:   eph,
	}
	sig, err := crypto.SignEnvelope(env, privSender)
	if err != nil {
		t.Fatal(err)
	}
	env.Signature = sig
	bin, err := env.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(msgID[:]), relayclient.InboxMessage{
		Seq:          seq,
		MsgIDB64:     base64.StdEncoding.EncodeToString(msgID[:]),
		ReceivedAt:   receivedAt,
		ReceivedSats: 21,
		EnvelopeB64:  base64.StdEncoding.EncodeToString(bin),
	}
}

// fakeRelay serves /v1/inbox, /v1/blob/{sha} and the CAS /v1/state slot.
type fakeRelay struct {
	mu      sync.Mutex
	rows    []relayclient.InboxMessage // served newest-first like the real relay
	blobs   map[string][]byte
	refused map[string]bool // sha → 403

	priv    *btcec.PrivateKey
	version int64
	blob64  string // sealed state
}

func (f *fakeRelay) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/inbox":
			f.mu.Lock()
			rows := append([]relayclient.InboxMessage(nil), f.rows...)
			f.mu.Unlock()
			// newest-first, like the real relay
			for i, j := 0, len(rows)-1; i < j; i, j = i+1, j-1 {
				rows[i], rows[j] = rows[j], rows[i]
			}
			json.NewEncoder(w).Encode(map[string]any{"messages": rows, "next_seq": 0})
		case strings.HasPrefix(r.URL.Path, "/v1/blob/"):
			sha := strings.TrimPrefix(r.URL.Path, "/v1/blob/")
			f.mu.Lock()
			data, ok := f.blobs[sha]
			refused := f.refused[sha]
			f.mu.Unlock()
			if refused {
				http.Error(w, `{"error":"blob not accessible"}`, 403)
				return
			}
			if !ok {
				http.Error(w, `{"error":"blob not found"}`, 404)
				return
			}
			w.Write(data)
		case r.URL.Path == "/v1/state":
			f.mu.Lock()
			defer f.mu.Unlock()
			if r.Method == "GET" {
				json.NewEncoder(w).Encode(map[string]any{"version": f.version, "state_b64": f.blob64})
				return
			}
			var req struct {
				ExpectVersion int64  `json:"expect_version"`
				StateB64      string `json:"state_b64"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, `{"error":"bad json"}`, 400)
				return
			}
			if req.ExpectVersion != f.version {
				w.WriteHeader(409)
				json.NewEncoder(w).Encode(map[string]any{"error": "version conflict", "version": f.version})
				return
			}
			f.blob64 = req.StateB64
			f.version++
			json.NewEncoder(w).Encode(map[string]any{"version": f.version})
		default:
			http.NotFound(w, r)
		}
	})
}

func (f *fakeRelay) seedState(t *testing.T, docJSON string) {
	t.Helper()
	b, err := json.Marshal(json.RawMessage(docJSON))
	if err != nil {
		t.Fatal(err)
	}
	eph, sealed, err := crypto.EncryptForRecipient(f.priv.PubKey(), b, []byte{})
	if err != nil {
		t.Fatal(err)
	}
	out := make([]byte, 33+len(sealed))
	copy(out, eph[:])
	copy(out[33:], sealed)
	f.mu.Lock()
	f.blob64 = base64.StdEncoding.EncodeToString(out)
	f.version = 1
	f.mu.Unlock()
}

func (f *fakeRelay) openState(t *testing.T) *relayclient.StateDoc {
	t.Helper()
	f.mu.Lock()
	blob64 := f.blob64
	f.mu.Unlock()
	blob, err := base64.StdEncoding.DecodeString(blob64)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := crypto.DecryptForRecipient(f.priv, blob[:33], blob[33:], []byte{})
	if err != nil {
		t.Fatal(err)
	}
	doc := &relayclient.StateDoc{}
	if err := json.Unmarshal(pt, doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestSyncOnceEndToEnd(t *testing.T) {
	ctx := context.Background()
	privRecv, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	privSender, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// letter 1: plain text, already read in the state doc
	msg1ID, row1 := sealLetter(t, privSender, privRecv, 1, "first", "body one", nil, nil, 1700000001)
	// letter 2: one downloadable blob + one the relay refuses (403)
	good := []byte("GOODBLOBBYTES")
	goodSHA := sha256.Sum256(good)
	goodSHAX := hex.EncodeToString(goodSHA[:])
	lockedSHA := strings.Repeat("ab", 32)
	var lockedRef [32]byte
	lb, _ := hex.DecodeString(lockedSHA)
	copy(lockedRef[:], lb)
	atts := []relayclient.Attachment{
		{SHA256: goodSHAX, Name: "good.bin", Size: int64(len(good))},
		{SHA256: lockedSHA, Name: "locked.bin", Size: 3},
	}
	goodRef := goodSHA
	msg2ID, row2 := sealLetter(t, privSender, privRecv, 2, "second", "body two",
		atts, [][32]byte{goodRef, lockedRef}, 1700000002)

	fake := &fakeRelay{
		priv:    privRecv,
		blobs:   map[string][]byte{goodSHAX: good},
		refused: map[string]bool{lockedSHA: true},
		rows:    []relayclient.InboxMessage{row1, row2},
	}
	// Seed a state doc with a read flag, a deleted flag and foreign data
	// (contacts) that the syncer must never touch.
	fake.seedState(t, fmt.Sprintf(
		`{"read":{%q:1},"spam":{},"deleted":{},"drafts":[],"sent":[],`+
			`"contacts":{"c1":{"id":"c1","ts":7,"name":"Alice","given":"","org":"","title":"","url":"",`+
			`"cell":"","phone":"","fax":"","email":"","addr":"","lnaddr":"","pubkey":"","pgp":"","note":"","btc":"","crypto":""}},"files":{}}`,
		msg1ID))
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	client := relayclient.New(srv.URL, "bob", privRecv)
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	syncer := NewSyncer(client, privRecv, store, "bob", time.Second)

	if err := syncer.SyncOnce(ctx); err != nil {
		t.Fatalf("SyncOnce: %v", err)
	}

	inbox, _ := store.Folder(FolderInbox)
	if len(inbox.msgs) != 2 {
		t.Fatalf("INBOX has %d messages, want 2", len(inbox.msgs))
	}
	// ascending seq order: letter 1 first
	if inbox.msgs[0].MsgID != msg1ID || inbox.msgs[1].MsgID != msg2ID {
		t.Fatalf("wrong order/ids: %s %s", inbox.msgs[0].MsgID, inbox.msgs[1].MsgID)
	}
	if !inbox.msgs[0].has(imap.FlagSeen) {
		t.Fatal("letter 1 must be \\Seen (state doc read flag)")
	}
	if inbox.msgs[1].has(imap.FlagSeen) {
		t.Fatal("letter 2 must stay unseen")
	}
	if v, _ := store.MetaInt(metaLastInboxSeq); v != 2 {
		t.Fatalf("last_inbox_seq = %d, want 2", v)
	}
	// The 403 blob degraded to a placeholder, the good blob arrived.
	raw2, err := store.Raw(inbox.msgs[1].UID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw2), "locked.bin") || !strings.Contains(string(raw2), "not available") {
		t.Fatal("missing placeholder part for the refused blob")
	}
	if !strings.Contains(string(raw2), base64.StdEncoding.EncodeToString(good)) {
		t.Fatal("good attachment not embedded (base64)")
	}
	if !strings.Contains(string(raw2), "X-LM-Received-Sats: 21") {
		t.Fatal("received sats header missing")
	}
	// Re-running the same sync must not duplicate anything.
	if err := syncer.SyncOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if inbox2, _ := store.Folder(FolderInbox); len(inbox2.msgs) != 2 {
		t.Fatal("re-sync duplicated messages")
	}

	// IMAP-side flag change + a bridge SMTP send must land in /v1/state.
	if err := store.MarkPendingFlag(msg2ID, true, false); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkPendingFlag(msg1ID, false, true); err != nil {
		t.Fatal(err)
	}
	if err := store.QueueSent(SentRecord{MsgID: "sent1", Ts: 1700000009,
		To: "dave@alpha", Subject: "reply", Body: "re body"}); err != nil {
		t.Fatal(err)
	}
	if err := syncer.SyncOnce(ctx); err != nil {
		t.Fatal(err)
	}
	doc := fake.openState(t)
	if doc.Read()[msg2ID] != 1 || doc.Read()[msg1ID] != 1 {
		t.Fatalf("read flags not pushed: %v", doc.Read())
	}
	if doc.Deleted()[msg1ID] != 1 {
		t.Fatalf("deleted flag not pushed: %v", doc.Deleted())
	}
	sent := doc.Sent()
	if len(sent) != 1 || sent[0].MsgID != "sent1" || sent[0].To != "dave@alpha" || sent[0].Subject != "reply" {
		t.Fatalf("sent entry not pushed: %+v", sent)
	}
	if raw, ok := doc.Raw("contacts"); !ok || !strings.Contains(string(raw), "Alice") {
		t.Fatalf("foreign contacts field was clobbered: %s", raw)
	}
	// The Sent folder materialized locally.
	sentFolder, _ := store.Folder(FolderSent)
	if len(sentFolder.msgs) != 1 || sentFolder.msgs[0].MsgID != "sent1" {
		t.Fatalf("Sent folder = %+v", sentFolder.msgs)
	}
	rawSent, _ := store.Raw(sentFolder.msgs[0].UID)
	if !strings.Contains(string(rawSent), "To: dave@alpha") {
		t.Fatalf("Sent raw wrong:\n%s", rawSent)
	}
	// Pending queues drained.
	if pf, _ := store.PeekPendingFlags(); len(pf) != 0 {
		t.Fatalf("pending flags not cleared: %+v", pf)
	}
	if ps, _ := store.PeekPendingSent(); len(ps) != 0 {
		t.Fatalf("pending sent not cleared: %+v", ps)
	}

	// A remote deletion hides the letter on the next sync without expunge
	// violence: it gets the \Deleted flag only.
	fake.seedState(t, fmt.Sprintf(`{"read":{},"spam":{},"deleted":{%q:1},"drafts":[],"sent":[],"contacts":{},"files":{}}`, msg2ID))
	store.SetMetaInt(metaLastInboxSeq, 0) // force a re-pull pass over known letters
	if err := syncer.SyncOnce(ctx); err != nil {
		t.Fatal(err)
	}
	inbox3, _ := store.Folder(FolderInbox)
	if !inbox3.msgs[1].has(imap.FlagDeleted) {
		t.Fatalf("remote deletion not mirrored: %v", inbox3.msgs[1].flagList())
	}
}
