package relayclient

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightningmail/lm1/crypto"
	"github.com/lightningmail/lm1/envelope"
)

// --- mock relay -------------------------------------------------------------

type sentEnvelope struct {
	To  string
	Raw []byte
}

type mockRelay struct {
	t *testing.T

	mu        sync.Mutex
	authCalls int
	blobs     map[string][]byte
	sent      []sentEnvelope

	// recipient identity served by /v1/profile
	recvPriv *btcec.PrivateKey
	addr     string // e.g. "bob@relay-mock"

	failNextProfile401 bool // exercise the auto-relogin path
	profile500         bool // exercise the 5xx branch
	token              string
}

func newMockRelay(t *testing.T, addr string) *mockRelay {
	priv, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	m := &mockRelay{
		t:        t,
		blobs:    map[string][]byte{},
		recvPriv: priv,
		addr:     addr,
		token:    "mock-token",
	}
	return m
}

func (m *mockRelay) authed(r *http.Request) bool {
	m.mu.Lock()
	tok := m.token
	m.mu.Unlock()
	return r.Header.Get("Authorization") == bearerPrefix+tok
}

func (m *mockRelay) handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/v1/auth", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 64<<10))
		var req struct{ Address, Pubkey, Sig string }
		// decode with explicit field mapping (json tags differ from Go names)
		var rawReq map[string]string
		if err := json.Unmarshal(body, &rawReq); err != nil {
			http.Error(w, `{"error":"bad request"}`, 400)
			return
		}
		req.Address, req.Pubkey, req.Sig = rawReq["address"], rawReq["pubkey_hex"], rawReq["sig"]

		pubBytes, err := hex.DecodeString(req.Pubkey)
		sigBytes, err2 := hex.DecodeString(req.Sig)
		if err != nil || err2 != nil {
			http.Error(w, `{"error":"bad hex"}`, 400)
			return
		}
		pub, err := crypto.ParsePubKey(pubBytes)
		if err != nil {
			http.Error(w, `{"error":"bad pubkey"}`, 400)
			return
		}
		// verify exactly like relaysrv handleAuth
		digest := crypto.AuthDigest([]byte("bmail-auth-v1:" + req.Address))
		if err := crypto.Verify(pub, digest, sigBytes); err != nil {
			m.t.Errorf("mock relay: auth signature invalid: %v", err)
			http.Error(w, `{"error":"bad sig"}`, 401)
			return
		}
		m.mu.Lock()
		m.authCalls++
		m.token = "tok-" + string(rune('a'+m.authCalls)) // rotate: old token dies
		tok := m.token
		m.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]string{"token": tok, "address": req.Address})
	})

	mux.HandleFunc("/v1/profile/", func(w http.ResponseWriter, r *http.Request) {
		if !m.authed(r) {
			http.Error(w, `{"error":"unauthorized"}`, 401)
			return
		}
		m.mu.Lock()
		fail401 := m.failNextProfile401
		m.failNextProfile401 = false
		fail500 := m.profile500
		m.mu.Unlock()
		if fail401 {
			http.Error(w, `{"error":"unauthorized"}`, 401)
			return
		}
		if fail500 {
			http.Error(w, `{"error":"boom"}`, 500)
			return
		}
		addr := strings.TrimPrefix(r.URL.Path, "/v1/profile/")
		if addr != m.addr {
			http.Error(w, `{"error":"not found"}`, 404)
			return
		}
		recvPub := crypto.PublicBytes(m.recvPriv)
		json.NewEncoder(w).Encode(map[string]any{
			"address":      m.addr,
			"pubkey":       hex.EncodeToString(recvPub[:]),
			"foreign_sats": 10,
		})
	})

	mux.HandleFunc("/v1/blob", func(w http.ResponseWriter, r *http.Request) {
		if !m.authed(r) {
			http.Error(w, `{"error":"unauthorized"}`, 401)
			return
		}
		data, _ := io.ReadAll(io.LimitReader(r.Body, 32<<20))
		sum := sha256.Sum256(data)
		sha := hex.EncodeToString(sum[:])
		m.mu.Lock()
		m.blobs[sha] = data
		m.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]string{"sha256_hex": sha})
	})

	mux.HandleFunc("/v1/send", func(w http.ResponseWriter, r *http.Request) {
		if !m.authed(r) {
			http.Error(w, `{"error":"unauthorized"}`, 401)
			return
		}
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 4<<20))
		env, err := envelope.Decode(raw)
		if err != nil {
			http.Error(w, `{"error":"bad envelope"}`, 400)
			return
		}
		// relay-side signature check (relaysrv handleSend parity)
		if err := crypto.VerifyEnvelope(env, env.SenderPubkey[:], env.Signature); err != nil {
			m.t.Errorf("mock relay: envelope signature invalid: %v", err)
			http.Error(w, `{"error":"bad sig"}`, 400)
			return
		}
		m.mu.Lock()
		m.sent = append(m.sent, sentEnvelope{To: r.URL.Query().Get("to"), Raw: raw})
		m.mu.Unlock()
		w.WriteHeader(202)
		json.NewEncoder(w).Encode(map[string]any{"msg_id": hex.EncodeToString(env.MsgID[:]), "status": "delivered"})
	})

	return mux
}

func startMock(t *testing.T, m *mockRelay) (*httptest.Server, *Client, *btcec.PrivateKey) {
	srv := httptest.NewServer(m.handler())
	t.Cleanup(srv.Close)
	senderPriv, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	c := New(srv.URL, "bridgebot", senderPriv)
	return srv, c, senderPriv
}

// --- tests ------------------------------------------------------------------

func TestLoginSignsChallenge(t *testing.T) {
	m := newMockRelay(t, "bob@relay-mock")
	_, c, _ := startMock(t, m)
	if err := c.Login(context.Background()); err != nil {
		t.Fatalf("Login: %v", err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.authCalls != 1 {
		t.Fatalf("authCalls = %d, want 1", m.authCalls)
	}
}

func TestAutoReloginOn401(t *testing.T) {
	m := newMockRelay(t, "bob@relay-mock")
	_, c, _ := startMock(t, m)
	ctx := context.Background()
	if err := c.Login(ctx); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	m.failNextProfile401 = true // simulates a relay restart killing the token
	m.mu.Unlock()
	prof, found, err := c.LookupProfile(ctx, m.addr)
	if err != nil || !found {
		t.Fatalf("LookupProfile after token kill: found=%v err=%v", found, err)
	}
	if prof.Pubkey == "" {
		t.Fatal("empty pubkey")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.authCalls != 2 {
		t.Fatalf("authCalls = %d, want 2 (relogin)", m.authCalls)
	}
}

func TestLookupProfile404IsNotFound(t *testing.T) {
	m := newMockRelay(t, "bob@relay-mock")
	_, c, _ := startMock(t, m)
	prof, found, err := c.LookupProfile(context.Background(), "stranger@world.example")
	if err != nil {
		t.Fatalf("404 must not be an error: %v", err)
	}
	if found || prof != nil {
		t.Fatal("404 must report found=false")
	}
}

func TestLookupProfile500IsTemporaryError(t *testing.T) {
	m := newMockRelay(t, "bob@relay-mock")
	_, c, _ := startMock(t, m)
	m.mu.Lock()
	m.profile500 = true
	m.mu.Unlock()
	_, found, err := c.LookupProfile(context.Background(), m.addr)
	if err == nil || found {
		t.Fatalf("500 must be an error, got found=%v err=%v", found, err)
	}
	var re *RelayError
	if !errors.As(err, &re) || re.Status != 500 || !re.Temporary() {
		t.Fatalf("want temporary RelayError 500, got %v", err)
	}
}

func TestLookupProfileKeepsFullAddress(t *testing.T) {
	m := newMockRelay(t, "bob@relay-mock.example")
	_, c, _ := startMock(t, m)
	// the mock only answers 200 when the FULL addr (with domain) arrives
	if _, found, err := c.LookupProfile(context.Background(), m.addr); err != nil || !found {
		t.Fatalf("domain must not be truncated: found=%v err=%v", found, err)
	}
}

// randBytes returns pseudo-random data without byte-period shortcuts —
// periodic fills create identical chunks and the sha-dedup "steals" uploads.
func randBytes(t *testing.T, n int, seed int64) []byte {
	t.Helper()
	r := rand.New(rand.NewSource(seed))
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestUploadFileChunkedManifestOnly(t *testing.T) {
	m := newMockRelay(t, "bob@relay-mock")
	_, c, _ := startMock(t, m)
	ctx := context.Background()
	if err := c.Login(ctx); err != nil {
		t.Fatal(err)
	}
	data := randBytes(t, chunkSize*2+chunkSize/2, 42) // 2.5 MiB → 3 chunks
	ref, att, err := c.UploadFile(ctx, File{Name: "big.bin", Bytes: data})
	if err != nil {
		t.Fatalf("UploadFile: %v", err)
	}
	if !att.Chunked || att.Chunks != 3 || att.Size != int64(len(data)) {
		t.Fatalf("bad attachment meta: %+v", att)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.blobs) != 4 { // 3 chunks + 1 manifest, nothing else
		t.Fatalf("blob count = %d, want 4", len(m.blobs))
	}
	// MANIFEST-ONLY rule: the ref is the manifest sha, not any chunk sha
	manRaw, ok := m.blobs[hex.EncodeToString(ref[:])]
	if !ok {
		t.Fatal("ref does not point at the stored manifest blob")
	}
	if manRaw == nil || hex.EncodeToString(ref[:]) != att.SHA256 {
		t.Fatal("att.SHA256 must equal the manifest sha")
	}
	var man manifest
	if err := json.Unmarshal(manRaw, &man); err != nil {
		t.Fatalf("manifest json: %v", err)
	}
	if man.V != 1 || man.Size != len(data) || len(man.Chunks) != 3 {
		t.Fatalf("bad manifest: %+v", man)
	}
	// chunks reassemble to the original file
	var rebuilt []byte
	for _, sha := range man.Chunks {
		chunk, ok := m.blobs[sha]
		if !ok {
			t.Fatalf("chunk %s missing", sha)
		}
		rebuilt = append(rebuilt, chunk...)
	}
	if sha256.Sum256(rebuilt) != sha256.Sum256(data) {
		t.Fatal("reassembled chunks differ from source")
	}
}

func TestSendMessageEnvelopeRoundtrip(t *testing.T) {
	m := newMockRelay(t, "bob@relay-mock")
	_, c, senderPriv := startMock(t, m)
	ctx := context.Background()
	if err := c.Login(ctx); err != nil {
		t.Fatal(err)
	}
	prof, found, err := c.LookupProfile(ctx, m.addr)
	if err != nil || !found {
		t.Fatalf("profile: %v %v", found, err)
	}
	attBytes := randBytes(t, 4096, 7)
	res, err := c.SendMessage(ctx, m.addr, prof, &Message{
		Subject:     "hello bridge",
		Body:        "body text",
		Attachments: []File{{Name: "note.bin", Bytes: attBytes}},
	})
	if err != nil {
		t.Fatalf("SendMessage: %v", err)
	}
	if res.MsgID == "" {
		t.Fatal("no msg_id")
	}
	m.mu.Lock()
	if len(m.sent) != 1 {
		m.mu.Unlock()
		t.Fatalf("sent = %d, want 1", len(m.sent))
	}
	se := m.sent[0]
	blobs := m.blobs
	m.mu.Unlock()
	if se.To != m.addr {
		t.Fatalf("to = %q, want %q", se.To, m.addr)
	}

	// decode like the receiving client (desktop/core DecodeMail parity)
	env, err := envelope.Decode(se.Raw)
	if err != nil {
		t.Fatalf("envelope decode: %v", err)
	}
	if err := crypto.VerifyEnvelope(env, env.SenderPubkey[:], env.Signature); err != nil {
		t.Fatalf("envelope sig: %v", err)
	}
	if env.SenderPubkey != crypto.PublicBytes(senderPriv) {
		t.Fatal("sender pubkey mismatch")
	}
	if len(env.BlobRefs) != 1 { // manifest-only / single small blob: exactly 1 ref
		t.Fatalf("blob refs = %d, want 1", len(env.BlobRefs))
	}
	recvPubBytes := crypto.PublicBytes(m.recvPriv)
	if env.RecipientHash != sha256.Sum256(recvPubBytes[:]) {
		t.Fatal("recipient hash mismatch")
	}
	aad := make([]byte, 64)
	copy(aad[:32], env.RecipientHash[:])
	copy(aad[32:], env.MsgID[:])
	pt, err := crypto.DecryptForRecipient(m.recvPriv, env.EphemeralPubkey[:], env.PayloadCiphertext, aad)
	if err != nil {
		t.Fatalf("payload decrypt: %v", err)
	}
	var p struct {
		Subject     string            `json:"subject"`
		Body        string            `json:"body"`
		Headers     map[string]string `json:"headers"`
		Attachments []Attachment      `json:"attachments"`
	}
	if err := json.Unmarshal(pt, &p); err != nil {
		t.Fatalf("payload json: %v", err)
	}
	if p.Subject != "hello bridge" || p.Body != "body text" {
		t.Fatalf("payload mismatch: %+v", p)
	}
	if p.Headers == nil {
		t.Fatal("headers must be an object, never null (send.ts parity)")
	}
	if len(p.Attachments) != 1 {
		t.Fatalf("attachments = %+v", p.Attachments)
	}
	att := p.Attachments[0]
	if att.Name != "note.bin" || att.Size != int64(len(attBytes)) || att.Chunked {
		t.Fatalf("attachment meta mismatch: %+v", att)
	}
	if hex.EncodeToString(env.BlobRefs[0][:]) != att.SHA256 {
		t.Fatal("envelope ref must equal payload attachment sha")
	}
	if stored, ok := blobs[att.SHA256]; !ok || sha256.Sum256(stored) != sha256.Sum256(attBytes) {
		t.Fatal("uploaded blob differs from attachment bytes")
	}
}
