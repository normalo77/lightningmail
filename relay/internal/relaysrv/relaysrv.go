// Package relaysrv: HTTP relay API server (spec §7).
// Endpoints: /v1/auth, /v1/balance, /v1/send, /v1/inbox, /v1/profile/{addr},
// /v1/blob, /v1/blob/{sha256}.
// Etappe 4a: persistent auth tokens (SQLite), blob ACL, storage quota.
package relaysrv

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/lightningmail/relay/internal/config"
	"github.com/lightningmail/relay/internal/crypto"
	"github.com/lightningmail/relay/internal/envelope"
	"github.com/lightningmail/relay/internal/ledger"
	"github.com/lightningmail/relay/internal/lnclient"
	"github.com/lightningmail/relay/internal/postage"
)

type Server struct {
	cfg     *config.Config
	ledger  *ledger.Ledger
	ln      *lnclient.Client
	postage *postage.Service
}

func New(cfg *config.Config, l *ledger.Ledger, ln *lnclient.Client, p *postage.Service) *Server {
	return &Server{cfg: cfg, ledger: l, ln: ln, postage: p}
}

func (s *Server) ListenAndServe() error {
	// Clean expired tokens on startup
	s.ledger.CleanExpiredTokens()

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth", s.handleAuth)
	mux.HandleFunc("/v1/balance", s.auth(s.handleBalance))
	mux.HandleFunc("/v1/send", s.auth(s.handleSend))
	mux.HandleFunc("/v1/inbox", s.auth(s.handleInbox))
	mux.HandleFunc("/v1/profile/", s.handleProfile)
	mux.HandleFunc("/v1/blob", s.auth(s.handleBlobUpload))
	mux.HandleFunc("/v1/blob/", s.auth(s.handleBlobGet))
	mux.HandleFunc("/v1/relay/blob/", s.relayBlob)
	mux.HandleFunc("/v1/account", s.handleAccount)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"ok":true}`))
	})

	log.Printf("relaysrv: listening on %s", s.cfg.ListenAddr)
	return http.ListenAndServe(s.cfg.ListenAddr, mux)
}

// --- auth middleware (persistent tokens, Etappe 4a) ---

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if tok == "" {
			http.Error(w, `{"error":"unauthorized"}`, 401)
			return
		}
		account, err := s.ledger.LookupToken(tok)
		if err != nil {
			http.Error(w, `{"error":"internal"}`, 500)
			return
		}
		if account == "" {
			http.Error(w, `{"error":"unauthorized"}`, 401)
			return
		}
		r.Header.Set("X-Bmail-Account", account)
		next(w, r)
	}
}

// --- POST /v1/auth ---
func (s *Server) handleAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error":"method not allowed"}`, 405)
		return
	}
	var req struct {
		Address string `json:"address"`
		Pubkey  string `json:"pubkey_hex"`
		Sig     string `json:"sig"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"bad request"}`, 400)
		return
	}
	pubBytes, err := hex.DecodeString(req.Pubkey)
	if err != nil || len(pubBytes) != 33 {
		http.Error(w, `{"error":"invalid pubkey"}`, 400)
		return
	}
	pub, err := crypto.ParsePubKey(pubBytes)
	if err != nil {
		http.Error(w, `{"error":"invalid pubkey"}`, 400)
		return
	}
	sigBytes, err := hex.DecodeString(req.Sig)
	if err != nil || len(sigBytes) != 64 {
		http.Error(w, `{"error":"invalid signature"}`, 400)
		return
	}
	challenge := []byte("bmail-auth-v1:" + req.Address)
	digest := crypto.AuthDigest(challenge)
	if err := crypto.Verify(pub, digest, sigBytes); err != nil {
		http.Error(w, `{"error":"signature verification failed"}`, 401)
		return
	}
	acct, err := s.ledger.GetAccount(req.Address)
	if err != nil {
		http.Error(w, `{"error":"account not found"}`, 404)
		return
	}
	if hex.EncodeToString(acct.MailboxPubkey) != req.Pubkey {
		http.Error(w, `{"error":"pubkey mismatch"}`, 401)
		return
	}
	tok := make([]byte, 32)
	rand.Read(tok)
	tokenStr := hex.EncodeToString(tok)

	// Persist token to SQLite (survives restart)
	if err := s.ledger.StoreToken(tokenStr, req.Address); err != nil {
		http.Error(w, `{"error":"token store"}`, 500)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"token": tokenStr})
}

// --- GET /v1/balance ---
func (s *Server) handleBalance(w http.ResponseWriter, r *http.Request) {
	account := r.Header.Get("X-Bmail-Account")
	bal, err := s.ledger.Balance(account)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%v"}`, err), 500)
		return
	}
	json.NewEncoder(w).Encode(map[string]int64{"balance_msat": bal})
}

// --- POST /v1/send ---
func (s *Server) handleSend(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error":"method not allowed"}`, 405)
		return
	}
	account := r.Header.Get("X-Bmail-Account")
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, `{"error":"read body"}`, 400)
		return
	}
	env, err := envelope.Decode(raw)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%v"}`, err), 400)
		return
	}
	if err := crypto.VerifyEnvelope(env, env.SenderPubkey[:], env.Signature); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"bad envelope sig: %v"}`, err), 400)
		return
	}

	dup, err := s.ledger.MsgWasSent(hex.EncodeToString(env.MsgID[:]))
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"ledger: %v"}`, err), 500)
		return
	}
	if dup {
		http.Error(w, `{"error":"duplicate msg_id"}`, 409)
		return
	}

	postageAmt := s.postage.ForeignSats()
	postageMsat := postageAmt * 1000

	if err := s.ledger.ApplyDelta(account, -postageMsat, ledger.KindPostageOut, hex.EncodeToString(env.MsgID[:])); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"insufficient balance: %v"}`, err), 402)
		return
	}

	if len(s.cfg.Peers) == 0 {
		s.ledger.ApplyDelta(account, postageMsat, ledger.KindPostageOut, "refund:"+hex.EncodeToString(env.MsgID[:]))
		http.Error(w, `{"error":"no peers configured"}`, 500)
		return
	}
	peer := &s.cfg.Peers[0]

	envBin, _ := env.MarshalBinary()

	info, err := s.ln.GetInfo(r.Context())
	if err != nil {
		s.ledger.ApplyDelta(account, postageMsat, ledger.KindPostageOut, "refund:"+hex.EncodeToString(env.MsgID[:]))
		http.Error(w, fmt.Sprintf(`{"error":"lnd: %v"}`, err), 500)
		return
	}
	relayPubkeyBytes, err := hex.DecodeString(info.IdentityPubkey)
	if err != nil {
		s.ledger.ApplyDelta(account, postageMsat, ledger.KindPostageOut, "refund:"+hex.EncodeToString(env.MsgID[:]))
		http.Error(w, `{"error":"bad node pubkey"}`, 500)
		return
	}

	now := time.Now().Unix()
	ts := make([]byte, 8)
	ts[0] = byte(now >> 56)
	ts[1] = byte(now >> 48)
	ts[2] = byte(now >> 40)
	ts[3] = byte(now >> 32)
	ts[4] = byte(now >> 24)
	ts[5] = byte(now >> 16)
	ts[6] = byte(now >> 8)
	ts[7] = byte(now)

	customRecords := map[uint64][]byte{
		34349334: envBin,
		34349337: make([]byte, 64),
		34349339: relayPubkeyBytes,
		34349343: ts,
	}

	preimage, err := s.ln.SendKeysend(r.Context(), peer.NodePubkey, postageAmt, customRecords)
	if err != nil {
		s.ledger.ApplyDelta(account, postageMsat, ledger.KindPostageOut, "refund:"+hex.EncodeToString(env.MsgID[:]))
		http.Error(w, fmt.Sprintf(`{"error":"keysend: %v"}`, err), 502)
		return
	}

	resp := map[string]any{
		"msg_id": hex.EncodeToString(env.MsgID[:]),
		"receipt": map[string]any{
			"amount_sats":  postageAmt,
			"preimage_b64": base64.StdEncoding.EncodeToString([]byte(preimage)),
		},
	}
	w.WriteHeader(202)
	json.NewEncoder(w).Encode(resp)
	log.Printf("send: %s -> peer %s, %d sats, preimage=%s", account, peer.Name, postageAmt, preimage[:16])
}

// --- GET /v1/inbox ---
func (s *Server) handleInbox(w http.ResponseWriter, r *http.Request) {
	account := r.Header.Get("X-Bmail-Account")
	acct, err := s.ledger.GetAccount(account)
	if err != nil {
		http.Error(w, `{"error":"account not found"}`, 404)
		return
	}
	afterSeq := int64(0)
	if a := r.URL.Query().Get("after"); a != "" {
		fmt.Sscanf(a, "%d", &afterSeq)
	}
	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		fmt.Sscanf(l, "%d", &limit)
	}
	msgs, err := s.ledger.ListMessages(acct.ID, afterSeq, limit)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%v"}`, err), 500)
		return
	}
	type inboxMsg struct {
		Seq         int64  `json:"seq"`
		MsgID       string `json:"msg_id_b64"`
		ReceivedAt  int64  `json:"received_at"`
		EnvelopeB64 string `json:"envelope_b64"`
	}
	out := make([]inboxMsg, 0, len(msgs))
	for _, m := range msgs {
		out = append(out, inboxMsg{
			Seq:         m.Seq,
			MsgID:       base64.StdEncoding.EncodeToString(m.MsgID[:]),
			ReceivedAt:  m.CreatedAt,
			EnvelopeB64: base64.StdEncoding.EncodeToString(m.Envelope),
		})
	}
	nextSeq := int64(0)
	if len(msgs) > 0 {
		nextSeq = msgs[len(msgs)-1].Seq
	}
	json.NewEncoder(w).Encode(map[string]any{
		"messages": out,
		"next_seq": nextSeq,
	})
}

// --- POST /v1/account (bootstrap/registration) ---
func (s *Server) handleAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error":"method not allowed"}`, 405)
		return
	}
	var req struct {
		Name   string `json:"name"`
		Pubkey string `json:"pubkey"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"bad request"}`, 400)
		return
	}
	pubBytes, err := hex.DecodeString(req.Pubkey)
	if err != nil || len(pubBytes) != 33 {
		http.Error(w, `{"error":"invalid pubkey"}`, 400)
		return
	}
	acct, err := s.ledger.CreateAccount(req.Name, pubBytes)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%v"}`, err), 409)
		return
	}
	json.NewEncoder(w).Encode(map[string]any{
		"name":           acct.Name,
		"pubkey":         hex.EncodeToString(acct.MailboxPubkey),
		"recipient_hash": hex.EncodeToString(acct.RecipientHash[:]),
	})
}

// --- GET /v1/profile/{addr} ---
func (s *Server) handleProfile(w http.ResponseWriter, r *http.Request) {
	addr := strings.TrimPrefix(r.URL.Path, "/v1/profile/")
	if addr == "" {
		http.Error(w, `{"error":"address required"}`, 400)
		return
	}
	acct, err := s.ledger.GetAccount(addr)
	if err != nil {
		http.Error(w, `{"error":"not found"}`, 404)
		return
	}
	json.NewEncoder(w).Encode(map[string]any{
		"address":      acct.Name,
		"pubkey":       hex.EncodeToString(acct.MailboxPubkey),
		"foreign_sats": s.postage.ForeignSats(),
		"contact_sats": s.cfg.Postage.ContactSats,
	})
}

// --- POST /v1/blob (attachment upload, spec §6.3, Etappe 4a: quota + ACL) ---
func (s *Server) handleBlobUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error":"method not allowed"}`, 405)
		return
	}
	account := r.Header.Get("X-Bmail-Account")
	if r.ContentLength > s.cfg.Postage.BlobMaxBytes {
		http.Error(w, `{"error":"blob too large"}`, 413)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, s.cfg.Postage.BlobMaxBytes+1))
	if err != nil {
		http.Error(w, `{"error":"read body"}`, 500)
		return
	}
	if int64(len(raw)) > s.cfg.Postage.BlobMaxBytes {
		http.Error(w, `{"error":"blob too large"}`, 413)
		return
	}

	// Quota check
	if err := s.ledger.CheckQuota(account, int64(len(raw))); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"quota exceeded: %v"}`, err), 413)
		return
	}

	h := sha256.Sum256(raw)
	hexSha := hex.EncodeToString(h[:])
	dir := s.cfg.DataDir + "/blob/" + hexSha[:2]
	os.MkdirAll(dir, 0700)
	path := dir + "/" + hexSha

	// Only write file if new; always register blob ref
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := os.WriteFile(path, raw, 0600); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"write: %v"}`, err), 500)
			return
		}
	}

	// Register blob ref for ACL
	acct, err := s.ledger.GetAccount(account)
	if err != nil {
		http.Error(w, `{"error":"account lookup"}`, 500)
		return
	}
	if err := s.ledger.RegisterBlobRef(acct.ID, h, int64(len(raw))); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"blob ref: %v"}`, err), 500)
		return
	}

	json.NewEncoder(w).Encode(map[string]any{
		"sha256_hex":    hexSha,
		"bytes_written": len(raw),
	})
}

// --- GET /v1/blob/{sha256} (Etappe 4a: ACL check) ---
func (s *Server) handleBlobGet(w http.ResponseWriter, r *http.Request) {
	account := r.Header.Get("X-Bmail-Account")
	hexSha := strings.TrimPrefix(r.URL.Path, "/v1/blob/")
	if len(hexSha) != 64 {
		http.Error(w, `{"error":"invalid sha256 hex"}`, 400)
		return
	}

	// ACL: only accounts with a blob_ref can download
	acct, err := s.ledger.GetAccount(account)
	if err != nil {
		http.Error(w, `{"error":"account not found"}`, 404)
		return
	}
	shaBytes, err := hex.DecodeString(hexSha)
	if err != nil || len(shaBytes) != 32 {
		http.Error(w, `{"error":"invalid sha256"}`, 400)
		return
	}
	var sha32 [32]byte
	copy(sha32[:], shaBytes)

	ok, err := s.ledger.HasBlobAccess(acct.ID, sha32)
	if err != nil {
		http.Error(w, `{"error":"ledger"}`, 500)
		return
	}
	if !ok {
		http.Error(w, `{"error":"blob not accessible"}`, 403)
		return
	}

	dir := s.cfg.DataDir + "/blob/" + hexSha[:2]
	path := dir + "/" + hexSha
	data, err := os.ReadFile(path)
	if err != nil {
		http.Error(w, `{"error":"blob not found"}`, 404)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
	w.Write(data)
}

// GET /v1/relay/blob/{sha} — relay-zu-relay Blob-Spiegel (spec 6.4, M2a).
func (s *Server) relayBlob(w http.ResponseWriter, r *http.Request) {
	if s.cfg.RelaySecret == "" || r.Header.Get("X-Relay-Secret") != s.cfg.RelaySecret {
		http.Error(w, `{"error":"relay auth"}`, 401)
		return
	}
	hexSha := strings.TrimPrefix(r.URL.Path, "/v1/relay/blob/")
	if len(hexSha) != 64 {
		http.Error(w, `{"error":"bad sha"}`, 400)
		return
	}
	path := s.cfg.DataDir + "/blob/" + hexSha[:2] + "/" + hexSha
	f, err := os.Open(path)
	if err != nil {
		http.Error(w, `{"error":"not found"}`, 404)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	io.Copy(w, f)
}
