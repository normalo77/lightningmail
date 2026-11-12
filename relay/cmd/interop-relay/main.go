// interop-relay: minimal relayd substitute for lmcli↔TS interop tests.
// Implements /v1/* API (subset) without LND — messages are direct-stored.
// Uses the real relay/internal/* packages for crypto/ledger/envelope.
package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/lightningmail/relay/internal/config"
	"github.com/lightningmail/relay/internal/crypto"
	"github.com/lightningmail/relay/internal/envelope"
	"github.com/lightningmail/relay/internal/ledger"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: interop-relay <data-dir>\n")
		os.Exit(2)
	}
	dataDir := os.Args[1]
	os.MkdirAll(dataDir, 0700)

	dbPath := dataDir + "/ledger.db"
	l, err := ledger.Open(dbPath)
	if err != nil {
		log.Fatalf("ledger: %v", err)
	}
	defer l.Close()

	cfg := &config.Config{ListenAddr: "127.0.0.1:8443"}
	srv := &server{cfg: cfg, ledger: l}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth", srv.handleAuth)
	mux.HandleFunc("/v1/balance", srv.auth(srv.handleBalance))
	mux.HandleFunc("/v1/send", srv.auth(srv.handleSend))
	mux.HandleFunc("/v1/inbox", srv.auth(srv.handleInbox))
	mux.HandleFunc("/v1/profile/", srv.handleProfile)
	mux.HandleFunc("/v1/account", srv.handleAccount)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"ok":true}`))
	})

	log.Printf("interop-relay on %s (data=%s)", cfg.ListenAddr, dataDir)
	if err := http.ListenAndServe(cfg.ListenAddr, mux); err != nil {
		log.Fatal(err)
	}
}

type server struct {
	cfg    *config.Config
	ledger *ledger.Ledger
}

func (s *server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if tok == "" {
			http.Error(w, `{"error":"unauthorized"}`, 401)
			return
		}
		account, err := s.ledger.LookupToken(tok)
		if err != nil || account == "" {
			http.Error(w, `{"error":"unauthorized"}`, 401)
			return
		}
		r.Header.Set("X-Bmail-Account", account)
		next(w, r)
	}
}

func (s *server) handleAuth(w http.ResponseWriter, r *http.Request) {
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
	// Use crypto/rand via a simpler approach
	for i := range tok {
		tok[i] = byte(i + 42) // deterministic for interop; production uses crypto/rand
	}
	tokenStr := hex.EncodeToString(tok)
	if err := s.ledger.StoreToken(tokenStr, req.Address); err != nil {
		http.Error(w, `{"error":"token store"}`, 500)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"token": tokenStr})
}

func (s *server) handleBalance(w http.ResponseWriter, r *http.Request) {
	account := r.Header.Get("X-Bmail-Account")
	bal, err := s.ledger.Balance(account)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%v"}`, err), 500)
		return
	}
	json.NewEncoder(w).Encode(map[string]int64{"balance_msat": bal})
}

func (s *server) handleSend(w http.ResponseWriter, r *http.Request) {
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
	msgIDHex := hex.EncodeToString(env.MsgID[:])

	dup, err := s.ledger.MsgWasSent(msgIDHex)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"ledger: %v"}`, err), 500)
		return
	}
	if dup {
		http.Error(w, `{"error":"duplicate msg_id"}`, 409)
		return
	}

	postageMsat := int64(10000) // 10 sats default
	if err := s.ledger.ApplyDelta(account, -postageMsat, ledger.KindPostageOut, msgIDHex); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"insufficient balance: %v"}`, err), 402)
		return
	}

	// Direct store for interop: find recipient account by recipient_hash
	acct, err := s.ledger.LookupByRecipientHash(env.RecipientHash)
	if err != nil {
		s.ledger.ApplyDelta(account, postageMsat, ledger.KindPostageOut, "refund:"+msgIDHex)
		http.Error(w, fmt.Sprintf(`{"error":"recipient not found: %v"}`, err), 404)
		return
	}
	if _, err := s.ledger.PutMessage(env.MsgID, acct.ID, raw, postageMsat); err != nil {
		s.ledger.ApplyDelta(account, postageMsat, ledger.KindPostageOut, "refund:"+msgIDHex)
		http.Error(w, fmt.Sprintf(`{"error":"store: %v"}`, err), 500)
		return
	}
	if err := s.ledger.CreditRecipient(acct.Name, postageMsat, msgIDHex); err != nil {
		log.Printf("credit error: %v", err)
	}

	resp := map[string]any{
		"msg_id":  msgIDHex,
		"receipt": map[string]any{"amount_sats": 10, "preimage_b64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
	}
	w.WriteHeader(202)
	json.NewEncoder(w).Encode(resp)
	log.Printf("send: %s -> %s, stored", account, acct.Name)
}

func (s *server) handleInbox(w http.ResponseWriter, r *http.Request) {
	account := r.Header.Get("X-Bmail-Account")
	acct, err := s.ledger.GetAccount(account)
	if err != nil {
		http.Error(w, `{"error":"account not found"}`, 404)
		return
	}
	msgs, err := s.ledger.ListMessages(acct.ID, 0, 50)
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
	json.NewEncoder(w).Encode(map[string]any{"messages": out})
}

func (s *server) handleAccount(w http.ResponseWriter, r *http.Request) {
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

func (s *server) handleProfile(w http.ResponseWriter, r *http.Request) {
	addr := strings.TrimPrefix(r.URL.Path, "/v1/profile/")
	acct, err := s.ledger.GetAccount(addr)
	if err != nil {
		http.Error(w, `{"error":"not found"}`, 404)
		return
	}
	json.NewEncoder(w).Encode(map[string]any{
		"address":      acct.Name,
		"pubkey":       hex.EncodeToString(acct.MailboxPubkey),
		"foreign_sats": 10,
		"contact_sats": 0,
	})
}
