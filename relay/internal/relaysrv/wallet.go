// Wallet: Lightning-Aufladung/Auszahlung + LUD-16-Lightning-Adresse.
// POST /v1/topup + POST /v1/withdraw (auth), GET /.well-known/lnurlp/{name} (öffentlich).
// Gutschrift der Aufladung passiert NICHT hier, sondern im relayd-Ingest
// (setztled Invoice mit Memo "bmail-topup:ACCOUNT" → ledger.KindTopup).
package relaysrv

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/lightningmail/relay/internal/ledger"
)

// --- POST /v1/topup: Bolt11-Invoice fürs eigene Konto erzeugen ---
func (s *Server) handleTopup(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error":"method not allowed"}`, 405)
		return
	}
	account := r.Header.Get("X-Bmail-Account")
	var req struct {
		AmountSats int64 `json:"amount_sats"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.AmountSats < 1 || req.AmountSats > 10_000_000 {
		http.Error(w, `{"error":"amount_sats must be 1..10000000"}`, 400)
		return
	}
	if s.ln == nil {
		http.Error(w, `{"error":"lnd unavailable"}`, 503)
		return
	}
	payReq, rHash, err := s.ln.AddInvoice(r.Context(), req.AmountSats, "bmail-topup:"+account)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"lnd: %v"}`, err), 502)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"payment_request": payReq,
		"r_hash":          rHash,
		"amount_sats":     req.AmountSats,
	})
}

// --- POST /v1/withdraw: Bolt11-Invoice vom Guthaben bezahlen ---
// Reihenfolge wie beim Porto: erst abbuchen, dann zahlen; Zahlungsfehler refundet.
func (s *Server) handleWithdraw(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error":"method not allowed"}`, 405)
		return
	}
	account := r.Header.Get("X-Bmail-Account")
	var req struct {
		PaymentRequest string `json:"payment_request"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.PaymentRequest) == "" {
		http.Error(w, `{"error":"payment_request required"}`, 400)
		return
	}
	if s.ln == nil {
		http.Error(w, `{"error":"lnd unavailable"}`, 503)
		return
	}
	amtSats, payHash, err := s.ln.DecodePayReq(r.Context(), req.PaymentRequest)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"decode: %v"}`, err), 400)
		return
	}
	if amtSats <= 0 {
		http.Error(w, `{"error":"invalid invoice amount"}`, 400)
		return
	}
	if err := s.ledger.ApplyDeltaMeta(account, -amtSats*1000, ledger.KindWithdraw, "withdraw:"+payHash, "btc", s.ratePtr()); err != nil {
		if errors.Is(err, ledger.ErrInsufficient) {
			http.Error(w, `{"error":"insufficient balance"}`, 402)
			return
		}
		http.Error(w, fmt.Sprintf(`{"error":"ledger: %v"}`, err), 500)
		return
	}
	preimage, _, err := s.ln.PayInvoice(r.Context(), req.PaymentRequest)
	if err != nil {
		s.ledger.ApplyDeltaMeta(account, amtSats*1000, ledger.KindWithdraw, "refund:withdraw:"+payHash, "btc", s.ratePtr())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(502)
		json.NewEncoder(w).Encode(map[string]string{"error": "pay: " + err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"amount_sats":  amtSats,
		"preimage":     preimage,
		"payment_hash": payHash,
	})
}

// --- GET /.well-known/lnurlp/{name}: LUD-06/LUD-16 Lightning Address ---
// Ohne ?amount: Metadata-Doc; mit ?amount (msat): Bolt11-Invoice (Top-Up des Kontos).
func (s *Server) handleLNURLP(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/.well-known/lnurlp/")
	if name == "" || strings.Contains(name, "/") || name != strings.ToLower(name) {
		http.Error(w, `{"status":"ERROR","reason":"bad path"}`, 400)
		return
	}
	if _, err := s.ledger.GetAccount(name); err != nil {
		http.Error(w, `{"error":"unknown user"}`, 404)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	meta, _ := json.Marshal([][]string{
		{"text/plain", "Lightningmail top-up for " + name},
		{"text/identifier", name + "@" + s.oidcDomain()},
	})
	if amtStr := r.URL.Query().Get("amount"); amtStr != "" {
		amtMsat, err := strconv.ParseInt(amtStr, 10, 64)
		if err != nil || amtMsat < 1000 || amtMsat > 10_000_000_000 {
			http.Error(w, `{"status":"ERROR","reason":"amount must be 1000..10000000000 msat"}`, 400)
			return
		}
		if s.ln == nil {
			json.NewEncoder(w).Encode(map[string]any{"status": "ERROR", "reason": "LND unavailable"})
			return
		}
		payReq, _, err := s.ln.AddInvoice(r.Context(), amtMsat/1000, "bmail-topup:"+name)
		if err != nil {
			json.NewEncoder(w).Encode(map[string]any{"status": "ERROR", "reason": fmt.Sprintf("%v", err)})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"pr": payReq, "routes": []any{}})
		return
	}
	json.NewEncoder(w).Encode(map[string]any{
		"tag":         "payRequest",
		"callback":    s.oidcIssuer() + "/.well-known/lnurlp/" + name,
		"minSendable": 1000,
		"maxSendable": 10000000000,
		"metadata":    string(meta),
	})
}
