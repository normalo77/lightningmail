// Etappe 6b: delivery receipts ✓/✓✓ (CONCEPT §23).
// The stamp point is the recipient's inbox fetch (client fetch, not
// relay ingest — the LN settle alone is only the ✓ level). Mirror to the
// peers in batches via X-Relay-Secret (pattern from spec 6.4 blob mirror);
// mapping to the sender account via sha256(sender_pub) = recipientHash.
package relaysrv

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/lightningmail/lm1/envelope"
	"github.com/lightningmail/relay/internal/ledger"
)

// stampInboxFetch stamps all returned messages as received.
// shortcut: envelope decode per fetch even for already stamped mails —
// tag parsing is cheap; if inbox polling load grows, add a seen column.
func (s *Server) stampInboxFetch(accountID int64, msgs []ledger.Message) {
	if len(msgs) == 0 {
		return
	}
	ts := time.Now().Unix()
	items := make([]ledger.ReceiptStamp, 0, len(msgs))
	for _, m := range msgs {
		env, err := envelope.Decode(m.Envelope)
		if err != nil {
			continue
		}
		items = append(items, ledger.ReceiptStamp{MsgID: m.MsgID, SenderPub: env.SenderPubkey[:], Ts: ts})
	}
	if len(items) == 0 {
		return
	}
	fresh, err := s.ledger.StampReceipts(accountID, items)
	if err != nil {
		log.Printf("receipts: stamp: %v", err)
		return
	}
	if len(fresh) == 0 {
		return
	}
	outs := make([]ledger.ReceiptOut, 0, len(fresh))
	for _, f := range fresh {
		outs = append(outs, ledger.ReceiptOut{ReceiptStamp: f, AccountID: accountID})
	}
	go s.mirrorReceipts(outs) // async, does not block the inbox fetch
}

// mirrorReceipts distributes fresh stamps: locally (same relay = sender and
// recipient here) directly, else POST to all peers. Failures are retried by
// the 60s retry ticker (mirrored stays 0).
func (s *Server) mirrorReceipts(items []ledger.ReceiptOut) {
	if len(items) == 0 {
		return
	}
	for _, it := range items {
		if _, err := s.ledger.StoreIncomingReceipt(it.MsgID, it.SenderPub, it.Ts); err != nil {
			log.Printf("receipts: local store: %v", err)
		}
	}
	payload := make([]ledger.IncomingReceipt, 0, len(items))
	for _, it := range items {
		payload = append(payload, ledger.IncomingReceipt{
			MsgIDHex:     hex.EncodeToString(it.MsgID[:]),
			SenderPubHex: hex.EncodeToString(it.SenderPub),
			Ts:           it.Ts,
		})
	}
	body, err := json.Marshal(map[string]any{"receipts": payload})
	if err != nil {
		return
	}
	allOK := len(s.cfg.Peers) > 0
	for i := range s.cfg.Peers {
		p := s.cfg.Peers[i]
		if p.URL == "" {
			continue
		}
		req, _ := http.NewRequest("POST", p.URL+"/v1/relay/receipt", bytes.NewReader(body))
		req.Header.Set("X-Relay-Secret", p.Token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil || resp.StatusCode != 200 {
			if resp != nil {
				resp.Body.Close()
			}
			log.Printf("receipts: mirror zu %s fehlgeschlagen (Retry in 60s)", p.Name)
			allOK = false
			continue
		}
		resp.Body.Close()
	}
	if allOK {
		if err := s.ledger.MarkReceiptsMirrored(items); err != nil {
			log.Printf("receipts: mark mirrored: %v", err)
		}
	}
}

// POST /v1/relay/receipt — peer relay reports fetched messages (spec 6.4 pattern).
func (s *Server) relayReceipt(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error":"method not allowed"}`, 405)
		return
	}
	if s.cfg.RelaySecret == "" || r.Header.Get("X-Relay-Secret") != s.cfg.RelaySecret {
		http.Error(w, `{"error":"relay auth"}`, 401)
		return
	}
	var req struct {
		Receipts []ledger.IncomingReceipt `json:"receipts"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"bad request"}`, 400)
		return
	}
	stored := 0
	for _, rr := range req.Receipts {
		mid, err := hex.DecodeString(rr.MsgIDHex)
		if err != nil || len(mid) != 32 {
			continue
		}
		pub, err := hex.DecodeString(rr.SenderPubHex)
		if err != nil || len(pub) != 33 {
			continue
		}
		var m [32]byte
		copy(m[:], mid)
		ok, err := s.ledger.StoreIncomingReceipt(m, pub, rr.Ts)
		if err != nil {
			log.Printf("receipts: store: %v", err)
			continue
		}
		if ok {
			stored++
		}
	}
	json.NewEncoder(w).Encode(map[string]int{"stored": stored})
}

// GET /v1/receipts — ✓✓ list of the own account (for the sent folder).
func (s *Server) handleReceipts(w http.ResponseWriter, r *http.Request) {
	acct, err := s.ledger.GetAccount(r.Header.Get("X-Bmail-Account"))
	if err != nil {
		http.Error(w, `{"error":"account not found"}`, 404)
		return
	}
	list, err := s.ledger.ListIncomingReceipts(acct.ID, 1000)
	if err != nil {
		http.Error(w, `{"error":"internal"}`, 500)
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"receipts": list})
}
