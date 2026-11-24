// Etappe J1 — Drive: personal persistent storage. Uploads go through
// POST /v1/blob?kind=drive (handleBlobUpload, relaysrv.go); here live
// release (DELETE /v1/blob), usage and tier purchase. Money flow like byteporto:
// charge first, then deliver; refund infrastructure errors (kind='fee').
package relaysrv

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/lightningmail/relay/internal/ledger"
)

// handleDriveRelease — DELETE /v1/blob {"sha":"<hex64>"}: deletes the own
// drive ref. The file only falls when no refs at all remain for the sha
// (other accounts hold their own rows → remaining>0).
func (s *Server) handleDriveRelease(w http.ResponseWriter, r *http.Request) {
	account := r.Header.Get("X-Bmail-Account")
	var req struct {
		Sha string `json:"sha"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"bad request"}`, 400)
		return
	}
	shaBytes, err := hex.DecodeString(req.Sha)
	if err != nil || len(shaBytes) != 32 {
		http.Error(w, `{"error":"invalid sha256 hex"}`, 400)
		return
	}
	var sha [32]byte
	copy(sha[:], shaBytes)
	acct, err := s.ledger.GetAccount(account)
	if err != nil {
		http.Error(w, `{"error":"account not found"}`, 404)
		return
	}
	own, err := s.ledger.HasDriveRef(acct.ID, sha)
	if err != nil {
		http.Error(w, `{"error":"internal"}`, 500)
		return
	}
	if !own {
		http.Error(w, `{"error":"no drive ref for this sha"}`, 403)
		return
	}
	remaining, err := s.ledger.RemoveDriveRef(acct.ID, sha)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"release: %v"}`, err), 500)
		return
	}
	if remaining == 0 {
		hexSha := hex.EncodeToString(sha[:])
		path := s.cfg.DataDir + "/blob/" + hexSha[:2] + "/" + hexSha
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			log.Printf("drive release: remove %s: %v", hexSha[:12], err)
		}
	}
	json.NewEncoder(w).Encode(map[string]any{"released": true, "remaining_refs": remaining})
}

// handleDriveUsage — GET /v1/drive/usage: quota, usage and tier offer.
func (s *Server) handleDriveUsage(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, `{"error":"method not allowed"}`, 405)
		return
	}
	account := r.Header.Get("X-Bmail-Account")
	acct, err := s.ledger.GetAccount(account)
	if err != nil {
		http.Error(w, `{"error":"account not found"}`, 404)
		return
	}
	used, err := s.ledger.BlobUsage(acct.ID)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"usage: %v"}`, err), 500)
		return
	}
	tiers := make([]map[string]int64, 0, len(s.cfg.Drive.Tiers))
	for _, t := range s.cfg.Drive.Tiers {
		tiers = append(tiers, map[string]int64{"gb": t.GB, "sats": t.Sats})
	}
	json.NewEncoder(w).Encode(map[string]any{
		"enabled":     s.cfg.Drive.Enabled,
		"used_bytes":  used,
		"quota_bytes": acct.QuotaBytes,
		"tiers":       tiers,
	})
}

// handleDriveBuy — POST /v1/drive/buy {"tier":<index>}: book the tier price
// in sats as KindFee (ref 'drive-tier:<gb>GB'), then raise the quota. If the
// quota extension fails, money returns via a counter-booking ('refund:…').
func (s *Server) handleDriveBuy(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error":"method not allowed"}`, 405)
		return
	}
	if !s.cfg.Drive.Enabled {
		http.Error(w, `{"error":"drive disabled"}`, 404)
		return
	}
	account := r.Header.Get("X-Bmail-Account")
	var req struct {
		Tier int `json:"tier"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Tier < 0 || req.Tier >= len(s.cfg.Drive.Tiers) {
		http.Error(w, `{"error":"invalid tier"}`, 400)
		return
	}
	tier := s.cfg.Drive.Tiers[req.Tier]
	costMsat := tier.Sats * 1000
	ref := "drive-tier:" + strconv.FormatInt(tier.GB, 10) + "GB"
	if err := s.ledger.ApplyDeltaMeta(account, -costMsat, ledger.KindFee, ref, "btc", s.ratePtr()); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(402)
		json.NewEncoder(w).Encode(map[string]any{"error": "insufficient balance for drive tier", "cost_msat": costMsat})
		return
	}
	if err := s.ledger.AddQuotaBytes(account, tier.GB*1073741824); err != nil {
		if rb := s.ledger.ApplyDeltaMeta(account, costMsat, ledger.KindFee, "refund:"+ref, "btc", s.ratePtr()); rb != nil {
			log.Printf("drive buy refund %s: %v", account, rb)
		}
		http.Error(w, fmt.Sprintf(`{"error":"quota: %v"}`, err), 500)
		return
	}
	acct, err := s.ledger.GetAccount(account)
	if err != nil {
		http.Error(w, `{"error":"account not found"}`, 500)
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"quota_bytes": acct.QuotaBytes, "cost_sats": tier.Sats})
}
