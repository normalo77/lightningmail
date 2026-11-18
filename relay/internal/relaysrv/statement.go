// Etappe G2 (§25): Statement-Export.
//
//	GET /v1/statement?from&to&fmt=csv|json   (auth, eigenes Konto)
//	GET /v1/relay/statement?from&to&fmt=…    (X-Relay-Secret, Betreiber)
//
// Reines CSV (Bernd 15.11.: keine DATEV-Chiffren). Zeilen hash-verkettet,
// Monatsanfang = Anker (siehe ledger/statement.go). EUR-Spalten aus dem
// Zufluss-Stempel; ungeratete Zeilen (Regtest ohne Kurs) bleiben leer —
// der Export kennzeichnet das pro Zeile (rate_src leer).
package relaysrv

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/lightningmail/relay/internal/ledger"
)

func stmtRange(r *http.Request) (from, to int64) {
	from, _ = strconv.ParseInt(r.URL.Query().Get("from"), 10, 64)
	to, _ = strconv.ParseInt(r.URL.Query().Get("to"), 10, 64)
	if from < 0 {
		from = 0
	}
	if to < 0 {
		to = 0
	}
	return
}

func iso(ts int64) string {
	if ts <= 0 {
		return ""
	}
	return time.Unix(ts, 0).UTC().Format(time.RFC3339)
}

// --- Kontostatement (eigene Zeilen) ---

func (s *Server) handleStatement(w http.ResponseWriter, r *http.Request) {
	if !curOK(w, r) {
		return
	}
	account := r.Header.Get("X-Bmail-Account")
	from, to := stmtRange(r)
	rows, head, err := s.ledger.StatementChain(account, from, to)
	if err != nil {
		http.Error(w, `{"error":"internal"}`, 500)
		return
	}
	if r.URL.Query().Get("fmt") == "csv" {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="statement-`+account+`.csv"`)
		cw := csv.NewWriter(w)
		cw.Write([]string{"# bmail-statement", "v1", "konto=" + account, "von=" + iso(from), "bis=" + iso(to),
			"erzeugt=" + time.Now().UTC().Format(time.RFC3339), "genesis=" + ledger.GenesisHash(account), "kopf=" + head})
		cw.Write([]string{"# Hinweis: LND-Onchain-/Routinggebühren kennt der Relay nicht — LND-Reports ergänzen.", "", "", "", "", "", "", ""})
		cw.Write([]string{"id", "zeit", "art", "waehrung", "betrag_msat", "betrag_sat", "eur_micro", "kurs_ts", "kurs_quelle", "kurs_meur_per_btc", "referenz", "prev_hash", "hash"})
		for _, x := range rows {
			cw.Write([]string{strconv.FormatInt(x.ID, 10), iso(x.CreatedAt), x.Kind, x.Currency,
				strconv.FormatInt(x.DeltaMsat, 10), strconv.FormatInt(x.DeltaMsat/1000, 10),
				optStrCSV(x.EurMicro), optStrCSV(x.RateTs), derefStr(x.RateSrc), optStrCSV(x.RateMEur),
				x.Ref, x.PrevHash, x.Hash})
		}
		cw.Flush()
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, x := range rows {
		m := map[string]any{"id": x.ID, "ts": x.CreatedAt, "zeit": iso(x.CreatedAt), "art": x.Kind,
			"waehrung": x.Currency, "msat": x.DeltaMsat, "sat": x.DeltaMsat / 1000,
			"referenz": x.Ref, "prev_hash": x.PrevHash, "hash": x.Hash}
		if x.EurMicro != nil {
			m["eur_micro"] = *x.EurMicro
			m["eur"] = float64(*x.EurMicro) / 1e6
		}
		if x.RateTs != nil {
			m["kurs_ts"] = *x.RateTs
		}
		if x.RateSrc != nil {
			m["kurs_quelle"] = *x.RateSrc
		}
		if x.RateMEur != nil {
			m["kurs_meur_per_btc"] = *x.RateMEur
		}
		out = append(out, m)
	}
	json.NewEncoder(w).Encode(map[string]any{
		"konto": account, "von": from, "bis": to, "genesis": ledger.GenesisHash(account),
		"kopf": head, "zeilen": out,
	})
}

// --- Betreiberstatement (X-Relay-Secret, Muster aus relayBlob/relayReceipt) ---

func (s *Server) handleOperatorStatement(w http.ResponseWriter, r *http.Request) {
	if s.cfg.RelaySecret == "" || r.Header.Get("X-Relay-Secret") != s.cfg.RelaySecret {
		http.Error(w, `{"error":"forbidden"}`, 403)
		return
	}
	from, to := stmtRange(r)
	rows, head, err := s.ledger.OperatorChain(s.cfg.Name, from, to)
	if err != nil {
		http.Error(w, `{"error":"internal"}`, 500)
		return
	}
	if r.URL.Query().Get("fmt") == "csv" {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="betreiber-`+s.cfg.Name+`.csv"`)
		cw := csv.NewWriter(w)
		cw.Write([]string{"# bmail-betreiber-statement", "v1", "relay=" + s.cfg.Name, "von=" + iso(from), "bis=" + iso(to),
			"erzeugt=" + time.Now().UTC().Format(time.RFC3339), "genesis=" + ledger.OperatorGenesisHash(s.cfg.Name), "kopf=" + head})
		cw.Write([]string{"quelle", "id", "zeit", "konto", "art", "betrag_msat", "eur_micro", "kurs_ts", "kurs_quelle", "kurs_meur_per_btc", "referenz", "prev_hash", "hash"})
		for _, x := range rows {
			cw.Write([]string{x.Source, strconv.FormatInt(x.ID, 10), iso(x.CreatedAt), x.Account, x.Label,
				strconv.FormatInt(x.AmountMsat, 10), optStrCSV(x.EurMicro), optStrCSV(x.RateTs), derefStr(x.RateSrc),
				optStrCSV(x.RateMEur), x.Ref, x.PrevHash, x.Hash})
		}
		cw.Flush()
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, x := range rows {
		m := map[string]any{"quelle": x.Source, "id": x.ID, "ts": x.CreatedAt, "zeit": iso(x.CreatedAt),
			"konto": x.Account, "art": x.Label, "msat": x.AmountMsat, "referenz": x.Ref,
			"prev_hash": x.PrevHash, "hash": x.Hash}
		if x.EurMicro != nil {
			m["eur_micro"] = *x.EurMicro
			m["eur"] = float64(*x.EurMicro) / 1e6
		}
		if x.RateTs != nil {
			m["kurs_ts"] = *x.RateTs
		}
		if x.RateSrc != nil {
			m["kurs_quelle"] = *x.RateSrc
		}
		if x.RateMEur != nil {
			m["kurs_meur_per_btc"] = *x.RateMEur
		}
		out = append(out, m)
	}
	json.NewEncoder(w).Encode(map[string]any{
		"relay": s.cfg.Name, "von": from, "bis": to, "genesis": ledger.OperatorGenesisHash(s.cfg.Name),
		"kopf": head, "zeilen": out,
	})
}

func optStrCSV(p *int64) string {
	if p == nil {
		return ""
	}
	return strconv.FormatInt(*p, 10)
}

func derefStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
