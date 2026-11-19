// Key- und Porto-Lookup (GET /v1/profile/{addr}, spec §7) mit 429-Budget
// fuer anonyme Aufrufe. Kein oeffentliches Adressbuch, keine Profilkarten —
// das Ziel-Relay liefert nur Pubkey und Portopreis fuer den Mailversand.
package relaysrv

import (
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// --- 429-Budget fuer anonyme Profile-Lookups (Existenz-Oracle bremsen) ---

type lbEntry struct {
	tokens float64
	last   time.Time
}

// shortcut: In-Memory + CF-Connecting-IP ist im LAN spoofbar — fuer ein
// 429-Budget ok; harte Auth kommt mit mTLS/Onion (Etappe 5).
type pubLimit struct {
	mu  sync.Mutex
	b   map[string]*lbEntry
	rpm float64
}

func newPubLimit(rpm int) *pubLimit {
	return &pubLimit{b: map[string]*lbEntry{}, rpm: float64(rpm)}
}

func (pl *pubLimit) allow(key string) bool {
	if pl == nil || pl.rpm <= 0 {
		return true
	}
	pl.mu.Lock()
	defer pl.mu.Unlock()
	if len(pl.b) > 10000 { // Sweep gegen IP-Muell
		cut := time.Now().Add(-time.Hour)
		for k, e := range pl.b {
			if e.last.Before(cut) {
				delete(pl.b, k)
			}
		}
	}
	t := time.Now()
	e := pl.b[key]
	if e == nil {
		e = &lbEntry{tokens: pl.rpm, last: t}
		pl.b[key] = e
	}
	e.tokens += t.Sub(e.last).Minutes() * pl.rpm
	if e.tokens > pl.rpm {
		e.tokens = pl.rpm
	}
	e.last = t
	if e.tokens < 1 {
		return false
	}
	e.tokens--
	return true
}

func clientIP(r *http.Request) string {
	// Hinter dem Cloudflare-Tunnel ist RemoteAddr immer 127.0.0.1.
	if ip := r.Header.Get("CF-Connecting-IP"); ip != "" {
		return ip
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func (s *Server) optAccount(r *http.Request) string {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if tok == "" {
		return ""
	}
	acct, err := s.ledger.LookupToken(tok)
	if err != nil {
		return ""
	}
	return acct
}

// curOK — §26: Endpoints nehmen ?cur=; aktuell nur btc, keine Mischpfade.
func curOK(w http.ResponseWriter, r *http.Request) bool {
	if cur := r.URL.Query().Get("cur"); cur != "" && cur != "btc" {
		http.Error(w, `{"error":"unsupported currency (btc only)"}`, 400)
		return false
	}
	return true
}

// --- GET /v1/profile/{addr} ---

func (s *Server) handleProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, 405)
		return
	}
	addr := strings.TrimPrefix(r.URL.Path, "/v1/profile/")
	if i := strings.Index(addr, "@"); i >= 0 {
		addr = addr[:i] // Adressnotation erlaubt, aufgeloest wird der Local Part
	}
	if addr == "" || strings.Contains(addr, "/") {
		http.Error(w, `{"error":"address required"}`, 400)
		return
	}
	acct, err := s.ledger.GetAccount(addr)
	if err != nil {
		// Wenn lokal nicht gefunden und kein Peer-Loop (X-Relay-Hop):
		// konfigurierte Peer-Relays abfragen (Föderations-Lookup), damit ein Nutzer
		// auf Relay A auch Konten auf Relay B anschreiben kann, ohne dass das Konto
		// manuell auf beiden Relays angelegt werden muss.
		if r.Header.Get("X-Relay-Hop") == "" {
			cl := &http.Client{Timeout: 5 * time.Second}
			for _, peer := range s.cfg.Peers {
				if peer.URL == "" {
					continue
				}
				req, err2 := http.NewRequestWithContext(r.Context(), http.MethodGet, strings.TrimSuffix(peer.URL, "/")+"/v1/profile/"+addr, nil)
				if err2 != nil {
					continue
				}
				req.Header.Set("X-Relay-Hop", "1")
				pr, err2 := cl.Do(req)
				if err2 != nil {
					continue
				}
				if pr.StatusCode == 200 {
					var pbody map[string]any
					err3 := json.NewDecoder(pr.Body).Decode(&pbody)
					pr.Body.Close()
					if err3 == nil && pbody["pubkey"] != nil {
						pbody["relay"] = peer.Name
						w.Header().Set("Content-Type", "application/json")
						json.NewEncoder(w).Encode(pbody)
						return
					}
				} else {
					pr.Body.Close()
				}
			}
		}
		http.Error(w, `{"error":"not found"}`, 404)
		return
	}
	if s.optAccount(r) == "" && !s.pubLim.allow(clientIP(r)) {
		w.Header().Set("Retry-After", "60")
		http.Error(w, `{"error":"rate limit exceeded"}`, 429)
		return
	}
	json.NewEncoder(w).Encode(map[string]any{
		"address":      acct.Name,
		"pubkey":       hex.EncodeToString(acct.MailboxPubkey),
		"foreign_sats": s.postage.ForeignSats(),
	})
}
