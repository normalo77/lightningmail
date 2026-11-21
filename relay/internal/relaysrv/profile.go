// Key and postage lookup (GET /v1/profile/{addr}, spec §7) with a 429 budget
// for anonymous calls. No public address book, no profile cards —
// the target relay only returns pubkey and postage price for sending mail.
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

// --- 429 budget for anonymous profile lookups (slow down the existence oracle) ---

type lbEntry struct {
	tokens float64
	last   time.Time
}

// shortcut: in-memory + CF-Connecting-IP is spoofable on a LAN — fine for
// a 429 budget; hard auth comes with mTLS/onion (Etappe 5).
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
	if len(pl.b) > 10000 { // sweep against IP junk
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
	// Behind the Cloudflare tunnel RemoteAddr is always 127.0.0.1.
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

// curOK — §26: endpoints take ?cur=; currently only btc, no mixed paths.
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
	domain := ""
	if i := strings.Index(addr, "@"); i >= 0 {
		domain = strings.ToLower(addr[i+1:]) // §4.2: domain → relay discovery
		addr = addr[:i]
	}
	if addr == "" || strings.Contains(addr, "/") {
		http.Error(w, `{"error":"address required"}`, 400)
		return
	}
	acct, err := s.ledger.GetAccount(addr)
	// explicitly foreign domain (peer from config) → query remotely even on a local hit.
	explicitRemote := domain != "" && !strings.EqualFold(domain, s.cfg.Name) && s.lookupPeer(domain) != nil
	if err != nil || explicitRemote {
		// When not found locally (or a foreign domain is addressed) and no
		// peer loop (X-Relay-Hop): query the target relay via DNS/peer discovery
		// (federation lookup §4.2), so a user on relay A can also write to
		// accounts on relay B. Fallback: all peers in order.
		if r.Header.Get("X-Relay-Hop") == "" {
			cl := &http.Client{Timeout: 5 * time.Second}
			fetch := func(relayURL, relayName string) bool {
				if relayURL == "" {
					return false
				}
				req, err2 := http.NewRequestWithContext(r.Context(), http.MethodGet, strings.TrimSuffix(relayURL, "/")+"/v1/profile/"+addr, nil)
				if err2 != nil {
					return false
				}
				req.Header.Set("X-Relay-Hop", "1")
				pr, err2 := cl.Do(req)
				if err2 != nil {
					return false
				}
				defer pr.Body.Close()
				if pr.StatusCode != 200 {
					return false
				}
				var pbody map[string]any
				if err2 := json.NewDecoder(pr.Body).Decode(&pbody); err2 != nil || pbody["pubkey"] == nil {
					return false
				}
				pbody["relay"] = relayName
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(pbody)
				return true
			}
			if domain != "" {
				if relayURL, _, err2 := s.resolveDomainRelay(r.Context(), domain); err2 == nil && fetch(relayURL, domain) {
					return
				}
			}
			if err != nil {
				for _, peer := range s.cfg.Peers {
					if fetch(peer.URL, peer.Name) {
						return
					}
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
		"welcome_sats": s.postage.WelcomeSats(),
	})
}
