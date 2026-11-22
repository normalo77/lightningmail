package relaysrv

// Etappe A (relay admin panel): operator stats + account deletion over a
// SECOND listener that is meant to be bound to a LAN address. The public
// tunnel points at ListenAddr only, so /admin never leaves the local net —
// and every handler still re-checks the source IP (defense in depth).
//
// Login: the browser asks for a challenge nonce, the operator runs
// `lncli signmessage <nonce>` on the relay host (the node key of the
// relay's own lnd wallet — or cfg.admin.node_pubkey), pastes the signature
// back. relayd verifies it via lnd's VerifyMessage: nothing secret is ever
// typed into the browser. Sessions are in-memory tokens (restart = logout).

import (
	"context"
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

//go:embed admin.html
var adminHTML []byte

const (
	adminNonceTTL   = 2 * time.Minute
	adminTokenTTL   = 12 * time.Hour
	adminLoginLimit = 8 // attempts per IP per window
	adminWin        = 15 * time.Minute
)

type adminState struct {
	mu         sync.Mutex
	nonce      string
	nonceUntil time.Time
	tokens     map[string]time.Time
	fails      map[string][]time.Time
	pubkey     string // pinned or lazily resolved node pubkey
	// verify seam for tests: returns the recovered pubkey for msg+sig.
	verify func(msg, sig string) (string, error)
}

// AdminRoutes builds the panel mux (also used directly by httptest).
func (s *Server) AdminRoutes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.adminIP(s.serveAdminHTML))
	mux.HandleFunc("POST /v1/admin/challenge", s.adminIP(s.adminChallenge))
	mux.HandleFunc("POST /v1/admin/login", s.adminIP(s.adminLogin))
	mux.HandleFunc("GET /v1/admin/overview", s.adminIP(s.adminAuth(s.adminOverview)))
	mux.HandleFunc("POST /v1/admin/delete", s.adminIP(s.adminAuth(s.adminDelete)))
	return mux
}

// AdminListenAndServe blocks serving the panel on cfg.Admin.Listen.
func (s *Server) AdminListenAndServe() error {
	if s.cfg.Admin.Listen == "" {
		return nil
	}
	return http.ListenAndServe(s.cfg.Admin.Listen, s.AdminRoutes())
}

// --- guards ---

func privateIP(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast())
}

func (s *Server) adminIP(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil || !privateIP(host) {
			http.Error(w, `{"error":"admin panel: LAN-only"}`, http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

func (s *Server) adminAuth(next func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Auth"+"orization"), "Bearer ")
		now := time.Now()
		s.adm.mu.Lock()
		exp, ok := s.adm.tokens[tok]
		if ok && exp.Before(now) {
			delete(s.adm.tokens, tok)
			ok = false
		}
		for t, e := range s.adm.tokens { // lazy purge
			if e.Before(now) {
				delete(s.adm.tokens, t)
			}
		}
		s.adm.mu.Unlock()
		if !ok || tok == "" {
			http.Error(w, `{"error":"admin: login erforderlich"}`, http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// expectedNodePubkey: config pin wins; else this relay's own lnd node.
func (s *Server) expectedNodePubkey() (string, error) {
	s.adm.mu.Lock()
	if s.adm.pubkey != "" {
		pk := s.adm.pubkey
		s.adm.mu.Unlock()
		return pk, nil
	}
	s.adm.mu.Unlock()
	pk := ""
	if s.cfg.Admin.NodePubkey != "" {
		pk = strings.ToLower(strings.TrimSpace(s.cfg.Admin.NodePubkey))
	} else {
		if s.ln == nil {
			return "", fmt.Errorf("admin: kein lnd und kein node_pubkey konfiguriert")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		info, err := s.ln.GetInfo(ctx)
		if err != nil {
			return "", err
		}
		pk = strings.ToLower(info.IdentityPubkey)
	}
	if len(pk) != 66 {
		return "", fmt.Errorf("admin: node_pubkey ungültig (%d Zeichen)", len(pk))
	}
	s.adm.mu.Lock()
	s.adm.pubkey = pk
	s.adm.mu.Unlock()
	return pk, nil
}

func (s *Server) verifyNodeSig(msg, sig string) (string, error) {
	if s.adm.verify != nil {
		return s.adm.verify(msg, sig)
	}
	if s.ln == nil {
		return "", fmt.Errorf("admin: lnd nicht verfuegbar")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return s.ln.VerifyMessage(ctx, msg, sig)
}

// --- handlers ---

func (s *Server) serveAdminHTML(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Write(adminHTML)
}

func (s *Server) adminChallenge(w http.ResponseWriter, r *http.Request) {
	nonce := randHex(16)
	s.adm.mu.Lock()
	s.adm.nonce = nonce
	s.adm.nonceUntil = time.Now().Add(adminNonceTTL)
	s.adm.mu.Unlock()
	jsonOut(w, map[string]any{"nonce": nonce, "command": "lncli signmessage '" + nonce + "'"})
}

func (s *Server) adminLogin(w http.ResponseWriter, r *http.Request) {
	var body struct{ Nonce, Signature string }
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		http.Error(w, `{"error":"bad json"}`, 400)
		return
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	now := time.Now()
	s.adm.mu.Lock()
	kept := s.adm.fails[ip][:0]
	for _, t := range s.adm.fails[ip] {
		if now.Sub(t) < adminWin {
			kept = append(kept, t)
		}
	}
	tooMany := len(kept) >= adminLoginLimit
	s.adm.fails[ip] = kept
	fresh := s.adm.nonce != "" && s.adm.nonce == body.Nonce && now.Before(s.adm.nonceUntil)
	if fresh {
		s.adm.nonce = "" // single-use, even before verification
	}
	s.adm.mu.Unlock()
	if tooMany {
		http.Error(w, `{"error":"zu viele Fehlversuche — 15 Min. Sperre"}`, http.StatusTooManyRequests)
		return
	}
	if !fresh {
		http.Error(w, `{"error":"challenge abgelaufen oder unbekannt — neu anfordern"}`, http.StatusBadRequest)
		return
	}
	want, err := s.expectedNodePubkey()
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"admin: %v"}`, err), http.StatusBadGateway)
		return
	}
	got, err := s.verifyNodeSig(body.Nonce, strings.TrimSpace(body.Signature))
	if err != nil {
		log.Printf("admin: verify failed from %s: %v", ip, err)
		s.adm.mu.Lock()
		s.adm.fails[ip] = append(s.adm.fails[ip], time.Now())
		s.adm.mu.Unlock()
		http.Error(w, `{"error":"Signatur ungueltig"}`, http.StatusUnauthorized)
		return
	}
	if subtle.ConstantTimeCompare([]byte(strings.ToLower(got)), []byte(want)) != 1 {
		s.adm.mu.Lock()
		s.adm.fails[ip] = append(s.adm.fails[ip], time.Now())
		s.adm.mu.Unlock()
		http.Error(w, `{"error":"Signatur von fremdem Node-Key"}`, http.StatusUnauthorized)
		return
	}
	tok := randHex(24)
	s.adm.mu.Lock()
	s.adm.tokens[tok] = time.Now().Add(adminTokenTTL)
	s.adm.mu.Unlock()
	jsonOut(w, map[string]any{"token": tok, "node_pubkey": want})
}

func (s *Server) adminOverview(w http.ResponseWriter, r *http.Request) {
	ov, err := s.ledger.AdminOverview()
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"overview: %v"}`, err), 500)
		return
	}
	ov.RelayName = s.cfg.Name
	ov.Network = s.cfg.LND.Network
	jsonOut(w, ov)
}

func (s *Server) adminDelete(w http.ResponseWriter, r *http.Request) {
	var body struct{ Name string }
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil || !acctNameRe.MatchString(body.Name) {
		http.Error(w, `{"error":"name fehlt oder ungueltig"}`, 400)
		return
	}
	orphans, err := s.ledger.DeleteAccountCascade(body.Name)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"delete: %v"}`, err), 500)
		return
	}
	removed := 0
	for _, sha := range orphans {
		p := s.cfg.DataDir + "/blob/" + sha[:2] + "/" + sha
		if err := os.Remove(p); err == nil {
			removed++
		} else if !os.IsNotExist(err) {
			log.Printf("admin: blob unlink %s: %v", sha, err)
		}
	}
	jsonOut(w, map[string]any{"deleted": true, "account": body.Name, "orphan_blobs": len(orphans), "files_removed": removed})
}

func jsonOut(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
