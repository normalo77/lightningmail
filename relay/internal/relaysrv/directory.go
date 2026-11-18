// Etappe B — Directory-Endpoints (CONCEPT §21, Beschluss 15.11.2026, spec §7d):
//
//	PUT    /v1/profile        (auth) signierte Karte + gdpr1-Consent veroeffentlichen
//	DELETE /v1/profile        (auth) Karte loeschen (DSGVO: alles weg)
//	GET    /v1/profile/{addr}         gratis Key-Lookup (+ Karten-Metadaten), 429-Budget
//	GET    /v1/profile/{addr}/card (auth) gekaufte/eigene Karte, sonst 402 Preisangebot
//	POST   /v1/profile/{addr}/card (auth) Karte kaufen (Dedup pro card_hash)
//
// Oekonomik: Key-Aufloesung gratis, Profilkarte bezahlt — Split Server-Fee +
// Kontaktpreis (Default 2,5 + 2,5 ct), wertdefiniert in Milli-EUR → sats per
// Tageskurs (§25/§26). Ohne Kurs kein Kauf (503) — Preis waere erfunden.
// Suche nur exakter Treffer; kein Scan, keine Liste, Existenz nur via
// Key-Lookup (der war schon immer gratis, spec §7).
package relaysrv

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/lightningmail/relay/internal/config"
	"github.com/lightningmail/relay/internal/crypto"
	"github.com/lightningmail/relay/internal/ledger"
)

var cardFieldRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

const maxCardFields = 32

// --- 429-Budget fuer anonyme Directory-Lesen (Existenz-Oracle bremsen) ---

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

// optAccount: Token freiwillig — fuer "purchased"-Flag im Gratis-Lookup.
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

// curOK — §26: Endpoints nehmen ?cur=; Etappe B kennt nur btc, keine Mischpfade.
func curOK(w http.ResponseWriter, r *http.Request) bool {
	if cur := r.URL.Query().Get("cur"); cur != "" && cur != "btc" {
		http.Error(w, `{"error":"unsupported currency (btc only in Etappe B)"}`, 400)
		return false
	}
	return true
}

// meurToMsat: wertdefinierter Preis (Milli-EUR) → msat am Tageskurs, aufgerundet
// (niemand bekommt eine Karte unter Wert). rate = EUR/BTC × 1000.
func meurToMsat(meur, rateMEurPerBtc int64) int64 {
	if rateMEurPerBtc <= 0 || meur <= 0 {
		return 0
	}
	return (meur*100000000000 + rateMEurPerBtc - 1) / rateMEurPerBtc
}

// --- PUT/DELETE /v1/profile (auth, exakter Pfad) ---

type gdprConsent struct {
	V       string   `json:"v"`
	Ts      int64    `json:"ts"`
	Fields  []string `json:"fields"`
	Purpose string   `json:"purpose"`
}

type putProfileReq struct {
	CardB64   string      `json:"card_b64"`
	Sig       string      `json:"sig"`
	PriceMEur *int64      `json:"price_meur"`
	Consent   gdprConsent `json:"consent"`
}

func (s *Server) handleMyProfile(w http.ResponseWriter, r *http.Request) {
	name := r.Header.Get("X-Bmail-Account")
	switch r.Method {
	case http.MethodPut:
		s.putProfile(w, r, name)
	case http.MethodDelete:
		acct, err := s.ledger.GetAccount(name)
		if err != nil {
			http.Error(w, `{"error":"not found"}`, 404)
			return
		}
		if err := s.ledger.DeleteProfile(acct.ID); err != nil {
			http.Error(w, `{"error":"internal"}`, 500)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "deleted": true})
	default:
		http.Error(w, `{"error":"method not allowed"}`, 405)
	}
}

func (s *Server) putProfile(w http.ResponseWriter, r *http.Request, name string) {
	acct, err := s.ledger.GetAccount(name)
	if err != nil {
		http.Error(w, `{"error":"not found"}`, 404)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, `{"error":"read body"}`, 500)
		return
	}
	var req putProfileReq
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, `{"error":"invalid json"}`, 400)
		return
	}
	cardBytes, err := base64.StdEncoding.DecodeString(req.CardB64)
	if err != nil || len(cardBytes) < 2 || len(cardBytes) > config.MaxCardBytes {
		http.Error(w, `{"error":"card_b64 missing or out of size bounds"}`, 400)
		return
	}
	var fields map[string]string
	if err := json.Unmarshal(cardBytes, &fields); err != nil || len(fields) == 0 || len(fields) > maxCardFields {
		http.Error(w, `{"error":"card must be a non-empty JSON object of string fields"}`, 400)
		return
	}
	for k := range fields {
		if !cardFieldRe.MatchString(k) {
			http.Error(w, `{"error":"card field name not allowed: `+k+`"}`, 400)
			return
		}
	}
	// Consent (Beschluss: exakt gdpr1, signierte Projektion, fields == Kartenfelder)
	c := req.Consent
	if c.V != "gdpr1" || c.Purpose != "directory" || c.Ts <= 0 {
		http.Error(w, `{"error":"consent must be {v:gdpr1, ts, fields, purpose:directory}"}`, 400)
		return
	}
	fieldSet := map[string]bool{}
	for _, f := range c.Fields {
		fieldSet[f] = true
	}
	if len(fieldSet) != len(c.Fields) || len(fieldSet) != len(fields) {
		http.Error(w, `{"error":"consent.fields must match card fields exactly"}`, 400)
		return
	}
	for k := range fields {
		if !fieldSet[k] {
			http.Error(w, `{"error":"consent.fields must match card fields exactly"}`, 400)
			return
		}
	}
	// Signatur: BIP340 ueber sha256(exakte Karten-Bytes) mit dem Mailbox-Key —
	// Aenderung/Loeschung globaler Eintraege nur durch den Key-Inhaber.
	sigBytes, err := hex.DecodeString(req.Sig)
	if err != nil || len(sigBytes) != 64 {
		http.Error(w, `{"error":"sig must be 64-byte hex (BIP340)"}`, 400)
		return
	}
	pub, err := crypto.ParsePubKey(acct.MailboxPubkey)
	if err != nil {
		http.Error(w, `{"error":"internal"}`, 500)
		return
	}
	if err := crypto.Verify(pub, cardBytes, sigBytes); err != nil {
		http.Error(w, `{"error":"card signature invalid for this account"}`, 403)
		return
	}
	price := s.cfg.Directory.DefaultPriceMEur
	if req.PriceMEur != nil {
		price = *req.PriceMEur
	}
	if price < 0 || price > config.MaxCardPriceMEur {
		http.Error(w, `{"error":"price_meur out of range [0,100000]"}`, 400)
		return
	}
	consentRaw, _ := json.Marshal(c)
	p, err := s.ledger.PutProfile(acct.ID, string(cardBytes), req.Sig, string(consentRaw), price)
	if err != nil {
		http.Error(w, `{"error":"internal"}`, 500)
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"ok": true, "card_hash": p.CardHash, "price_meur": price})
}

// --- GET /v1/profile/{addr} (+ /card) ---

func (s *Server) handleProfile(w http.ResponseWriter, r *http.Request) {
	addr := strings.TrimPrefix(r.URL.Path, "/v1/profile/")
	if name, ok := strings.CutSuffix(addr, "/card"); ok {
		s.handleCard(w, r, name)
		return
	}
	if i := strings.Index(addr, "@"); i >= 0 {
		addr = addr[:i] // Adressnotation erlaubt, geloost wird der Local Part
	}
	if addr == "" {
		http.Error(w, `{"error":"address required"}`, 400)
		return
	}
	acct, err := s.ledger.GetAccount(addr)
	if err != nil {
		http.Error(w, `{"error":"not found"}`, 404)
		return
	}
	me := s.optAccount(r)
	if me == "" && !s.pubLim.allow(clientIP(r)) {
		w.Header().Set("Retry-After", "60")
		http.Error(w, `{"error":"rate limit — Directory-Budget erschoepft"}`, 429)
		return
	}
	resp := map[string]any{
		"address":      acct.Name,
		"pubkey":       hex.EncodeToString(acct.MailboxPubkey),
		"foreign_sats": s.postage.ForeignSats(),
		"contact_sats": s.cfg.Postage.ContactSats,
		"has_card":     false,
	}
	if p, err := s.ledger.GetProfileByName(addr); err == nil {
		fee := s.cfg.Directory.ServerFeeMEur
		total := p.PriceMEur + fee
		resp["has_card"] = true
		resp["card_hash"] = p.CardHash
		resp["price_meur"] = p.PriceMEur
		resp["fee_meur"] = fee
		resp["total_meur"] = total
		if rate, ok := s.rateFeed.Current(); ok {
			resp["total_msat"] = meurToMsat(total, rate.MEurPerBtc)
			resp["rate"] = map[string]any{"meur_per_btc": rate.MEurPerBtc, "ts": rate.Ts, "src": rate.Src}
		}
		if me != "" {
			bought := me == addr
			if !bought {
				bought, _ = s.ledger.HasPurchase(me, p.CardHash)
			}
			resp["purchased"] = bought
		}
	}
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleCard(w http.ResponseWriter, r *http.Request, name string) {
	if !curOK(w, r) {
		return
	}
	if i := strings.Index(name, "@"); i >= 0 {
		name = name[:i]
	}
	buyer := s.optAccount(r)
	if buyer == "" {
		http.Error(w, `{"error":"unauthorized"}`, 401)
		return
	}
	p, err := s.ledger.GetProfileByName(name)
	if errors.Is(err, ledger.ErrNoProfile) {
		// Achtungs-Note (Beschluss): wer schon bezahlt hat, bekommt 410 statt 404.
		if bought, _ := s.ledger.BoughtFrom(buyer, name); bought {
			http.Error(w, `{"error":"card deleted by owner"}`, 410)
			return
		}
		http.Error(w, `{"error":"no published profile"}`, 404)
		return
	}
	if err != nil {
		http.Error(w, `{"error":"internal"}`, 500)
		return
	}
	switch r.Method {
	case http.MethodGet:
		if buyer == p.Name {
			s.writeCard(w, p, true, nil)
			return
		}
		if bought, _ := s.ledger.HasPurchase(buyer, p.CardHash); bought {
			s.writeCard(w, p, true, nil)
			return
		}
		s.writeCardOffer(w, p, 402)
	case http.MethodPost:
		s.buyCard(w, r, buyer, p)
	default:
		http.Error(w, `{"error":"method not allowed"}`, 405)
	}
}

func (s *Server) buyCard(w http.ResponseWriter, r *http.Request, buyer string, p *ledger.Profile) {
	if buyer == p.Name {
		s.writeCard(w, p, true, nil) // eigene Karte ist immer frei
		return
	}
	fee := s.cfg.Directory.ServerFeeMEur
	total := p.PriceMEur + fee
	if total <= 0 { // Gratis-Karte: kein Geld, kein Kaufeintrag
		s.writeCard(w, p, true, map[string]any{"total_meur": int64(0), "fresh": true, "free": true})
		return
	}
	rate, ok := s.rateFeed.Current()
	if !ok {
		http.Error(w, `{"error":"no exchange rate — card purchase currently unavailable"}`, 503)
		return
	}
	paidMsat := meurToMsat(total, rate.MEurPerBtc)
	sellerMsat := meurToMsat(p.PriceMEur, rate.MEurPerBtc)
	feeMsat := paidMsat - sellerMsat
	fresh, err := s.ledger.BuyCard(buyer, p.Name, p.CardHash, paidMsat, sellerMsat, feeMsat, "btc", &rate)
	if errors.Is(err, ledger.ErrInsufficient) {
		s.writeCardOffer(w, p, 402) // Preisangebot nochmal, Client meldet Guthaben
		return
	}
	if errors.Is(err, ledger.ErrNotFound) {
		http.Error(w, `{"error":"not found"}`, 404)
		return
	}
	if err != nil {
		http.Error(w, `{"error":"internal"}`, 500)
		return
	}
	paid := map[string]any{
		"total_meur": total, "seller_meur": p.PriceMEur, "fee_meur": fee,
		"total_msat": paidMsat, "seller_msat": sellerMsat, "currency": "btc",
		"rate": map[string]any{"meur_per_btc": rate.MEurPerBtc, "ts": rate.Ts, "src": rate.Src},
		"fresh": fresh,
	}
	s.writeCard(w, p, true, paid)
}

// writeCardOffer: 402 mit Preisangebot (Existenz-Oracle bleibt kostenlos,
// Inhalt gibt es erst nach Zahlung — Beschluss 15.11.).
func (s *Server) writeCardOffer(w http.ResponseWriter, p *ledger.Profile, status int) {
	fee := s.cfg.Directory.ServerFeeMEur
	total := p.PriceMEur + fee
	body := map[string]any{
		"error": "payment required", "card_hash": p.CardHash,
		"total_meur": total, "seller_meur": p.PriceMEur, "fee_meur": fee,
	}
	if rate, ok := s.rateFeed.Current(); ok {
		body["total_msat"] = meurToMsat(total, rate.MEurPerBtc)
		body["rate"] = map[string]any{"meur_per_btc": rate.MEurPerBtc, "ts": rate.Ts, "src": rate.Src}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(body)
}

func (s *Server) writeCard(w http.ResponseWriter, p *ledger.Profile, purchased bool, paid map[string]any) {
	resp := map[string]any{
		"address": p.Name, "pubkey": hex.EncodeToString(p.Pubkey),
		"card_b64":  base64.StdEncoding.EncodeToString([]byte(p.CardJSON)),
		"sig":       p.Sig, "card_hash": p.CardHash,
		"price_meur": p.PriceMEur, "purchased": purchased,
	}
	var c any
	if json.Unmarshal([]byte(p.Consent), &c) == nil {
		resp["consent"] = c
	}
	if paid != nil {
		resp["paid"] = paid
	}
	json.NewEncoder(w).Encode(resp)
}
