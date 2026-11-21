// Etappe 6: WebAuthn/passkey login (CONCEPT §21).
// Registration happens authenticated (only a logged-in user binds
// passkeys to their account); login is unauthenticated and returns
// a normal persistent token plus the key wraps.
// PRF evaluation happens ONLY in the client — the relay sees/stores only
// opaque wraps (no plaintext, no trust gain over LMKEY1).
package relaysrv

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/lightningmail/relay/internal/ledger"
)

var errWANotConfigured = errors.New("webauthn: not configured (relay.yaml webauthn.rp_id fehlt)")

const waSessionTTL = 5 * time.Minute

// waPRFSalt is the deterministic PRF salt per account (identical to the
// client-side formula in keywrap.ts so wrap/unwrap match).
func waPRFSalt(acct string) protocol.PRFValues {
	h := sha256.Sum256([]byte("lm-prf-v1:" + acct))
	return protocol.PRFValues{First: h[:]}
}

type waSessionEntry struct {
	sess    webauthn.SessionData
	expires time.Time
}

// waUser adapts a bmail account to the go-webauthn User interface.
type waUser struct {
	acct  string
	creds []webauthn.Credential
}

func (u *waUser) WebAuthnID() []byte                         { return []byte("bmail:" + u.acct) }
func (u *waUser) WebAuthnName() string                       { return u.acct }
func (u *waUser) WebAuthnDisplayName() string                { return u.acct }
func (u *waUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

func (s *Server) waInstance() (*webauthn.WebAuthn, error) {
	if s.cfg.WebAuthn.RPID == "" || len(s.cfg.WebAuthn.Origins) == 0 {
		return nil, errWANotConfigured
	}
	name := s.cfg.WebAuthn.RPName
	if name == "" {
		name = "lightningmail"
	}
	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: name,
		RPID:          s.cfg.WebAuthn.RPID,
		RPOrigins:     s.cfg.WebAuthn.Origins,
	})
	if err != nil {
		log.Printf("webauthn: config invalid: %v", err)
		return nil, err
	}
	return wa, nil
}

// loadWAUser fetches an account's registered credentials from the DB.
func (s *Server) loadWAUser(acct string) (*waUser, error) {
	rows, err := s.ledger.WACredentialsFor(acct)
	if err != nil {
		return nil, err
	}
	u := &waUser{acct: acct}
	for _, r := range rows {
		id, err := base64.RawURLEncoding.DecodeString(r.CredID)
		if err != nil {
			continue
		}
		u.creds = append(u.creds, webauthn.Credential{
			ID:        id,
			PublicKey: r.PublicKey,
			Authenticator: webauthn.Authenticator{
				SignCount: r.SignCount,
			},
		})
	}
	return u, nil
}

func (s *Server) waPutSession(sess *webauthn.SessionData) string {
	b := make([]byte, 16)
	rand.Read(b)
	sid := hex.EncodeToString(b)
	s.waMu.Lock()
	defer s.waMu.Unlock()
	now := time.Now()
	for k, v := range s.waSessions { // opportunistic TTL maintenance
		if now.After(v.expires) {
			delete(s.waSessions, k)
		}
	}
	s.waSessions[sid] = waSessionEntry{sess: *sess, expires: now.Add(waSessionTTL)}
	return sid
}

func (s *Server) waTakeSession(sid string) (webauthn.SessionData, bool) {
	s.waMu.Lock()
	defer s.waMu.Unlock()
	e, ok := s.waSessions[sid]
	if !ok {
		return webauthn.SessionData{}, false
	}
	delete(s.waSessions, sid)
	if time.Now().After(e.expires) {
		return webauthn.SessionData{}, false
	}
	return e.sess, true
}

// bodyWithCredential returns a request clone whose body is exactly the
// WebAuthn credential JSON (go-webauthn parses directly from *http.Request).
// Android browsers (Brave/Chrome/GMS) send unsolicited clientExtensionResults
// like "credProps", on which go-webauthn v0.18.2 strictly fails; since the relay
// doesn't need clientExtensionResults at all (PRF is evaluated client-side
// before the POST), we empty clientExtensionResults before parsing.
func bodyWithCredential(r *http.Request, credJSON json.RawMessage) *http.Request {
	var m map[string]any
	if err := json.Unmarshal(credJSON, &m); err == nil {
		m["clientExtensionResults"] = map[string]any{}
		if cleaned, err := json.Marshal(m); err == nil {
			credJSON = cleaned
		}
	}
	clone := r.Clone(r.Context())
	clone.Body = io.NopCloser(bytes.NewReader(credJSON))
	clone.ContentLength = int64(len(credJSON))
	clone.Header.Set("Content-Type", "application/json")
	return clone
}

func waError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// --- POST /v1/webauthn/register/begin (authenticated) ---

func (s *Server) handleWARegisterBegin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		waError(w, 405, "method not allowed")
		return
	}
	wa, err := s.waInstance()
	if err != nil {
		waError(w, 503, "WebAuthn ist auf diesem Relay nicht konfiguriert")
		return
	}
	acct := r.Header.Get("X-Bmail-Account") // from the bearer token (auth middleware)
	if _, err := s.ledger.GetAccount(acct); err != nil {
		waError(w, 404, "Konto nicht gefunden")
		return
	}
	user, err := s.loadWAUser(acct)
	if err != nil {
		waError(w, 500, "interner Fehler")
		return
	}
	opts, sess, err := wa.BeginRegistration(user,
		webauthn.WithExtensions(webauthn.WithExtensionPRF(waPRFSalt(acct))))
	if err != nil {
		waError(w, 500, "BeginRegistration: "+err.Error())
		return
	}
	sid := s.waPutSession(sess)
	json.NewEncoder(w).Encode(map[string]any{"sid": sid, "options": opts})
}

// --- POST /v1/webauthn/register/finish (authenticated) ---

func (s *Server) handleWARegisterFinish(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		waError(w, 405, "method not allowed")
		return
	}
	wa, err := s.waInstance()
	if err != nil {
		waError(w, 503, "WebAuthn ist auf diesem Relay nicht konfiguriert")
		return
	}
	acct := r.Header.Get("X-Bmail-Account")
	var req struct {
		SID        string          `json:"sid"`
		Name       string          `json:"name"`
		Credential json.RawMessage `json:"credential"`
		WrapPRF    string          `json:"wrap_prf"`
		WrapPass   string          `json:"wrap_pass"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		waError(w, 400, "bad request")
		return
	}
	sess, ok := s.waTakeSession(req.SID)
	if !ok {
		waError(w, 400, "Sitzung abgelaufen oder unbekannt — Registrierung neu starten")
		return
	}
	user, err := s.loadWAUser(acct)
	if err != nil {
		waError(w, 500, "interner Fehler")
		return
	}
	cred, err := wa.FinishRegistration(user, sess, bodyWithCredential(r, req.Credential))
	if err != nil {
		waError(w, 401, "Passkey-Registrierung fehlgeschlagen: "+err.Error())
		return
	}
	credID := base64.RawURLEncoding.EncodeToString(cred.ID)
	row := ledger.WACredential{
		CredID:    credID,
		Account:   acct,
		Name:      req.Name,
		PublicKey: cred.PublicKey,
		SignCount: cred.Authenticator.SignCount,
	}
	if err := s.ledger.WAStoreCredential(row); err != nil {
		waError(w, 500, "Speicherfehler")
		return
	}
	if req.WrapPRF != "" || req.WrapPass != "" {
		if err := s.ledger.WAStoreWraps(credID, req.WrapPRF, req.WrapPass); err != nil {
			waError(w, 500, "Speicherfehler (Wrap)")
			return
		}
	}
	json.NewEncoder(w).Encode(map[string]any{"ok": true, "cred_id": credID})
}

// --- POST /v1/webauthn/login/begin (unauthenticated) ---

func (s *Server) handleWALoginBegin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		waError(w, 405, "method not allowed")
		return
	}
	wa, err := s.waInstance()
	if err != nil {
		waError(w, 503, "WebAuthn ist auf diesem Relay nicht konfiguriert")
		return
	}
	var req struct {
		Address string `json:"address"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Address == "" {
		waError(w, 400, "bad request")
		return
	}
	// avoid an existence oracle: same response for an unknown account
	// and an account without passkeys.
	empty := func() {
		waError(w, 404, " Fuer dieses Konto ist kein Passkey registriert (oder es existiert nicht).")
	}
	if _, err := s.ledger.GetAccount(req.Address); err != nil {
		empty()
		return
	}
	user, err := s.loadWAUser(req.Address)
	if err != nil {
		waError(w, 500, "interner Fehler")
		return
	}
	if len(user.creds) == 0 {
		empty()
		return
	}
	opts, sess, err := wa.BeginLogin(user,
		webauthn.WithAssertionExtensions(webauthn.WithExtensionPRF(waPRFSalt(req.Address))))
	if err != nil {
		waError(w, 500, "BeginLogin: "+err.Error())
		return
	}
	sid := s.waPutSession(sess)
	json.NewEncoder(w).Encode(map[string]any{"sid": sid, "options": opts})
}

// --- POST /v1/webauthn/login/finish (unauthenticated) ---

func (s *Server) handleWALoginFinish(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		waError(w, 405, "method not allowed")
		return
	}
	wa, err := s.waInstance()
	if err != nil {
		waError(w, 503, "WebAuthn ist auf diesem Relay nicht konfiguriert")
		return
	}
	var req struct {
		Address    string          `json:"address"`
		SID        string          `json:"sid"`
		Credential json.RawMessage `json:"credential"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		waError(w, 400, "bad request")
		return
	}
	sess, ok := s.waTakeSession(req.SID)
	if !ok {
		waError(w, 400, "Sitzung abgelaufen oder unbekannt — Anmeldung neu starten")
		return
	}
	user, err := s.loadWAUser(req.Address)
	if err != nil {
		waError(w, 500, "interner Fehler")
		return
	}
	cred, err := wa.FinishLogin(user, sess, bodyWithCredential(r, req.Credential))
	if err != nil {
		waError(w, 401, "Passkey-Anmeldung fehlgeschlagen: "+err.Error())
		return
	}
	credID := base64.RawURLEncoding.EncodeToString(cred.ID)
	if cred.Authenticator.SignCount > 0 {
		_ = s.ledger.WAUpdateSignCount(credID, cred.Authenticator.SignCount)
	}
	// persistent token as in /v1/auth (Etappe 4a).
	tok := make([]byte, 32)
	rand.Read(tok)
	tokenStr := hex.EncodeToString(tok)
	if err := s.ledger.StoreToken(tokenStr, req.Address); err != nil {
		waError(w, 500, "token store")
		return
	}
	prf, pass, err := s.ledger.WAGetWraps(credID)
	if err != nil {
		waError(w, 500, "wraps")
		return
	}
	var name string
	if row, err := s.ledger.WALookupCredential(credID); err == nil {
		name = row.Name
	}
	json.NewEncoder(w).Encode(map[string]any{
		"token":     tokenStr,
		"wrap_prf":  prf,
		"wrap_pass": pass,
		"cred_id":   credID,
		"cred_name": name,
	})
}

// --- GET /v1/webauthn/credentials (authenticated) ---

func (s *Server) handleWAList(w http.ResponseWriter, r *http.Request) {
	acct := r.Header.Get("X-Bmail-Account")
	rows, err := s.ledger.WACredentialsFor(acct)
	if err != nil {
		waError(w, 500, "interner Fehler")
		return
	}
	type out struct {
		CredID  string `json:"cred_id"`
		Name    string `json:"name"`
		Created int64  `json:"created"`
	}
	list := []out{}
	for _, c := range rows {
		list = append(list, out{CredID: c.CredID, Name: c.Name, Created: c.Created})
	}
	json.NewEncoder(w).Encode(map[string]any{"credentials": list})
}

// --- POST /v1/webauthn/credentials/delete (authenticated) ---

func (s *Server) handleWADelete(w http.ResponseWriter, r *http.Request) {
	acct := r.Header.Get("X-Bmail-Account")
	var req struct {
		CredID string `json:"cred_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		waError(w, 400, "bad request")
		return
	}
	row, err := s.ledger.WALookupCredential(req.CredID)
	if err != nil {
		waError(w, 500, "interner Fehler")
		return
	}
	if row.CredID == "" || row.Account != acct {
		waError(w, 404, "Passkey nicht gefunden")
		return
	}
	if err := s.ledger.WADeleteCredential(req.CredID); err != nil {
		waError(w, 500, "interner Fehler")
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

// --- POST /v1/webauthn/wrap-upgrade (authenticated) — §21 PRF self-healing ---
// If an assertion delivers the PRF secret while the credential only has a
// passphrase wrap, the wrap is lifted to LMKEY1$PRF$ after the last
// passphrase login — future logins only need the fingerprint.
func (s *Server) handleWAWrapUpgrade(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		waError(w, 405, "method not allowed")
		return
	}
	acct := r.Header.Get("X-Bmail-Account")
	var req struct {
		CredID  string `json:"cred_id"`
		WrapPRF string `json:"wrap_prf"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.CredID == "" {
		waError(w, 400, "bad request")
		return
	}
	if !strings.HasPrefix(req.WrapPRF, "LMKEY1$PRF$") || len(req.WrapPRF) > 8192 {
		waError(w, 400, "kein LMKEY1$PRF-Wrap")
		return
	}
	row, err := s.ledger.WALookupCredential(req.CredID)
	if err != nil {
		waError(w, 500, "interner Fehler")
		return
	}
	if row.CredID == "" || row.Account != acct {
		waError(w, 404, "Passkey nicht gefunden")
		return
	}
	if err := s.ledger.WAUpdateWrapPRF(req.CredID, req.WrapPRF); err != nil {
		waError(w, 500, "interner Fehler")
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"ok": true})
}
