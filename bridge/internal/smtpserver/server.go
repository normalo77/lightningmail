// Package smtpserver implements the lmbridge Smart-SMTP-Router: one
// authenticated SMTP submission, per-recipient routing against the LM relay —
// LM accounts get end-to-end encrypted letters, everyone else a classic SMTP
// forward. Mixed mail is split into both deliveries.
package smtpserver

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"

	"github.com/lightningmail/bridge/internal/relayclient"
)

const (
	defaultMaxMessageBytes = 25 << 20
	defaultDomain          = "lmbridge"
	dataTimeout            = 10 * time.Minute // relay hops + blob uploads for big attachments
	lookupTimeout          = 30 * time.Second
)

// Relay is the subset of *relayclient.Client the router uses; an interface so
// unit tests can simulate outages without a network.
type Relay interface {
	LookupProfile(ctx context.Context, addr string) (*relayclient.Profile, bool, error)
	SendMessage(ctx context.Context, to string, prof *relayclient.Profile, m *relayclient.Message) (*relayclient.SendResult, error)
}

// Upstream forwards classic copies. A nil Upstream disables classic delivery.
type Upstream interface {
	Forward(ctx context.Context, from string, to []string, raw []byte) error
}

// Options wires one bridge server.
type Options struct {
	Addr            string
	Domain          string
	MaxMessageBytes int64
	TLSConfig       *tls.Config
	AuthUser        string
	AuthPass        string
	Relay           Relay
	Upstream        Upstream
	// ReplyTo is stamped on classic copies of MIXED mail (when the message
	// has no Reply-To yet) so replies reach the bridge-managed address.
	ReplyTo string
}

// NewServer builds the go-smtp server. AUTH is mandatory for submission;
// plain-text auth is only allowed when no TLS is configured (localhost /
// regtest setups) — with TLSConfig set, clients must STARTTLS first.
func NewServer(opts Options) *smtp.Server {
	if opts.Domain == "" {
		opts.Domain = defaultDomain
	}
	if opts.MaxMessageBytes <= 0 {
		opts.MaxMessageBytes = defaultMaxMessageBytes
	}
	s := smtp.NewServer(&backend{opts: opts})
	s.Addr = opts.Addr
	s.Domain = opts.Domain
	s.MaxMessageBytes = opts.MaxMessageBytes
	s.TLSConfig = opts.TLSConfig
	s.AllowInsecureAuth = opts.TLSConfig == nil
	s.ReadTimeout = 2 * time.Minute
	s.WriteTimeout = 2 * time.Minute
	return s
}

type backend struct{ opts Options }

func (b *backend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	return &session{opts: &b.opts}, nil
}

type rcpt struct {
	addr string
	prof *relayclient.Profile // nil = classic (non-LM) recipient
}

type session struct {
	opts   *Options
	authed bool
	from   string
	rcpts  []rcpt
}

var _ smtp.AuthSession = (*session)(nil)

func (s *session) AuthMechanisms() []string { return []string{"PLAIN", "LOGIN"} }

func (s *session) Auth(mech string) (sasl.Server, error) {
	switch strings.ToUpper(mech) {
	case "PLAIN":
		return sasl.NewPlainServer(func(identity, username, password string) error {
			return s.checkAuth(username, password)
		}), nil
	case "LOGIN":
		return &loginServer{check: s.checkAuth}, nil
	}
	return nil, smtp.ErrAuthUnknownMechanism
}

// checkAuth compares in constant time so the password cannot be leaked
// through response timing.
func (s *session) checkAuth(username, password string) error {
	u := subtle.ConstantTimeCompare([]byte(username), []byte(s.opts.AuthUser))
	p := subtle.ConstantTimeCompare([]byte(password), []byte(s.opts.AuthPass))
	if u == 1 && p == 1 {
		s.authed = true
		return nil
	}
	return smtp.ErrAuthFailed
}

// loginServer implements the legacy LOGIN mechanism server side — go-sasl
// only ships the client half.
type loginServer struct {
	check func(user, pass string) error
	step  int
	user  string
}

func (a *loginServer) Next(response []byte) (challenge []byte, done bool, err error) {
	switch a.step {
	case 0:
		if response == nil {
			a.step = 1
			return []byte("Username:"), false, nil
		}
		a.user = string(response) // "AUTH LOGIN <b64 username>" initial-response form
		a.step = 2
		return []byte("Password:"), false, nil
	case 1:
		a.user = string(response)
		a.step = 2
		return []byte("Password:"), false, nil
	case 2:
		done = true
		err = a.check(a.user, string(response))
	}
	return challenge, done, err
}

func (s *session) Reset() {
	s.from = ""
	s.rcpts = nil
}

func (s *session) Logout() error {
	s.Reset()
	s.authed = false
	return nil
}

func (s *session) Mail(from string, opts *smtp.MailOptions) error {
	if !s.authed {
		return smtp.ErrAuthRequired
	}
	s.Reset()
	s.from = from
	return nil
}

// Rcpt resolves each recipient against the relay right away, so the
// submitting client learns per-recipient problems before sending the body.
func (s *session) Rcpt(to string, opts *smtp.RcptOptions) error {
	if !s.authed {
		return smtp.ErrAuthRequired
	}
	if to == "" {
		return &smtp.SMTPError{Code: 501, EnhancedCode: smtp.NoEnhancedCode, Message: "empty recipient"}
	}
	for _, r := range s.rcpts {
		if strings.EqualFold(r.addr, to) {
			return nil // duplicate RCPT: deliver once
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
	defer cancel()
	prof, found, err := s.opts.Relay.LookupProfile(ctx, to)
	if err != nil {
		// Safety rule: a temporary lookup failure (5xx/network) must never be
		// misrouted to classic SMTP — that would deliver an LM-only letter in
		// plaintext. 451 tells the sender to retry later.
		return tempErr("recipient lookup temporarily failed")
	}
	if !found && s.opts.Upstream == nil {
		return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.NoEnhancedCode,
			Message: "not an LM account and no classic upstream configured"}
	}
	if found {
		s.rcpts = append(s.rcpts, rcpt{addr: to, prof: prof})
	} else {
		s.rcpts = append(s.rcpts, rcpt{addr: to})
	}
	return nil
}

func (s *session) Data(r io.Reader) error {
	if !s.authed {
		return smtp.ErrAuthRequired
	}
	if len(s.rcpts) == 0 {
		return &smtp.SMTPError{Code: 503, EnhancedCode: smtp.NoEnhancedCode, Message: "no recipients"}
	}
	raw, err := io.ReadAll(r) // server caps this at MaxMessageBytes
	if err != nil {
		// includes the size-limit error: permanent, retrying changes nothing
		return &smtp.SMTPError{Code: 552, EnhancedCode: smtp.NoEnhancedCode, Message: "message too large or unreadable"}
	}
	parsed, err := parseMail(raw)
	if err != nil {
		return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.NoEnhancedCode, Message: "malformed message: " + err.Error()}
	}

	var lm, classic []rcpt
	for _, r := range s.rcpts {
		if r.prof != nil {
			lm = append(lm, r)
		} else {
			classic = append(classic, r)
		}
	}

	// The LM payload keeps the ORIGINAL addressing in headers (send.ts schema:
	// subject/body/headers/attachments), so LM recipients see who else got it.
	// Canonical keys "To"/"Cc" match the PWA/desktop fan-out writers.
	lmHeaders := map[string]string{}
	if parsed.From != "" {
		lmHeaders["from"] = parsed.From
	}
	if parsed.To != "" {
		lmHeaders["To"] = parsed.To
	}
	if parsed.Cc != "" {
		lmHeaders["Cc"] = parsed.Cc
	}
	if d := parsed.Header.Get("Date"); d != "" {
		lmHeaders["date"] = d
	}

	ctx, cancel := context.WithTimeout(context.Background(), dataTimeout)
	defer cancel()

	// LM first: if the relay hop fails after a classic forward already went
	// out, a sender retry duplicates the classic copy — accepted in B1 (no
	// dedup store); per-recipient LMTP statuses are out of scope.
	msg := &relayclient.Message{
		Subject:     parsed.Subject,
		Body:        parsed.Body,
		Headers:     lmHeaders,
		Attachments: parsed.Attachments,
	}
	for _, r := range lm {
		if _, err := s.opts.Relay.SendMessage(ctx, r.addr, r.prof, msg); err != nil {
			return relaySMTPError(err)
		}
	}

	if len(classic) > 0 {
		out := raw
		tos := make([]string, 0, len(classic))
		for _, r := range classic {
			tos = append(tos, r.addr)
		}
		if len(lm) > 0 {
			// mixed delivery: strip LM-only addresses from the classic copy
			lmSet := make(map[string]bool, len(lm))
			for _, r := range lm {
				lmSet[strings.ToLower(r.addr)] = true
			}
			if out, err = classicCopy(raw, parsed, lmSet, tos, s.opts.ReplyTo); err != nil {
				return tempErr("building classic copy: " + err.Error())
			}
		}
		if err := s.opts.Upstream.Forward(ctx, s.from, tos, out); err != nil {
			return tempErr("upstream delivery temporarily failed")
		}
	}
	return nil
}

func tempErr(msg string) *smtp.SMTPError {
	return &smtp.SMTPError{Code: 451, EnhancedCode: smtp.NoEnhancedCode, Message: msg}
}

// relaySMTPError maps relay failures to SMTP codes: temporary relay states
// (5xx/402/429) and network errors become 4xx (sender retries); everything
// else is a permanent 5xx.
func relaySMTPError(err error) *smtp.SMTPError {
	var re *relayclient.RelayError
	if errors.As(err, &re) && !re.Temporary() {
		return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.NoEnhancedCode,
			Message: "relay rejected the letter: " + re.Error()}
	}
	return tempErr("relay temporarily unavailable")
}
