// Package config loads and validates the lmbridge YAML configuration.
// Validation is fail-closed: incomplete or inconsistent settings are rejected
// at startup instead of silently degrading delivery later.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/lightningmail/lm1/crypto"
	"gopkg.in/yaml.v3"
)

// TLS modes for the upstream SMTP hop.
const (
	TLSNone     = "none"
	TLSStartTLS = "starttls"
	TLSImplicit = "tls"
)

// BridgeAuth are the credentials SMTP clients must present (AUTH is mandatory).
type BridgeAuth struct {
	User     string `yaml:"user"`
	PassFile string `yaml:"pass_file"`
}

// UpstreamSMTP is the classic mail relay used for non-LM recipients.
type UpstreamSMTP struct {
	Host        string `yaml:"host"`
	Port        int    `yaml:"port"`
	User        string `yaml:"user"`
	PassFile    string `yaml:"pass_file"`
	FromAddress string `yaml:"from_address"`
	TLSMode     string `yaml:"tls_mode"`
}

// Config is the lmbridge YAML schema.
type Config struct {
	RelayURL    string `yaml:"relay_url"`
	Account     string `yaml:"account"`
	KeyFile     string `yaml:"key_file"`
	KeyPassFile string `yaml:"key_pass_file"`
	SMTPListen  string `yaml:"smtp_listen"`
	// IMAPListen optionally enables the LM-IMAP server (Etappe B2). When set,
	// state_dir must point at a writable directory for the SQLite cache.
	IMAPListen string `yaml:"imap_listen"`
	StateDir   string `yaml:"state_dir"`
	// PollInterval is the relay poll cadence of the IMAP syncer (default 15s).
	PollInterval time.Duration `yaml:"poll_interval"`
	TLSCert      string        `yaml:"tls_cert"`
	TLSKey       string        `yaml:"tls_key"`

	BridgeAuth BridgeAuth `yaml:"bridge_auth"`
	// UpstreamSMTP is optional: a pure-LM bridge runs without classic delivery.
	UpstreamSMTP *UpstreamSMTP `yaml:"upstream_smtp"`
}

// ReadPassFile reads a secret file and strips exactly one trailing newline.
// Inner whitespace is significant and preserved.
func ReadPassFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("pass file: %w", err)
	}
	s := strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r")
	if s == "" {
		return "", fmt.Errorf("pass file %q is empty", path)
	}
	return s, nil
}

// Load reads the YAML config at path and validates it strictly.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	// Typos in field names must never be ignored silently.
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) validate() error {
	u, err := url.Parse(c.RelayURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("relay_url must be a valid http(s) URL, got %q", c.RelayURL)
	}
	if c.Account == "" {
		return errors.New("account is required")
	}
	keyBytes, err := os.ReadFile(c.KeyFile)
	if err != nil {
		return fmt.Errorf("key_file: %w", err)
	}
	if crypto.IsWrapped(string(keyBytes)) && c.KeyPassFile == "" {
		return errors.New("key_file is a wrapped LMKEY file but key_pass_file is not set")
	}
	if c.KeyPassFile != "" {
		if _, err := ReadPassFile(c.KeyPassFile); err != nil {
			return fmt.Errorf("key_pass_file: %w", err)
		}
	}
	host, port, err := net.SplitHostPort(c.SMTPListen)
	if err != nil || host == "" || port == "" {
		return fmt.Errorf("smtp_listen must be host:port, got %q", c.SMTPListen)
	}
	if c.IMAPListen != "" {
		host, port, err := net.SplitHostPort(c.IMAPListen)
		if err != nil || host == "" || port == "" {
			return fmt.Errorf("imap_listen must be host:port, got %q", c.IMAPListen)
		}
		if c.StateDir == "" {
			return errors.New("state_dir is required when imap_listen is set")
		}
	}
	if c.PollInterval == 0 {
		c.PollInterval = 15 * time.Second
	} else if c.PollInterval < time.Second {
		return fmt.Errorf("poll_interval must be at least 1s, got %s", c.PollInterval)
	}
	if (c.TLSCert == "") != (c.TLSKey == "") {
		return errors.New("tls_cert and tls_key must both be set or both empty")
	}
	if c.TLSCert != "" {
		for _, p := range []string{c.TLSCert, c.TLSKey} {
			if _, err := os.Stat(p); err != nil {
				return fmt.Errorf("tls file: %w", err)
			}
		}
	}
	if c.BridgeAuth.User == "" {
		return errors.New("bridge_auth.user is required (SMTP AUTH is mandatory)")
	}
	if _, err := ReadPassFile(c.BridgeAuth.PassFile); err != nil {
		return fmt.Errorf("bridge_auth.pass_file: %w", err)
	}
	if up := c.UpstreamSMTP; up != nil {
		if up.Host == "" || up.Port < 1 || up.Port > 65535 {
			return fmt.Errorf("upstream_smtp needs a host and port 1..65535, got %q:%d", up.Host, up.Port)
		}
		switch up.TLSMode {
		case "", TLSNone, TLSStartTLS, TLSImplicit:
		default:
			return fmt.Errorf("upstream_smtp.tls_mode must be none|starttls|tls, got %q", up.TLSMode)
		}
		if (up.TLSMode == "" || up.TLSMode == TLSNone) && up.User != "" {
			h := strings.ToLower(strings.TrimSpace(up.Host))
			ip := net.ParseIP(h)
			if h != "localhost" && (ip == nil || !ip.IsLoopback()) {
				return fmt.Errorf("upstream_smtp: refusing plaintext AUTH to non-loopback host %q (set tls_mode: starttls or tls)", up.Host)
			}
		}
		if up.PassFile != "" {
			if _, err := ReadPassFile(up.PassFile); err != nil {
				return fmt.Errorf("upstream_smtp.pass_file: %w", err)
			}
		}
	}
	return nil
}

// KeyPass returns the keyfile passphrase (empty for a bare PEM key file).
func (c *Config) KeyPass() (string, error) {
	if c.KeyPassFile == "" {
		return "", nil
	}
	return ReadPassFile(c.KeyPassFile)
}
