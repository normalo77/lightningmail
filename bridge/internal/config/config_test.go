package config

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lightningmail/lm1/crypto"
)

// randToken avoids literal secret patterns in the repo; every run gets fresh
// throwaway credentials.
func randToken(t *testing.T) string {
	t.Helper()
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// setup writes a minimal valid config tree and returns the config path plus a
// mutate hook input (the raw YAML) for negative cases.
func setup(t *testing.T, mutate func(yaml string) string) string {
	t.Helper()
	dir := t.TempDir()

	priv, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pemBytes, err := crypto.PrivatePEM(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(dir, "bridge.key")
	if err := os.WriteFile(keyFile, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	passFile := filepath.Join(dir, "smtp.pass")
	if err := os.WriteFile(passFile, []byte(randToken(t)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	yaml := "relay_url: http://127.0.0.1:8443\n" +
		"account: bridgebot\n" +
		"key_file: " + keyFile + "\n" +
		"smtp_listen: 127.0.0.1:2525\n" +
		"bridge_auth:\n" +
		"  user: bridge\n" +
		"  pass_file: " + passFile + "\n"
	if mutate != nil {
		yaml = mutate(yaml)
	}
	cfgFile := filepath.Join(dir, "bridge.yaml")
	if err := os.WriteFile(cfgFile, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgFile
}

func TestLoadValid(t *testing.T) {
	cfg, err := Load(setup(t, nil))
	if err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if cfg.Account != "bridgebot" || cfg.BridgeAuth.User != "bridge" {
		t.Fatalf("unexpected config: %+v", cfg)
	}
	if cfg.UpstreamSMTP != nil {
		t.Fatal("upstream_smtp must stay nil when absent")
	}
	pass, err := cfg.KeyPass()
	if err != nil || pass != "" {
		t.Fatalf("bare PEM key must need no passphrase, got %q %v", pass, err)
	}
}

func TestLoadValidWithUpstream(t *testing.T) {
	cfg := setup(t, func(y string) string {
		return y + "upstream_smtp:\n  host: smtp.upstream.test\n  port: 587\n  from_address: bridge@upstream.test\n  tls_mode: starttls\n"
	})
	c, err := Load(cfg)
	if err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if c.UpstreamSMTP == nil || c.UpstreamSMTP.Host != "smtp.upstream.test" || c.UpstreamSMTP.Port != 587 {
		t.Fatalf("upstream not parsed: %+v", c.UpstreamSMTP)
	}
}

func TestLoadValidIMAP(t *testing.T) {
	dir := t.TempDir()
	// poll_interval omitted → 15s default
	cfg, err := Load(setup(t, func(y string) string {
		return y + "imap_listen: 127.0.0.1:2143\nstate_dir: " + dir + "\n"
	}))
	if err != nil {
		t.Fatalf("valid IMAP config rejected: %v", err)
	}
	if cfg.IMAPListen != "127.0.0.1:2143" || cfg.StateDir != dir {
		t.Fatalf("IMAP fields not parsed: %+v", cfg)
	}
	if cfg.PollInterval != 15*time.Second {
		t.Fatalf("poll_interval default = %s, want 15s", cfg.PollInterval)
	}
	// explicit poll_interval parses as a Go duration
	cfg, err = Load(setup(t, func(y string) string {
		return y + "imap_listen: 127.0.0.1:2143\nstate_dir: " + dir + "\npoll_interval: 30s\n"
	}))
	if err != nil {
		t.Fatalf("valid IMAP config with poll_interval rejected: %v", err)
	}
	if cfg.PollInterval != 30*time.Second {
		t.Fatalf("poll_interval = %s, want 30s", cfg.PollInterval)
	}
	// state_dir alone (no imap_listen) is allowed and leaves the server off
	cfg, err = Load(setup(t, func(y string) string { return y + "state_dir: " + dir + "\n" }))
	if err != nil || cfg.IMAPListen != "" {
		t.Fatalf("state_dir without imap_listen: %v %+v", err, cfg)
	}
}

func TestRejects(t *testing.T) {
	cases := map[string]func(string) string{
		"bad relay_url":                 func(y string) string { return strings.Replace(y, "http://127.0.0.1:8443", "ftp://x", 1) },
		"missing account":               func(y string) string { return strings.Replace(y, "account: bridgebot\n", "", 1) },
		"imap_listen without state_dir": func(y string) string { return y + "imap_listen: 127.0.0.1:2143\n" },
		"imap_listen bogus":             func(y string) string { return y + "imap_listen: bogus\nstate_dir: /tmp\n" },
		"poll_interval too small":       func(y string) string { return y + "poll_interval: 100ms\n" },
		"bad smtp_listen": func(y string) string {
			return strings.Replace(y, "smtp_listen: 127.0.0.1:2525", "smtp_listen: bogus", 1)
		},
		"tls_cert without key":  func(y string) string { return y + "tls_cert: /nonexistent/c.pem\n" },
		"missing bridge user":   func(y string) string { return strings.Replace(y, "  user: bridge\n", "", 1) },
		"unknown field":         func(y string) string { return y + "typo_field: 1\n" },
		"upstream bad port":     func(y string) string { return y + "upstream_smtp:\n  host: h\n  port: 99999\n" },
		"upstream bad tls_mode": func(y string) string { return y + "upstream_smtp:\n  host: h\n  port: 25\n  tls_mode: magic\n" },
		"missing key_file":      func(y string) string { return strings.Replace(y, "key_file: ", "key_file: /nonexistent/", 1) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(setup(t, mutate)); err == nil {
				t.Fatalf("config must be rejected (%s)", name)
			}
		})
	}
}

func TestWrappedKeyRequiresPassFile(t *testing.T) {
	dir := t.TempDir()
	priv, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pemBytes, err := crypto.PrivatePEM(priv)
	if err != nil {
		t.Fatal(err)
	}
	passphrase := randToken(t)
	wrapped, err := crypto.WrapKey(string(pemBytes), passphrase)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(dir, "bridge.lmkey")
	if err := os.WriteFile(keyFile, []byte(wrapped), 0o600); err != nil {
		t.Fatal(err)
	}
	smtpPass := filepath.Join(dir, "smtp.pass")
	if err := os.WriteFile(smtpPass, []byte(randToken(t)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	base := "relay_url: http://127.0.0.1:8443\n" +
		"account: bridgebot\n" +
		"key_file: " + keyFile + "\n" +
		"smtp_listen: 127.0.0.1:2525\n" +
		"bridge_auth:\n  user: bridge\n  pass_file: " + smtpPass + "\n"
	cfgFile := filepath.Join(dir, "bridge.yaml")
	if err := os.WriteFile(cfgFile, []byte(base), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(cfgFile); err == nil {
		t.Fatal("wrapped LMKEY file without key_pass_file must be rejected")
	}
	keyPass := filepath.Join(dir, "key.pass")
	if err := os.WriteFile(keyPass, []byte(passphrase+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgFile, []byte(base+"key_pass_file: "+keyPass+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(cfgFile); err != nil {
		t.Fatalf("wrapped key + pass file must load: %v", err)
	}
}

func TestReadPassFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "pw")
	if err := os.WriteFile(p, []byte(" keep inner spaces \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := ReadPassFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if s != " keep inner spaces " {
		t.Fatalf("got %q", s)
	}
	if err := os.WriteFile(p, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPassFile(p); err == nil {
		t.Fatal("empty pass file must be rejected")
	}
	if _, err := ReadPassFile(filepath.Join(dir, "nope")); err == nil {
		t.Fatal("missing pass file must be rejected")
	}
}
