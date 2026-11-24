package config

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestExampleConfigLoads guards bridge.yaml.example: Load uses KnownFields,
// so any schema drift or validation slip in the shipped example fails here.
func TestExampleConfigLoads(t *testing.T) {
	raw, err := os.ReadFile("../../bridge.yaml.example")
	if err != nil {
		t.Fatalf("read example: %v", err)
	}
	tmp := t.TempDir()
	for _, name := range []string{"lm.key", "key.pass", "bridge.pass", "upstream.pass"} {
		if err := os.WriteFile(filepath.Join(tmp, name), []byte("dummy\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// The example uses the container paths from the compose layout; point
	// them at the temp dir with dummy secret files instead.
	raw = bytes.ReplaceAll(raw, []byte("/secrets/"), []byte(tmp+"/"))
	raw = bytes.ReplaceAll(raw, []byte("/var/lib/lmbridge"), []byte(tmp))
	p := filepath.Join(tmp, "bridge.yaml")
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("bridge.yaml.example does not load: %v", err)
	}
	// The example should exercise the full IMAP + upstream surface.
	if cfg.IMAPListen == "" || cfg.StateDir != tmp {
		t.Errorf("example must enable the IMAP side, got imap=%q state_dir=%q", cfg.IMAPListen, cfg.StateDir)
	}
	if cfg.UpstreamSMTP == nil || cfg.UpstreamSMTP.FromAddress == "" {
		t.Error("example must exercise upstream_smtp incl. from_address (Reply-To stamping)")
	}
}
