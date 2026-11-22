package core

import (
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	lm1crypto "github.com/lightningmail/lm1/crypto"
)

func TestHardenBestEffort(t *testing.T) {
	issues := Harden() // must never abort, root or not
	var r syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_CORE, &r); err != nil {
		t.Skipf("getrlimit unsupported: %v", err)
	}
	if r.Cur != 0 {
		for _, i := range issues {
			t.Logf("hygiene issue: %v", i)
		}
		t.Fatalf("core dumps still enabled: cur=%d", r.Cur)
	}
	t.Logf("core dumps off; mlock: %v", issues)
}

func TestLoadKeyFileFormats(t *testing.T) {
	// bare PEM
	priv, err := lm1crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pemBytes, err := lm1crypto.PrivatePEM(priv)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "bernd.key")
	write := func(content string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(string(pemBytes))
	if _, err := LoadKeyFile(path, ""); err != nil {
		t.Fatalf("bare PEM: %v", err)
	}

	// LMKEY2 wrap
	w, err := lm1crypto.WrapKey(string(pemBytes), "sichere-passage-42")
	if err != nil {
		t.Fatal(err)
	}
	write(w)
	if _, err := LoadKeyFile(path, "sichere-passage-42"); err != nil {
		t.Fatalf("V2: %v", err)
	}
	if _, err := LoadKeyFile(path, "falsche-passage-1"); err == nil {
		t.Fatal("V2 wrong passphrase accepted")
	}

	// LMKEY1 golden fixture (noble-generated) must load via Go
	raw, err := os.ReadFile(filepath.Join("testdata", "m-sec-golden.json"))
	if err != nil {
		t.Skip("golden fixture missing — run client/test/m-sec-golden.mts")
	}
	var g struct {
		Unwrap []struct {
			Name       string
			Line       string
			Passphrase string `json:"passphrase"`
		}
	}
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatal(err)
	}
	for _, c := range g.Unwrap {
		write(c.Line)
		if _, err := LoadKeyFile(path, c.Passphrase); err != nil {
			t.Fatalf("golden %s: %v", c.Name, err)
		}
	}
}
