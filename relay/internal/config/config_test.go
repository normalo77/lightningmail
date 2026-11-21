package config

import (
	"errors"
	"strings"
	"testing"
)

func TestRelayConfigValid(t *testing.T) {
	c, err := LoadConfigFile("testdata/relay.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if c.Name != "alpha" || len(c.Peers) != 1 || c.Peers[0].Name != "beta" {
		t.Fatalf("parse mismatch: %+v", c)
	}
	if c.Postage.ForeignSats != 10 || c.Postage.MinSats != 1 {
		t.Fatalf("postage: %+v", c.Postage)
	}
	if c.Postage.BlobMaxBytes != DefaultBlobMaxBytes {
		t.Fatalf("blob default not applied: %d", c.Postage.BlobMaxBytes)
	}
}

func TestLNDNetwork(t *testing.T) {
	yaml := func(mac, network string) []byte {
		s := "name: alpha\nlisten_addr: 127.0.0.1:8443\ndata_dir: /var/lib/bmail\nlnd:\n" +
			"  rpc_host: 127.0.0.1:8080\n  tls_cert_path: /lnd/tls.cert\n  macaroon_path: " + mac + "\n"
		if network != "" {
			s += "  network: " + network + "\n"
		}
		return []byte(s + "postage: {foreign_sats: 10, min_sats: 1}\n")
	}
	// Auto-Detect aus dem Macaroon-Pfad
	for mac, want := range map[string]string{
		"/lnd/data/chain/bitcoin/mainnet/admin.macaroon": "mainnet",
		"/lnd/data/chain/bitcoin/testnet/admin.macaroon": "testnet",
		"/lnd/data/chain/bitcoin/regtest/admin.macaroon": "regtest",
		"/x/admin.macaroon": "regtest",
	} {
		c, err := ParseConfig(yaml(mac, ""))
		if err != nil {
			t.Fatal(err)
		}
		if c.LND.Network != want {
			t.Fatalf("mac %s: want %s, got %s", mac, want, c.LND.Network)
		}
	}
	// Explizites network gewinnt ueber Auto-Detect
	c, err := ParseConfig(yaml("/lnd/data/chain/bitcoin/mainnet/admin.macaroon", "signet"))
	if err != nil {
		t.Fatal(err)
	}
	if c.LND.Network != "signet" {
		t.Fatalf("explicit network not honored: %s", c.LND.Network)
	}
	// Ungueltiges network -> ErrValidation
	if _, err := ParseConfig(yaml("/x/admin.macaroon", "litecoin")); !errors.Is(err, ErrValidation) {
		t.Fatalf("want ErrValidation for bad network, got %v", err)
	}
}

func TestRelayConfigBad(t *testing.T) {
	_, err := LoadConfigFile("testdata/relay_bad.yaml")
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("want ErrValidation, got %v", err)
	}
	msg := err.Error()
	for _, want := range []string{
		"missing required field: name",
		"foreign_sats must be > 0",
		"min_sats must be <= foreign_sats",
		"peers[0].node_pubkey",
		"peers[0].url",
		"duplicate",
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("error must mention %q, got: %s", want, msg)
		}
	}
}

func TestDiscoveryValidAndLookup(t *testing.T) {
	d, err := LoadDiscoveryFile("testdata/relays.yaml")
	if err != nil {
		t.Fatal(err)
	}
	r, err := d.Lookup("BMAIL.DE") // case-insensitive lookup
	if err != nil {
		t.Fatal(err)
	}
	if r.Node == "" || !strings.HasPrefix(r.Relay, "https://") {
		t.Fatalf("record: %+v", r)
	}
	if _, err := d.Lookup("unknown.tld"); err == nil {
		t.Fatal("unknown domain must not resolve")
	}
}

func TestDiscoveryBad(t *testing.T) {
	_, err := LoadDiscoveryFile("testdata/relays_bad.yaml")
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("want ErrValidation, got %v", err)
	}
	msg := err.Error()
	for _, want := range []string{"schema must be", "duplicate", "not hex"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("error must mention %q, got: %s", want, msg)
		}
	}
}

func TestURLSchemeRules(t *testing.T) {
	// http on localhost fine (regtest dev), http elsewhere not.
	if err := validURL("http://localhost:8443"); err != nil {
		t.Fatal(err)
	}
	if err := validURL("http://127.0.0.1:9443"); err != nil {
		t.Fatal(err)
	}
	if err := validURL("http://evil.example"); err == nil {
		t.Fatal("plain http to remote host accepted")
	}
	if err := validURL("https://x.onion"); err != nil {
		t.Fatal(err)
	}
}

func TestPubkeyValidation(t *testing.T) {
	// genesis compressed key: valid on-curve point
	if err := validPubkeyHex("03678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb6"); err != nil {
		t.Fatal(err)
	}
	// x = genesis-x + 1: no square root for y^2=x^3+7 -> not a curve point
	if err := validPubkeyHex("02678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb7"); err == nil {
		t.Fatal("off-curve pubkey accepted")
	}
	if err := validPubkeyHex(strings.Repeat("ab", 32)); err == nil {
		t.Fatal("32-byte key accepted")
	}
}

func TestDriveConfig(t *testing.T) {
	base := "name: alpha\nlisten_addr: 127.0.0.1:8443\ndata_dir: /var/lib/bmail\nlnd:\n" +
		"  rpc_host: 127.0.0.1:8080\n  tls_cert_path: /lnd/tls.cert\n  macaroon_path: /x/admin.macaroon\n" +
		"postage: {foreign_sats: 10, min_sats: 1}\n"
	// Default: Sektion ungesetzt → QuotaMB 5120, disabled, keine Tiers
	c, err := ParseConfig([]byte(base))
	if err != nil {
		t.Fatal(err)
	}
	if c.Drive.QuotaMB != DefaultDriveQuotaMB || c.Drive.Enabled || len(c.Drive.Tiers) != 0 {
		t.Fatalf("drive default: %+v", c.Drive)
	}
	// Explizit: enabled, quota, tiers
	c, err = ParseConfig([]byte(base + "drive:\n  enabled: true\n  quota_mb: 2048\n  tiers:\n    - {gb: 5, sats: 5000}\n    - {gb: 50, sats: 40000}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !c.Drive.Enabled || c.Drive.QuotaMB != 2048 || len(c.Drive.Tiers) != 2 ||
		c.Drive.Tiers[0].GB != 5 || c.Drive.Tiers[0].Sats != 5000 || c.Drive.Tiers[1].GB != 50 {
		t.Fatalf("drive parse: %+v", c.Drive)
	}
	// Validierung: quota_mb<=0 und kaputte Tiers sammeln Fehler
	_, err = ParseConfig([]byte(base + "drive:\n  quota_mb: -5\n  tiers:\n    - {gb: 0, sats: 10}\n    - {gb: 5, sats: 0}\n"))
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("want ErrValidation, got %v", err)
	}
	for _, want := range []string{"drive.quota_mb must be > 0", "drive.tiers[0].gb must be > 0", "drive.tiers[1].sats must be > 0"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error must mention %q, got: %s", want, err)
		}
	}
}
