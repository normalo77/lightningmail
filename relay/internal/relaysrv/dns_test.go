package relaysrv

import (
	"context"
	"testing"

	"github.com/lightningmail/relay/internal/config"
)

// valid compressed secp256k1 pubkey (generator point)
const testNodeKey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

func TestParseBmailTXT(t *testing.T) {
	valid := []struct{ name, txt, relay string }{
		{"standard", "v=bmail1; relay=https://relay.example.com; node=" + testNodeKey, "https://relay.example.com"},
		{"extra-fields", "v=bmail1; relay=https://r.example.com; onion=abc.onion; node=" + testNodeKey + "; policy=https://r.example.com/p.json", "https://r.example.com"},
	}
	for _, tc := range valid {
		relay, node, err := parseBmailTXT(tc.txt)
		if err != nil {
			t.Errorf("%s: unexpected error: %v", tc.name, err)
			continue
		}
		if relay != tc.relay || node != testNodeKey {
			t.Errorf("%s: got (%q,%q), want (%q,%q)", tc.name, relay, node, tc.relay, testNodeKey)
		}
	}

	invalid := []struct{ name, txt string }{
		{"wrong version", "v=bmail2; relay=https://r.example.com; node=" + testNodeKey},
		{"missing version", "relay=https://r.example.com; node=" + testNodeKey},
		{"plain http", "v=bmail1; relay=http://r.example.com; node=" + testNodeKey},
		{"ssrf localhost", "v=bmail1; relay=https://localhost:8443; node=" + testNodeKey},
		{"ssrf loopback", "v=bmail1; relay=https://127.0.0.1:8443; node=" + testNodeKey},
		{"ssrf private lan", "v=bmail1; relay=https://192.168.1.50:8443; node=" + testNodeKey},
		{"missing relay", "v=bmail1; node=" + testNodeKey},
		{"missing node", "v=bmail1; relay=https://r.example.com"},
		{"node not hex", "v=bmail1; relay=https://r.example.com; node=zz" + testNodeKey[2:]},
		{"node too short", "v=bmail1; relay=https://r.example.com; node=" + testNodeKey[:32]},
		{"node not on curve", "v=bmail1; relay=https://r.example.com; node=020000000000000000000000000000000000000000000000000000000000000000"},
		{"empty", ""},
	}
	for _, tc := range invalid {
		if _, _, err := parseBmailTXT(tc.txt); err == nil {
			t.Errorf("%s: expected error, got nil", tc.name)
		}
	}
}

// configured peers win over DNS (no lookup, peer URL immediately).
func TestResolveDomainRelayPeerMatch(t *testing.T) {
	s := &Server{cfg: &config.Config{Peers: []config.Peer{
		{Name: "peerb", URL: "http://relay-b.local:8082", NodePubkey: testNodeKey},
	}}, dns: map[string]dnsEntry{}}

	relay, node, err := s.resolveDomainRelay(context.Background(), "PeerB")
	if err != nil || relay != "http://relay-b.local:8082" || node != testNodeKey {
		t.Fatalf("by name: got (%q,%q,%v)", relay, node, err)
	}
	relay, node, err = s.resolveDomainRelay(context.Background(), "relay-b.local")
	if err != nil || relay != "http://relay-b.local:8082" || node != testNodeKey {
		t.Fatalf("by hostname: got (%q,%q,%v)", relay, node, err)
	}
	if _, _, err := s.resolveDomainRelay(context.Background(), ""); err == nil {
		t.Fatal("empty domain: expected error")
	}
}

// Etappe T: onion= field — ignored unless tor.socks5 is active (torEnabled),
// junk onion values must never break https discovery.
func TestParseBmailTXTOnion(t *testing.T) {
	v3 := "zkjevp5ldo5x72q7lnhrhxh2rwq3hxwjx5q6c2jfqvy5hck3zsdgsvqd.onion"
	txt := "v=bmail1; relay=https://r.example.com; onion=" + v3 + "; node=" + testNodeKey

	relay, node, err := parseBmailTXT(txt) // legacy signature: torEnabled=false
	if err != nil || relay != "https://r.example.com" || node != testNodeKey {
		t.Fatalf("legacy path changed: %q %q %v", relay, node, err)
	}

	r2, _, o2, err := parseBmailTXTFull(txt, false)
	if err != nil || o2 != "" || r2 != "https://r.example.com" {
		t.Fatalf("tor off: relay=%q onion=%q err=%v", r2, o2, err)
	}

	r3, _, o3, err := parseBmailTXTFull(txt, true)
	if err != nil || o3 != v3 {
		t.Fatalf("tor on: onion=%q err=%v", o3, err)
	}
	cfg := &config.Config{Tor: config.Tor{Socks5: "127.0.0.1:9050"}}
	if got := cfg.PeerURL(r3, o3); got != "http://"+v3 {
		t.Fatalf("PeerURL: %q", got)
	}
	cfgOff := &config.Config{}
	if got := cfgOff.PeerURL(r3, o3); got != r3 {
		t.Fatalf("PeerURL off: %q", got)
	}

	// junk onion values are silently dropped, TXT stays valid over https
	for _, bad := range []string{"abc.onion", "not.onion", "mzi@.onion", "v3zq…"} {
		j := "v=bmail1; relay=https://r.example.com; onion=" + bad + "; node=" + testNodeKey
		_, _, o, err := parseBmailTXTFull(j, true)
		if err != nil || o != "" {
			t.Fatalf("junk onion %q accepted: %q %v", bad, o, err)
		}
	}

	// SSRF stays closed: onion-only TXT with a private relay URL is still
	// dialed as the onion (chosen), the https field is never used — but the
	// parser must keep the localhost guard when no onion is present.
	if _, _, _, err := parseBmailTXTFull("v=bmail1; relay=https://127.0.0.1:8443; node="+testNodeKey, true); err == nil {
		t.Fatal("private relay url without onion must be rejected")
	}
	_ = context.Background()
}
