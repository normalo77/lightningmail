package relaysrv

import (
	"context"
	"testing"

	"github.com/lightningmail/relay/internal/config"
)

// gültiger komprimierter secp256k1-Pubkey (Generator-Punkt)
const testNodeKey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

func TestParseBmailTXT(t *testing.T) {
	valid := []struct{ name, txt, relay string }{
		{"standard", "v=bmail1; relay=https://relay.example.com; node=" + testNodeKey, "https://relay.example.com"},
		{"localhost-http", "v=bmail1; relay=http://localhost:8082; node=" + testNodeKey, "http://localhost:8082"},
		{"loopback-http", "v=bmail1;relay=http://127.0.0.1:8082;node=" + testNodeKey, "http://127.0.0.1:8082"},
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

// Konfigurierte Peers gewinnen vor DNS (kein Lookup, sofort Peer-URL).
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
