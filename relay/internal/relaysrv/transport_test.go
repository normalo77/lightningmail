package relaysrv

import (
	"os"
	"testing"

	"github.com/lightningmail/relay/internal/config"
)

// relayTransportKey: persistence roundtrip — second call loads the same key.
func TestRelayTransportKeyRoundtrip(t *testing.T) {
	dir := t.TempDir()
	s1 := &Server{cfg: &config.Config{DataDir: dir}}
	k1, err := s1.relayTransportKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir + "/relay_transport.key"); err != nil {
		t.Fatal("key not persisted:", err)
	}
	s2 := &Server{cfg: &config.Config{DataDir: dir}} // simulates a restart
	k2, err := s2.relayTransportKey()
	if err != nil {
		t.Fatal(err)
	}
	if k1.Key != k2.Key {
		t.Fatal("reloaded key differs from generated key")
	}
}
