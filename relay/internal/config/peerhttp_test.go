package config

import "testing"

func TestPeerURLBareOnionGets8443(t *testing.T) {
	c := &Config{}
	c.Tor.Socks5 = "127.0.0.1:9050"
	https := "https://r.example.org"
	onion := "5duvftqj3rqjhuyjldswnhpnx37vy47qgduj4aavv3zo2bg4b4w4mxid.onion" // echter v3-host (56 base32)
	if got := c.PeerURL(https, onion); got != "http://"+onion+":8443" {
		t.Errorf("bare onion: got %q", got)
	}
	if got := c.PeerURL(https, onion+":9999"); got != "http://"+onion+":9999" {
		t.Errorf("explicit port: got %q", got)
	}
	if got := c.PeerURL(https, "http://"+onion+":8443"); got != "http://"+onion+":8443" {
		t.Errorf("scheme form: got %q", got)
	}
	if got := c.PeerURL(https, "bogus.onion"); got != https {
		t.Errorf("invalid onion must fall back to https, got %q", got)
	}
	c2 := &Config{} // tor disabled
	if got := c2.PeerURL(https, onion); got != https {
		t.Errorf("tor off: got %q", got)
	}
}
