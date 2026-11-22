// Etappe T: peer HTTP transport (Etappe-T operational layer). Relay-to-relay
// calls (profile loop, receipt mirror, blob mirror) share one http.Client;
// when tor.socks5 is configured the client dials through the SOCKS5 endpoint,
// which makes *.onion peer URLs work (Go resolves them remotely over SOCKS5).
// https stays the fallback: nothing in the protocol changes.
package config

import (
	"net/http"
	"net/url"
	"sync"
	"time"
)

type peerTransport struct {
	mu       sync.Mutex
	base     *http.Transport
	socks5At string
}

var peerMu sync.Map // *Config -> *peerTransport (instances are unique per process)

// PeerHTTP returns a client for relay-to-relay traffic honoring tor.socks5.
// The transport (connection pool) is shared across calls; it is rebuilt when
// the socks endpoint string changes (config reload / restart normally covers
// that).
func (c *Config) PeerHTTP(timeout time.Duration) *http.Client {
	v, _ := peerMu.LoadOrStore(c, &peerTransport{})
	pt := v.(*peerTransport)
	pt.mu.Lock()
	defer pt.mu.Unlock()
	if pt.base == nil || pt.socks5At != c.Tor.Socks5 {
		tr := &http.Transport{}
		if c.Tor.Socks5 != "" {
			if pu, err := url.Parse("socks5://" + c.Tor.Socks5); err == nil {
				tr.Proxy = http.ProxyURL(pu)
			}
		}
		pt.base, pt.socks5At = tr, c.Tor.Socks5
	}
	return &http.Client{Timeout: timeout, Transport: pt.base}
}

// PeerURL picks the onion or the https URL for a resolved domain relay
// (Etappe T §33): onion wins only when tor.socks5 is configured and the
// onion string is a valid v3 address.
func (c *Config) PeerURL(relayHTTPS, onion string) string {
	if c.Tor.Socks5 == "" || !ValidOnionHost(onion) {
		return relayHTTPS
	}
	if !hasScheme(onion) {
		return "http://" + onion // relayd speaks plain HTTP behind the hidden service
	}
	return onion
}

// ValidOnionHost accepts a bare v3 onion host (56 base32 chars + .onion),
// optionally with scheme (only for PeerURL pass-through checks).
func ValidOnionHost(s string) bool {
	host := s
	if hasScheme(s) {
		u, err := url.Parse(s)
		if err != nil {
			return false
		}
		host = u.Hostname()
	}
	if len(host) < len(".onion") || host[len(host)-6:] != ".onion" {
		return false
	}
	b32 := host[:len(host)-6]
	if len(b32) != 56 {
		return false
	}
	const alpha = "abcdefghijklmnopqrstuvwxyz234567"
	for _, ch := range b32 {
		if !contains(alpha, ch) {
			return false
		}
	}
	return true
}

func hasScheme(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme != ""
}

func contains(set string, ch rune) bool {
	for _, s := range set {
		if s == ch {
			return true
		}
	}
	return false
}
