// Etappe T: peer HTTP transport (Etappe-T operational layer). Relay-to-relay
// calls (profile loop, receipt mirror, blob mirror) share one http.Client;
// when tor.socks5 is configured the client dials through the SOCKS5 endpoint,
// which makes *.onion peer URLs work (Go resolves them remotely over SOCKS5).
// https stays the fallback: nothing in the protocol changes.
package config

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ParseTorSocks normalizes and validates a SOCKS5 host:port endpoint so
// malformed tor.socks5 configs fail closed instead of leaking to clearnet.
func ParseTorSocks(raw string) (*url.URL, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil, nil
	}
	s = strings.TrimPrefix(s, "socks5h://")
	s = strings.TrimPrefix(s, "socks5://")
	host, port, err := net.SplitHostPort(s)
	if err != nil || host == "" {
		return nil, fmt.Errorf("expected host:port (e.g. 127.0.0.1:9050)")
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return nil, fmt.Errorf("invalid port %q", port)
	}
	return &url.URL{Scheme: "socks5h", Host: net.JoinHostPort(host, port)}, nil
}

type peerTransport struct {
	mu       sync.Mutex
	base     *http.Transport
	socks5At string
}

var peerMu sync.Map // *Config -> *peerTransport (instances are unique per process)

// PeerHTTP returns a client for relay-to-relay traffic honoring tor.socks5.
// Invalid tor.socks5 fails closed instead of silently dialing clearnet.
func (c *Config) PeerHTTP(timeout time.Duration) *http.Client {
	v, _ := peerMu.LoadOrStore(c, &peerTransport{})
	pt := v.(*peerTransport)
	pt.mu.Lock()
	defer pt.mu.Unlock()
	if pt.base == nil || pt.socks5At != c.Tor.Socks5 {
		tr := &http.Transport{}
		if strings.TrimSpace(c.Tor.Socks5) != "" {
			pu, err := ParseTorSocks(c.Tor.Socks5)
			if err != nil {
				bad := c.Tor.Socks5
				tr.DialContext = func(context.Context, string, string) (net.Conn, error) {
					return nil, fmt.Errorf("tor.socks5 %q invalid: %w", bad, err)
				}
			} else {
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
		// relayd speaks plain HTTP behind the hidden service. Convention:
		// a bare onion host without port means the standard :8443, exactly
		// like the https peers it replaces.
		if !strings.Contains(onion[strings.LastIndex(onion, "/")+1:], ":") {
			return "http://" + onion + ":8443"
		}
		return "http://" + onion
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
	if i := strings.LastIndex(host, ":"); i > 0 && !strings.Contains(host[i:], ".") {
		host = host[:i] // bare form: host:port without scheme
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
