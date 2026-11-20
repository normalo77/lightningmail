// Dynamische Relay-Discovery (CONCEPT §4.2): _bmail._tcp.<domain> TXT-Record
// "v=bmail1; relay=https://…; node=<66-hex>" — konfigurierte Peers gewinnen,
// DNS-Ergebnisse werden 5 Minuten gecacht.
package relaysrv

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/lightningmail/relay/internal/config"
	"github.com/lightningmail/relay/internal/crypto"
)

const dnsCacheTTL = 5 * time.Minute

type dnsEntry struct {
	relay, node string
	at          time.Time
}

// lookupPeer findet einen konfigurierten Peer per Name oder URL-Hostname.
func (s *Server) lookupPeer(domain string) *config.Peer {
	for i := range s.cfg.Peers {
		p := &s.cfg.Peers[i]
		if strings.EqualFold(p.Name, domain) {
			return p
		}
		if u, err := url.Parse(p.URL); err == nil && strings.EqualFold(u.Hostname(), domain) {
			return p
		}
	}
	return nil
}

// resolveDomainRelay: Domain → (relayURL, nodePubkey). Erst Peers, dann DNS.
func (s *Server) resolveDomainRelay(ctx context.Context, domain string) (string, string, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return "", "", errors.New("dns: empty domain")
	}
	if p := s.lookupPeer(domain); p != nil {
		return p.URL, p.NodePubkey, nil
	}
	s.dnsMu.Lock()
	if e, ok := s.dns[domain]; ok && time.Since(e.at) < dnsCacheTTL {
		s.dnsMu.Unlock()
		return e.relay, e.node, nil
	}
	s.dnsMu.Unlock()

	txts, err := net.DefaultResolver.LookupTXT(ctx, "_bmail._tcp."+domain)
	if err != nil {
		return "", "", fmt.Errorf("dns: %w", err)
	}
	var lastErr error
	for _, txt := range txts {
		relay, node, err := parseBmailTXT(txt)
		if err != nil {
			lastErr = err
			continue
		}
		if err := verifyPublicRelayURL(ctx, relay); err != nil {
			lastErr = err
			continue
		}
		s.dnsMu.Lock()
		s.dns[domain] = dnsEntry{relay: relay, node: node, at: time.Now()}
		s.dnsMu.Unlock()
		return relay, node, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no _bmail._tcp TXT record")
	}
	return "", "", fmt.Errorf("dns: %s: %w", domain, lastErr)
}

// parseBmailTXT parst "v=bmail1; relay=https://…; node=<33B komprimiert hex>".
func parseBmailTXT(txt string) (relay, node string, err error) {
	kv := map[string]string{}
	for _, part := range strings.Split(txt, ";") {
		k, v, ok := strings.Cut(part, "=")
		if ok {
			kv[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
		}
	}
	if kv["v"] != config.DiscoverySchema { // "bmail1"
		return "", "", fmt.Errorf("unsupported version %q", kv["v"])
	}
	relay, node = kv["relay"], kv["node"]
	// Öffentliche DNS-Records dürfen ausschließlich https:// auf öffentliche Hosts nutzen
	// (lokale Dev-Relays stehen in relay.yaml unter peers, niemals im öffentlichen DNS -> SSRF-Schutz).
	u, uerr := url.Parse(relay)
	if uerr != nil || u.Scheme != "https" || u.Hostname() == "" || strings.EqualFold(u.Hostname(), "localhost") {
		return "", "", fmt.Errorf("bad relay url %q (https on public host required)", relay)
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return "", "", fmt.Errorf("ssrf blocked: private/loopback IP in relay url %q", relay)
		}
	}
	raw, err := hex.DecodeString(node)
	if err != nil || len(raw) != 33 {
		return "", "", fmt.Errorf("bad node pubkey %q", node)
	}
	if _, err := crypto.ParsePubKey(raw); err != nil {
		return "", "", fmt.Errorf("bad node pubkey: %w", err)
	}
	return relay, node, nil
}

// verifyPublicRelayURL prüft nach DNS-Auflösung, dass der Ziel-Hostname auf keine
// private, Loopback- oder Link-Local-IP auflöst (DNS-Rebinding-/SSRF-Schutz).
func verifyPublicRelayURL(ctx context.Context, relayURL string) error {
	u, err := url.Parse(relayURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return fmt.Errorf("ssrf: non-https relay %q", relayURL)
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, u.Hostname())
	if err != nil || len(ips) == 0 {
		return fmt.Errorf("ssrf: cannot resolve %q", u.Hostname())
	}
	for _, a := range ips {
		ip := a.IP
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return fmt.Errorf("ssrf: blocked private/loopback address %s for %s", ip.String(), u.Hostname())
		}
	}
	return nil
}
