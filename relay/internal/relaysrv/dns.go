// Dynamic relay discovery (CONCEPT §4.2): _bmail._tcp.<domain> TXT record
// "v=bmail1; relay=https://…; node=<66-hex>[; onion=<v3-host>]" — configured
// peers win, DNS results are cached for 5 minutes. Etappe T: with a tor.socks5
// endpoint set, a valid onion field is preferred over the https URL.
package relaysrv

import (
	"log"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/lightningmail/lm1/crypto"
	"github.com/lightningmail/relay/internal/config"
)

const dnsCacheTTL = 5 * time.Minute

// isOnionURL reports whether a relay URL points at a .onion host.
func isOnionURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && strings.HasSuffix(strings.ToLower(u.Hostname()), ".onion")
}

type dnsEntry struct {
	relay, node string
	at          time.Time
}

// lookupPeer finds a configured peer by name or URL hostname.
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

// resolveDomainRelay: domain → (relayURL, nodePubkey). Peers first, then DNS.
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
		log.Printf("dns-discovery: LookupTXT %s: %v", domain, err)
		return "", "", fmt.Errorf("dns: %w", err)
	}
	var lastErr error
	for _, txt := range txts {
		relay, node, onion, err := parseBmailTXTFull(txt, s.cfg.Tor.Socks5 != "")
		if err != nil {
			lastErr = err
			continue
		}
		chosen := s.cfg.PeerURL(relay, onion)
		if !isOnionURL(chosen) {
			// plain https target: SSRF check as before Etappe T
			if err := verifyPublicRelayURL(ctx, chosen); err != nil {
				lastErr = err
				continue
			}
		} // onion: unresolvable locally by design — only dialable through
		// the configured SOCKS5, never a private LAN address.
		s.dnsMu.Lock()
		s.dns[domain] = dnsEntry{relay: chosen, node: node, at: time.Now()}
		s.dnsMu.Unlock()
		return chosen, node, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no _bmail._tcp TXT record")
	}
	log.Printf("dns-discovery: %s -> all TXT failed (lastErr: %v)", domain, lastErr)
	return "", "", fmt.Errorf("dns: %s: %w", domain, lastErr)
}

// parseBmailTXT parses "v=bmail1; relay=https://…; node=<33B compressed hex>"
// and the OPTIONAL Etappe T field onion=<v3-onion host or URL>. An invalid
// onion value is ignored (kept as "") — it must never break https discovery.
func parseBmailTXT(txt string) (relay, node string, err error) {
	relay, node, _, err = parseBmailTXTFull(txt, false)
	return relay, node, err
}

func parseBmailTXTFull(txt string, torEnabled bool) (relay, node, onion string, err error) {
	kv := map[string]string{}
	for _, part := range strings.Split(txt, ";") {
		k, v, ok := strings.Cut(part, "=")
		if ok {
			kv[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
		}
	}
	if kv["v"] != config.DiscoverySchema { // "bmail1"
		return "", "", "", fmt.Errorf("unsupported version %q", kv["v"])
	}
	relay, node = kv["relay"], kv["node"]
	onion = kv["onion"]
	if onion != "" && !config.ValidOnionHost(onion) {
		onion = "" // junk onion field: https-only, exactly like before T
	}
	if onion != "" && !torEnabled {
		onion = "" // no SOCKS endpoint configured: nothing can dial it
	}
	// Public DNS records must use https:// on public hosts (local dev relays
	// live in relay.yaml under peers, never in public DNS -> SSRF protection).
	// Exception (Etappe T): a valid onion alongside is a legitimate Tor-only
	// advertisement — but ONLY when a socks5 dialer exists AND the https
	// target is itself public or onion.
	u, uerr := url.Parse(relay)
	if uerr != nil || u.Hostname() == "" || strings.EqualFold(u.Hostname(), "localhost") {
		return "", "", "", fmt.Errorf("bad relay url %q (https on public host required)", relay)
	}
	if onion == "" {
		if u.Scheme != "https" {
			return "", "", "", fmt.Errorf("bad relay url %q (https on public host required)", relay)
		}
		if ip := net.ParseIP(u.Hostname()); ip != nil {
			if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
				return "", "", "", fmt.Errorf("ssrf blocked: private/loopback IP in relay url %q", relay)
			}
		}
	}
	raw, err := hex.DecodeString(node)
	if err != nil || len(raw) != 33 {
		return "", "", "", fmt.Errorf("bad node pubkey %q", node)
	}
	if _, err := crypto.ParsePubKey(raw); err != nil {
		return "", "", "", fmt.Errorf("bad node pubkey: %w", err)
	}
	return relay, node, onion, nil
}

// verifyPublicRelayURL checks after DNS resolution that the target hostname
// resolves to no private, loopback or link-local IP (DNS-rebinding/SSRF protection).
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
