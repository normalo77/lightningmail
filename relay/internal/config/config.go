// Package config parses and validates the two YAML surfaces of a relay
// (docs/spec.md §6): relay.yaml (own node, peers, postage) and relays.yaml
// (discovery; same field structure as the future DNS-TXT record of
// CONCEPT §4.2, so DNS becomes a drop-in parser swap in M2).
package config

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"gopkg.in/yaml.v3"
)

var (
	ErrSchema     = errors.New("config: unsupported schema version")
	ErrValidation = errors.New("config: validation failed")
)

// ---------- relay.yaml ----------

type LND struct {
	RPCHost      string `yaml:"rpc_host"`
	TLSCertPath  string `yaml:"tls_cert_path"`
	MacaroonPath string `yaml:"macaroon_path"`
	// Network (Etappe O): regtest|testnet|signet|mainnet; leer = Auto-Detect
	// aus dem Macaroon-Pfad (…/chain/bitcoin/<net>/…).
	Network string `yaml:"network"`
}

type Postage struct {
	ForeignSats  int64 `yaml:"foreign_sats"`
	ContactSats  int64 `yaml:"contact_sats"`
	// Willkommensporto fuer Erstkontakte (Envelope-Tag 0x0A signup);
	// 0 = Default 3x foreign_sats (wird in ParseConfig gesetzt).
	WelcomeSats int64 `yaml:"welcome_sats"`
	MinSats      int64 `yaml:"min_sats"`
	BlobMaxBytes int64 `yaml:"blob_max_bytes"`
	// Etappe 7 (§22): Byte-Porto — Storage-Preis in Milli-EUR pro MiB beim
	// Upload, wertdefiniert (§26) → msat per Tageskurs. 0 = aus (Default,
	// Uploads gratis wie vor Etappe 7); einmal pro (Konto, Blob).
	BytePortoMEurPerMB int64 `yaml:"byte_porto_meur_per_mb"`
}

type Peer struct {
	Name       string `yaml:"name"`
	URL        string `yaml:"url"`
	NodePubkey string `yaml:"node_pubkey"`
	Token      string `yaml:"token"`
}

// Retention steuert die POP3-artige Aufbewahrung (CONCEPT 16):
// GraceDays nach dem letzten Erstdownload ALLER Referenzen, MaxDays absolut.
// -1 deaktiviert den jeweiligen Zweig.
type Retention struct {
	GraceDays int `yaml:"grace_days"`
	MaxDays   int `yaml:"max_days"`
}

// WebAuthn (Etappe 6, CONCEPT §21): Passkey-Login. RPID = Host der UI
// (Domain oder IP), Origins = exakte UI-Origin(s) inkl. Schema+Port.
type WebAuthn struct {
	RPID    string   `yaml:"rp_id"`
	RPName  string   `yaml:"rp_name"`
	Origins []string `yaml:"origins"`
}

// Rates (§25/§26/§22): Tageskurs-Feed fuer Steuerstempel und Byte-Porto,
// sowie 429-Budget fuer anonyme Key-Lookups. Kurs: manual_eur_per_btc > 0
// gewinnt (Regtest, rate_src="manual"), sonst rate_url (24h-Cache); beides
// leer = ungeratet.
type Rates struct {
	ManualEurPerBtc float64 `yaml:"manual_eur_per_btc"`
	RateURL         string  `yaml:"rate_url"`
	PublicRPM       int     `yaml:"public_rpm"`
}

const (
	DefaultPublicRPM = 30 // 429-Budget anonyme Profile/Key-Lookups pro IP
)

// Oidc (IdP, CONCEPT §21/§29): „Sign in with lightningmail".
// Issuer leer = IdP aus (Endpoints 503). Clients statisch (public clients,
// PKCE S256 Pflicht — kein Secret, kein DCR; shortcuts v0.1). Login laeuft
// ueber die PWA (login_page) im OIDC-Modus; Foederations-Beweis = BIP340-Sig
// des Mailbox-Keys als bmail-Claim im ID-Token.
type OidcClient struct {
	ID           string   `yaml:"id"`
	Name         string   `yaml:"name"`
	RedirectURIs []string `yaml:"redirect_uris"`
}

type Oidc struct {
	Issuer        string       `yaml:"issuer"`
	LoginPage     string       `yaml:"login_page"`     // absolute PWA-URL
	AddressDomain string       `yaml:"address_domain"` // Default: Host des Issuers
	Clients       []OidcClient `yaml:"clients"`
}

type Config struct {
	Name        string    `yaml:"name"`
	ListenAddr  string    `yaml:"listen_addr"`
	DataDir     string    `yaml:"data_dir"`
	LND         LND       `yaml:"lnd"`
	Postage     Postage   `yaml:"postage"`
	Peers       []Peer    `yaml:"peers"`
	RelaySecret string    `yaml:"relay_secret"`
	Retention   Retention `yaml:"retention"`
	WebAuthn    WebAuthn  `yaml:"webauthn"`
	Rates       Rates     `yaml:"rates"`
	Oidc        Oidc      `yaml:"oidc"`
}

const DefaultBlobMaxBytes = 10 * 1024 * 1024 // 10 MiB (PRECODING §B)

// LoadConfigFile reads + validates relay.yaml.
func LoadConfigFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseConfig(data)
}

func ParseConfig(data []byte) (*Config, error) {
	c := &Config{}
	if err := yaml.Unmarshal(data, c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if c.Postage.BlobMaxBytes == 0 {
		c.Postage.BlobMaxBytes = DefaultBlobMaxBytes // the one explicit default
	}
	if c.LND.Network == "" {
		switch {
		case strings.Contains(c.LND.MacaroonPath, "/mainnet/"):
			c.LND.Network = "mainnet"
		case strings.Contains(c.LND.MacaroonPath, "/testnet/"):
			c.LND.Network = "testnet"
		default:
			c.LND.Network = "regtest"
		}
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if c.Postage.WelcomeSats == 0 {
		c.Postage.WelcomeSats = c.Postage.ForeignSats * 3
	}
	if c.Retention.GraceDays == 0 {
		c.Retention.GraceDays = 7
	}
	if c.Retention.MaxDays == 0 {
		c.Retention.MaxDays = 90
	}
	if c.Rates.PublicRPM == 0 {
		c.Rates.PublicRPM = DefaultPublicRPM
	}

	return c, nil
}

func (c *Config) Validate() error {
	var errs []string
	req := func(field, v string) {
		if strings.TrimSpace(v) == "" {
			errs = append(errs, "missing required field: "+field)
		}
	}
	req("name", c.Name)
	req("listen_addr", c.ListenAddr)
	req("data_dir", c.DataDir)
	req("lnd.rpc_host", c.LND.RPCHost)
	req("lnd.tls_cert_path", c.LND.TLSCertPath)
	req("lnd.macaroon_path", c.LND.MacaroonPath)
	switch c.LND.Network {
	case "", "regtest", "testnet", "signet", "mainnet":
	default:
		errs = append(errs, "lnd.network must be one of regtest|testnet|signet|mainnet, got "+c.LND.Network)
	}

	if c.Postage.ForeignSats <= 0 {
		errs = append(errs, "postage.foreign_sats must be > 0")
	}
	if c.Postage.MinSats < 1 {
		errs = append(errs, "postage.min_sats must be >= 1")
	} else if c.Postage.MinSats > c.Postage.ForeignSats {
		errs = append(errs, "postage.min_sats must be <= foreign_sats")
	}
	if c.Postage.ContactSats < 0 {
		errs = append(errs, "postage.contact_sats must be >= 0")
	}
	if c.Postage.WelcomeSats < 0 {
		errs = append(errs, "postage.welcome_sats must be >= 0")
	}
	if c.Postage.BlobMaxBytes <= 0 {
		errs = append(errs, "postage.blob_max_bytes must be > 0")
	}
	if c.Postage.BytePortoMEurPerMB < 0 {
		errs = append(errs, "postage.byte_porto_meur_per_mb must be >= 0 (0 = aus)")
	}
	if c.Rates.PublicRPM < -1 {
		errs = append(errs, "rates.public_rpm must be >= -1")
	}
	if c.Rates.ManualEurPerBtc < 0 {
		errs = append(errs, "rates.manual_eur_per_btc must be >= 0")
	}
	if c.Oidc.Issuer != "" {
		if u, err := url.Parse(c.Oidc.Issuer); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			errs = append(errs, "oidc.issuer must be an absolute http(s) URL")
		}
		if c.Oidc.LoginPage != "" {
			if u, err := url.Parse(c.Oidc.LoginPage); err != nil || u.Host == "" {
				errs = append(errs, "oidc.login_page must be an absolute URL")
			}
		}
		seen := map[string]bool{}
		for i, cl := range c.Oidc.Clients {
			where := fmt.Sprintf("oidc.clients[%d]", i)
			if cl.ID == "" {
				errs = append(errs, where+".id is required")
			} else if seen[cl.ID] {
				errs = append(errs, where+".id duplicate: "+cl.ID)
			} else {
				seen[cl.ID] = true
			}
			if len(cl.RedirectURIs) == 0 {
				errs = append(errs, where+".redirect_uris must not be empty")
			}
			for _, u := range cl.RedirectURIs {
				if pu, err := url.Parse(u); err != nil || pu.Host == "" {
					errs = append(errs, where+".redirect_uris must be absolute URLs")
				}
			}
		}
	}

	names := map[string]bool{c.Name: true}
	for i, p := range c.Peers {
		where := fmt.Sprintf("peers[%d]", i)
		if p.Name == "" {
			errs = append(errs, where+".name is required")
		} else if names[p.Name] {
			errs = append(errs, where+".name duplicate (including own name)")
		} else {
			names[p.Name] = true
		}
		if err := validURL(p.URL); err != nil {
			errs = append(errs, where+".url: "+err.Error())
		}
		if err := validPubkeyHex(p.NodePubkey); err != nil {
			errs = append(errs, where+".node_pubkey: "+err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%w: %s", ErrValidation, strings.Join(errs, "; "))
	}
	return nil
}

// ---------- relays.yaml (discovery) ----------

type RelayRecord struct {
	Domain string `yaml:"domain"`
	Relay  string `yaml:"relay"`
	Onion  string `yaml:"onion"`
	Node   string `yaml:"node"`
	Policy string `yaml:"policy"`
	Key    string `yaml:"key"`
}

type Discovery struct {
	Schema  string        `yaml:"schema"`
	Records []RelayRecord `yaml:"records"`
}

// DiscoverySchema mirrors the TXT version tag (v=bmail1, CONCEPT §4.2).
const DiscoverySchema = "bmail1"

func LoadDiscoveryFile(path string) (*Discovery, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseDiscovery(data)
}

func ParseDiscovery(data []byte) (*Discovery, error) {
	d := &Discovery{}
	if err := yaml.Unmarshal(data, d); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if err := d.Validate(); err != nil {
		return nil, err
	}
	return d, nil
}

// Lookup resolves a bmail address domain to its relay record.
func (d *Discovery) Lookup(domain string) (*RelayRecord, error) {
	domain = strings.ToLower(domain)
	for i := range d.Records {
		if d.Records[i].Domain == domain {
			return &d.Records[i], nil
		}
	}
	return nil, fmt.Errorf("config: no relay record for domain %q", domain)
}

func (d *Discovery) Validate() error {
	var errs []string
	if d.Schema != DiscoverySchema {
		errs = append(errs, fmt.Sprintf("schema must be %q, got %q", DiscoverySchema, d.Schema))
	}
	if len(d.Records) == 0 {
		errs = append(errs, "records must contain at least one entry")
	}
	seen := map[string]bool{}
	for i, r := range d.Records {
		where := fmt.Sprintf("records[%d]", i)
		if r.Domain == "" || strings.ToLower(r.Domain) != r.Domain {
			errs = append(errs, where+".domain required and lowercase")
		} else if seen[r.Domain] {
			errs = append(errs, where+".domain duplicate: "+r.Domain)
		} else {
			seen[r.Domain] = true
		}
		if err := validURL(r.Relay); err != nil {
			errs = append(errs, where+".relay: "+err.Error())
		}
		if err := validPubkeyHex(r.Node); err != nil {
			errs = append(errs, where+".node: "+err.Error())
		}
		if r.Policy != "" {
			if err := validURL(r.Policy); err != nil {
				errs = append(errs, where+".policy: "+err.Error())
			}
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%w: %s", ErrValidation, strings.Join(errs, "; "))
	}
	return nil
}

// ---------- shared validators ----------

func validURL(s string) error {
	if strings.TrimSpace(s) == "" {
		return errors.New("url is required")
	}
	u, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("unparseable url: %v", err)
	}
	switch u.Scheme {
	case "https":
	case "http":
		// shortcut: http only for local dev (docker regtest); tighten to
		// https-only when relayd serves real traffic (Etappe 3/mTLS).
		host := u.Hostname()
		if host != "localhost" && !strings.HasPrefix(host, "127.") && host != "::1" {
			return fmt.Errorf("http url only allowed for localhost, got %q", host)
		}
	default:
		return fmt.Errorf("url scheme must be https (or http on localhost), got %q", u.Scheme)
	}
	if u.Host == "" {
		return errors.New("url has no host")
	}
	return nil
}

func validPubkeyHex(s string) error {
	raw, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return fmt.Errorf("not hex: %v", err)
	}
	if len(raw) != 33 {
		return fmt.Errorf("must be 33 bytes compressed, got %d", len(raw))
	}
	if _, err := btcec.ParsePubKey(raw); err != nil {
		return fmt.Errorf("not a valid secp256k1 compressed pubkey: %v", err)
	}
	return nil
}
