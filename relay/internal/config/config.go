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
}

type Postage struct {
	ForeignSats  int64 `yaml:"foreign_sats"`
	ContactSats  int64 `yaml:"contact_sats"`
	MinSats      int64 `yaml:"min_sats"`
	BlobMaxBytes int64 `yaml:"blob_max_bytes"`
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

type Config struct {
	Name        string    `yaml:"name"`
	ListenAddr  string    `yaml:"listen_addr"`
	DataDir     string    `yaml:"data_dir"`
	LND         LND       `yaml:"lnd"`
	Postage     Postage   `yaml:"postage"`
	Peers       []Peer    `yaml:"peers"`
	RelaySecret string    `yaml:"relay_secret"`
	Retention   Retention `yaml:"retention"`
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
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if c.Retention.GraceDays == 0 {
		c.Retention.GraceDays = 7
	}
	if c.Retention.MaxDays == 0 {
		c.Retention.MaxDays = 90
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
	if c.Postage.BlobMaxBytes <= 0 {
		errs = append(errs, "postage.blob_max_bytes must be > 0")
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
