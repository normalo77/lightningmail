// Package core is the DOM-free heart of the desktop client: config, relay
// API, mail decoding, StateDoc handling, HTML sanitizing and blob cache.
// Unit-testable without GTK (gate: go test ./core/... runs on Hermes).
package core

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Config lives at ~/.config/lightningmail/config.json.
type Config struct {
	Relay   string `json:"relay"`   // base URL, e.g. http://127.0.0.1:18443
	Name    string `json:"name"`    // account name on the relay
	Keyfile string `json:"keyfile"` // SEC1 PEM mailbox key ("~" allowed)
	// TorSocks: Etappe T — SOCKS5 endpoint "host:port" for Tor routing.
	// Empty = direct connection (M1 default).
	TorSocks string `json:"tor_socks"`
}

// DefaultConfigPath is the canonical config location.
func DefaultConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "lightningmail", "config.json"), nil
}

// LoadConfig reads path (DefaultConfigPath when empty) and expands "~".
func LoadConfig(path string) (*Config, error) {
	if path == "" {
		var err error
		if path, err = DefaultConfigPath(); err != nil {
			return nil, err
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Validate checks the required fields and normalizes Keyfile ("~" -> $HOME).
func (c *Config) Validate() error {
	if c.Relay == "" || c.Name == "" || c.Keyfile == "" {
		return fmt.Errorf("config: relay, name and keyfile are required")
	}
	if strings.HasPrefix(c.Keyfile, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		c.Keyfile = filepath.Join(home, c.Keyfile[2:])
	}
	return nil
}
