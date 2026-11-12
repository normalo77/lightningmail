// Package postage: porto calculation from relay config (spec §7.2).
package postage

import "github.com/lightningmail/relay/internal/config"

type Service struct {
	cfg *config.Config
}

func New(cfg *config.Config) *Service {
	return &Service{cfg: cfg}
}

// ForeignSats returns the postage price for a stranger.
func (s *Service) ForeignSats() int64 {
	return s.cfg.Postage.ForeignSats
}

// MinSats returns the minimum acceptable postage.
func (s *Service) MinSats() int64 {
	return s.cfg.Postage.MinSats
}
