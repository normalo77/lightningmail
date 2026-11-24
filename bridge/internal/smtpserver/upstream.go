package smtpserver

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
)

// SMTPUpstream forwards classic copies to the configured upstream SMTP
// relay (implements Upstream).
type SMTPUpstream struct {
	Host        string
	Port        int
	User        string
	Pass        string
	FromAddress string // optional MAIL FROM override for strict providers (e.g. web.de)
	TLSMode     string // none | starttls | tls (config.TLS* constants)
}

func (u *SMTPUpstream) addr() string {
	return net.JoinHostPort(u.Host, strconv.Itoa(u.Port))
}

// Forward dials the upstream (hard dial timeout — go-smtp's client has no
// context support) and submits the message verbatim.
func (u *SMTPUpstream) Forward(ctx context.Context, from string, to []string, raw []byte) error {
	d := net.Dialer{Timeout: 30 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", u.addr())
	if err != nil {
		return err
	}
	var c *smtp.Client
	switch u.TLSMode {
	case "tls":
		tconn := tls.Client(conn, &tls.Config{ServerName: u.Host, MinVersion: tls.VersionTLS12})
		if err := tconn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return fmt.Errorf("upstream tls handshake: %w", err)
		}
		c = smtp.NewClient(tconn)
	case "starttls":
		// NewClientStartTLS runs the EHLO + STARTTLS upgrade itself
		c, err = smtp.NewClientStartTLS(conn, &tls.Config{ServerName: u.Host, MinVersion: tls.VersionTLS12})
		if err != nil {
			return fmt.Errorf("upstream starttls: %w", err)
		}
	default:
		c = smtp.NewClient(conn)
	}
	defer c.Close()
	if u.User != "" {
		if err := c.Auth(sasl.NewPlainClient("", u.User, u.Pass)); err != nil {
			return fmt.Errorf("upstream auth: %w", err)
		}
	}
	envFrom := from
	if u.FromAddress != "" {
		envFrom = u.FromAddress
	}
	if err := c.Mail(envFrom, nil); err != nil {
		return err
	}
	for _, t := range to {
		if err := c.Rcpt(t, nil); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(raw); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}
