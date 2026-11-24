// Command lmbridge runs the lightningmail bridge (Etappe B2): authenticated
// classic SMTP in, smart per-recipient routing to the LM relay or an upstream
// SMTP host, plus an optional IMAP server that mirrors the LM inbox from a
// local SQLite cache and round-trips flags through /v1/state.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/emersion/go-smtp"

	"github.com/lightningmail/bridge/internal/config"
	lmimap "github.com/lightningmail/bridge/internal/imapserver"
	"github.com/lightningmail/bridge/internal/relayclient"
	"github.com/lightningmail/bridge/internal/smtpserver"
	"github.com/lightningmail/lm1/crypto"
)

func main() {
	cfgPath := flag.String("config", "bridge.yaml", "path to the YAML config file")
	flag.Parse()
	if err := run(*cfgPath); err != nil {
		log.Fatalf("lmbridge: %v", err)
	}
}

func run(cfgPath string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}

	keyBytes, err := os.ReadFile(cfg.KeyFile)
	if err != nil {
		return fmt.Errorf("key file: %w", err)
	}
	pass, err := cfg.KeyPass()
	if err != nil {
		return err
	}
	priv, err := crypto.LoadKey(keyBytes, pass)
	clear(keyBytes) // do not leave the unwrapped PEM lying around in memory
	if err != nil {
		return fmt.Errorf("key file: %w", err)
	}
	defer func() {
		// Best-effort RAM hygiene: overwrite the private scalar on exit.
		// (ModNScalar.Bytes() returns a copy, so zeroing goes through Set.)
		priv.Key.SetByteSlice(make([]byte, 32))
	}()

	relay := relayclient.New(cfg.RelayURL, cfg.Account, priv)
	lctx, lcancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer lcancel()
	// Fail fast: a bad key or dead relay must stop the bridge before it
	// accepts mail it cannot deliver.
	if err := relay.Login(lctx); err != nil {
		return fmt.Errorf("relay login: %w", err)
	}
	log.Printf("lmbridge: authenticated to %s as %s", cfg.RelayURL, cfg.Account)

	opts := smtpserver.Options{
		Addr:  cfg.SMTPListen,
		Relay: relay,
	}
	opts.AuthUser = cfg.BridgeAuth.User
	if opts.AuthPass, err = config.ReadPassFile(cfg.BridgeAuth.PassFile); err != nil {
		return err
	}
	if up := cfg.UpstreamSMTP; up != nil {
		smtpUp := &smtpserver.SMTPUpstream{
			Host:        up.Host,
			Port:        up.Port,
			User:        up.User,
			FromAddress: up.FromAddress,
			TLSMode:     up.TLSMode,
		}
		if up.PassFile != "" {
			if smtpUp.Pass, err = config.ReadPassFile(up.PassFile); err != nil {
				return err
			}
		}
		opts.Upstream = smtpUp
		opts.ReplyTo = up.FromAddress
	}
	if cfg.TLSCert != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
		if err != nil {
			return fmt.Errorf("tls: %w", err)
		}
		opts.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Optional IMAP side (Etappe B2). The syncer must exist before the SMTP
	// server starts so the RecordingRelay wrapper can report LM sends.
	var (
		imapErrc     chan error // nil without imap_listen: select skips it
		shutdownIMAP func(alreadyExited bool)
	)
	if cfg.IMAPListen != "" {
		store, err := lmimap.OpenStore(cfg.StateDir)
		if err != nil {
			return fmt.Errorf("imap store: %w", err)
		}
		defer store.Close() // runs after shutdownIMAP below, before key zeroing
		syncer := lmimap.NewSyncer(relay, priv, store, cfg.Account, cfg.PollInterval)
		opts.Relay = &lmimap.RecordingRelay{Inner: relay, S: syncer}

		isrv := lmimap.NewServer(lmimap.Options{
			Addr:      cfg.IMAPListen,
			AuthUser:  cfg.BridgeAuth.User,
			AuthPass:  opts.AuthPass,
			TLSConfig: opts.TLSConfig,
			Store:     store,
		})
		ln, err := net.Listen("tcp", cfg.IMAPListen)
		if err != nil {
			return fmt.Errorf("imap listen: %w", err)
		}
		imapErrc = make(chan error, 1)
		go func() { imapErrc <- isrv.Serve(ln) }()
		log.Printf("lmbridge: IMAP listening on %s (state dir %s, poll %s)",
			cfg.IMAPListen, cfg.StateDir, cfg.PollInterval)

		syncDone := make(chan struct{})
		go func() {
			defer close(syncDone)
			syncer.Run(ctx) // returns nil when ctx is cancelled
		}()
		shutdownIMAP = func(alreadyExited bool) {
			isrv.Close() // closes listeners and live connections
			if !alreadyExited {
				<-imapErrc
			}
			<-syncDone // the syncer must be done before the store closes
		}
	}

	srv := smtpserver.NewServer(opts)
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	log.Printf("lmbridge: SMTP listening on %s", cfg.SMTPListen)

	var (
		retErr   error
		smtpDone bool
		imapDone bool
	)
	select {
	case err := <-errc:
		smtpDone = true
		if err != nil && !errors.Is(err, smtp.ErrServerClosed) {
			retErr = err
		}
	case err := <-imapErrc:
		imapDone = true
		if err != nil {
			retErr = fmt.Errorf("imap: %w", err)
		}
	case <-ctx.Done():
		log.Print("lmbridge: signal received, shutting down")
	}

	// Orderly teardown on every exit path: stop the syncer (ctx), drain SMTP,
	// then IMAP connections and the store — all before the deferred key
	// zeroing runs last.
	stop()
	if !smtpDone {
		sctx, scancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer scancel()
		if err := srv.Shutdown(sctx); err != nil {
			log.Printf("lmbridge: smtp shutdown: %v", err)
		}
		<-errc
	}
	if shutdownIMAP != nil {
		shutdownIMAP(imapDone)
	}
	log.Print("lmbridge: stopped, key material zeroed")
	return retErr
}
