package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/lightningmail/relay/internal/config"
	"github.com/lightningmail/relay/internal/envelope"
	"github.com/lightningmail/relay/internal/ledger"
	"github.com/lightningmail/relay/internal/lnclient"
	"github.com/lightningmail/relay/internal/postage"
	"github.com/lightningmail/relay/internal/relaysrv"
)

func main() {
	cfgPath := flag.String("config", "relay.yaml", "path to relay.yaml")
	listenAddr := flag.String("addr", "", "override listen address")
	flag.Parse()

	cfg, err := config.LoadConfigFile(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if *listenAddr != "" {
		cfg.ListenAddr = *listenAddr
	}

	os.MkdirAll(cfg.DataDir, 0700)
	dbPath := cfg.DataDir + "/ledger.db"
	l, err := ledger.Open(dbPath)
	if err != nil {
		log.Fatalf("ledger: %v", err)
	}
	defer l.Close()

	macBytes, err := os.ReadFile(cfg.LND.MacaroonPath)
	if err != nil {
		log.Fatalf("macaroon: %v", err)
	}
	macHex := ""
	for _, b := range macBytes {
		macHex += string("0123456789abcdef"[b>>4]) + string("0123456789abcdef"[b&0xf])
	}

	// Connect to LND REST + lncli
	// Derive gRPC port from REST port: REST 8081→gRPC 10001, REST 8082→gRPC 10002
	rpcAddr := strings.Replace(cfg.LND.RPCHost, ":8081", ":10001", 1)
	rpcAddr = strings.Replace(rpcAddr, ":8082", ":10002", 1)
	ln := lnclient.New(lnclient.Config{
		RESTHost:     cfg.LND.RPCHost,
		Macaroon:     macHex,
		TLSCert:      cfg.LND.TLSCertPath,
		MacaroonPath: cfg.LND.MacaroonPath,
		RPCAddr:      rpcAddr,
	})

	p := postage.New(cfg)
	srv := relaysrv.New(cfg, l, ln, p)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Invoice subscriber: catches incoming keysend, stores in mailbox
	go func() {
		ch, err := ln.SubscribeInvoices(ctx)
		if err != nil {
			log.Printf("invoice sub: %v", err)
			return
		}
		for update := range ch {
			if update.Error != nil {
				log.Printf("invoice sub error: %v", update.Error)
				continue
			}
			if !update.Settled {
				continue
			}
			envRaw, ok := update.CustomRecords[34349334]
			if !ok || len(envRaw) == 0 {
				continue
			}
			env, err2 := envelope.Decode(envRaw)
			if err2 != nil {
				log.Printf("incoming: bad envelope: %v", err2)
				continue
			}
			acct, err2 := l.LookupByRecipientHash(env.RecipientHash)
			if err2 != nil {
				log.Printf("incoming: unknown recipient_hash: %v", err2)
				continue
			}
			seq, inserted, err2 := l.PutMessage(env.MsgID, acct.ID, envRaw, update.AmtPaid*1000)
			if err2 != nil {
				log.Printf("incoming: mailbox put error: %v", err2)
				continue
			}
			if !inserted {
				continue // Duplikat-Event: Portokasse NICHT doppelt fuellen
			}
			if err2 := l.CreditRecipient(acct.Name, update.AmtPaid*1000, hex.EncodeToString(env.MsgID[:])); err2 != nil {
				log.Printf("incoming: credit error for %s: %v", acct.Name, err2)
			}
			log.Printf("incoming: msg stored for %s seq=%d amt=%d", acct.Name, seq, update.AmtPaid)
			// Blob-Mirror (spec 6.4): Empfaenger-Relay holt referenzierte Blobs vom Peer und vergibt ACL
			if cfg.RelaySecret != "" && len(env.BlobRefs) > 0 {
				mirrorBlobs(cfg, l, env.BlobRefs, acct.ID, acct.Name)
			}
		}
	}()

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("shutting down...")
		cancel()
		os.Exit(0)
	}()

	log.Printf("relayd %s starting (lnd=%s)", cfg.Name, cfg.LND.RPCHost)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("server: %v", err)
	}
}
func mirrorBlobs(cfg *config.Config, l *ledger.Ledger, refs [][32]byte, acctID int64, acctName string) {
	for _, ref := range refs {
		hexSha := hex.EncodeToString(ref[:])
		loc := cfg.DataDir + "/blob/" + hexSha[:2] + "/" + hexSha
		if st, err := os.Stat(loc); err == nil {
			l.RegisterBlobRef(acctID, ref, st.Size())
			continue
		}
		var raw []byte
		for i := range cfg.Peers {
			p := cfg.Peers[i]
			if p.URL == "" {
				continue
			}
			req, _ := http.NewRequest("GET", p.URL+"/v1/relay/blob/"+hexSha, nil)
			req.Header.Set("X-Relay-Secret", p.Token)
			resp, err := http.DefaultClient.Do(req)
			if err != nil || resp.StatusCode != 200 {
				if resp != nil {
					resp.Body.Close()
				}
				continue
			}
			raw, err = io.ReadAll(resp.Body)
			resp.Body.Close()
			if err == nil {
				break
			}
		}
		if raw == nil {
			log.Printf("mirror: blob %s nicht abrufbar (nachricht trotzdem zugestellt)", hexSha[:12])
			continue
		}
		if h := sha256.Sum256(raw); h != ref {
			log.Printf("mirror: sha mismatch fuer %s", hexSha[:12])
			continue
		}
		os.MkdirAll(cfg.DataDir+"/blob/"+hexSha[:2], 0700)
		if err := os.WriteFile(loc, raw, 0600); err != nil {
			log.Printf("mirror: write %s: %v", hexSha[:12], err)
			continue
		}
		l.RegisterBlobRef(acctID, ref, int64(len(raw)))
		log.Printf("mirror: blob %s gespiegelt fuer %s (%d bytes)", hexSha[:12], acctName, len(raw))
	}
}
