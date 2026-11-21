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
	"time"

	"github.com/lightningmail/relay/internal/config"
	"github.com/lightningmail/relay/internal/crypto"
	"github.com/lightningmail/relay/internal/envelope"
	"github.com/lightningmail/relay/internal/ledger"
	"github.com/lightningmail/relay/internal/lnclient"
	"github.com/lightningmail/relay/internal/postage"
	"github.com/lightningmail/relay/internal/rates"
	"github.com/lightningmail/relay/internal/relaysrv"
)

func main() {
	var cleanupOnce bool
	flag.BoolVar(&cleanupOnce, "cleanup-once", false, "Retention-Sweep einmal ausfuehren und beenden")
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
	// Derive gRPC port from REST port: REST 8080→gRPC 10009 (mainnet default),
	// REST 8081→gRPC 10001, REST 8082→gRPC 10002 (regtest-Compose)
	rpcAddr := strings.Replace(cfg.LND.RPCHost, ":8081", ":10001", 1)
	rpcAddr = strings.Replace(rpcAddr, ":8082", ":10002", 1)
	rpcAddr = strings.Replace(rpcAddr, ":8080", ":10009", 1)
	ln := lnclient.New(lnclient.Config{
		RESTHost:     cfg.LND.RPCHost,
		Macaroon:     macHex,
		TLSCert:      cfg.LND.TLSCertPath,
		MacaroonPath: cfg.LND.MacaroonPath,
		RPCAddr:      rpcAddr,
		Network:      cfg.LND.Network,
	})

	p := postage.New(cfg)
	// ONE rate feed for both HTTP server AND LN ingest (§25: every
	// inflow is stamped with the daily rate; without one it stays unrated).
	feed := rates.NewFeed(cfg.Rates.RateURL, cfg.Rates.ManualEurPerBtc)
	go feed.Start()
	srv := relaysrv.New(cfg, l, ln, p, feed)

	// M3 retention: sweep 60s after start, then daily; -cleanup-once for tests.
	sweep := func() {
		shas, err := l.RetentionSweep(time.Now().Unix(), int64(cfg.Retention.GraceDays)*86400, int64(cfg.Retention.MaxDays)*86400)
		if err != nil {
			log.Printf("retention sweep: %v", err)
			return
		}
		for _, sha := range shas {
			hexs := hex.EncodeToString(sha)
			path := cfg.DataDir + "/blob/" + hexs[:2] + "/" + hexs
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				log.Printf("retention remove %s: %v", hexs[:12], err)
				continue
			}
			if err := l.DeleteBlobRefs(sha); err != nil {
				log.Printf("retention refs %s: %v", hexs[:12], err)
			}
			log.Printf("retention: blob %s… getilgt", hexs[:12])
		}
	}
	if cleanupOnce {
		sweep()
		return
	}
	go func() {
		time.AfterFunc(60*time.Second, sweep)
		for range time.Tick(24 * time.Hour) {
			sweep()
		}
	}()

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
				// No bmail TLV: possibly a Lightning top-up (Bolt11 invoice with
				// memo "bmail-topup:ACCOUNT", created via /v1/topup or LUD-16).
				if strings.HasPrefix(update.Memo, "bmail-topup:") {
					acctName := strings.TrimPrefix(update.Memo, "bmail-topup:")
					if _, err2 := l.GetAccount(acctName); err2 != nil {
						log.Printf("topup: unknown account %q", acctName)
						continue
					}
					ref := "topup:" + update.RHashHex
					hist, err2 := l.History(acctName, 200)
					if err2 != nil {
						log.Printf("topup: history %s: %v", acctName, err2)
						continue
					}
					dup := false
					for _, tx := range hist {
						if tx.Ref == ref {
							dup = true
							break
						}
					}
					if dup {
						continue // same invoice already credited (replay after restart)
					}
					// §25 G1: stamp inflow with the daily rate when the feed has one
					if snap, ok := feed.Current(); ok {
						err2 = l.ApplyDeltaMeta(acctName, update.AmtPaid*1000, ledger.KindTopup, ref, "btc", &snap)
					} else {
						err2 = l.ApplyDelta(acctName, update.AmtPaid*1000, ledger.KindTopup, ref)
					}
					if err2 != nil {
						log.Printf("topup: credit %s: %v", acctName, err2)
						continue
					}
					log.Printf("topup: %s +%d sats (r_hash=%s)", acctName, update.AmtPaid, update.RHashHex)
				}
				continue
			}
			env, err2 := envelope.Decode(envRaw)
			if err2 != nil {
				log.Printf("incoming: bad envelope: %v", err2)
				continue
			}
			if err2 := crypto.VerifyEnvelope(env, env.SenderPubkey[:], env.Signature); err2 != nil {
				log.Printf("incoming: invalid envelope signature: %v", err2)
				continue
			}
			if tSig, ok1 := update.CustomRecords[34349337]; ok1 && len(tSig) == 64 {
				if tPubRaw, ok2 := update.CustomRecords[34349339]; ok2 && len(tPubRaw) == 33 {
					// only verify when tSig is not 64 zero bytes (legacy compatibility)
					nonZero := false
					for _, b := range tSig {
						if b != 0 {
							nonZero = true
							break
						}
					}
					if nonZero {
						if tPub, err3 := crypto.ParsePubKey(tPubRaw); err3 != nil || crypto.Verify(tPub, envRaw, tSig) != nil {
							log.Printf("incoming: invalid transport signature 34349337")
							continue
						}
					}
				}
			}
			acct, err2 := l.LookupByRecipientHash(env.RecipientHash)
			if err2 != nil {
				log.Printf("incoming: unknown recipient_hash: %v", err2)
				continue
			}
			minPostage := p.ForeignSats()
			if env.Signup {
				minPostage = p.WelcomeSats()
			}
			if update.AmtPaid < minPostage {
				log.Printf("incoming: insufficient postage for %s: paid=%d < required=%d (signup=%v)", acct.Name, update.AmtPaid, minPostage, env.Signup)
				continue
			}
			seq, inserted, err2 := l.PutMessage(env.MsgID, acct.ID, envRaw, update.AmtPaid*1000)
			if err2 != nil {
				log.Printf("incoming: mailbox put error: %v", err2)
				continue
			}
			if !inserted {
				continue // duplicate event: do NOT credit the postage pot twice
			}
			creditRef := hex.EncodeToString(env.MsgID[:])
			// §25 G1: stamp inflow with the daily rate when the feed has one
			if snap, ok := feed.Current(); ok {
				err2 = l.ApplyDeltaMeta(acct.Name, update.AmtPaid*1000, ledger.KindPostageIn, creditRef, "btc", &snap)
			} else {
				err2 = l.CreditRecipient(acct.Name, update.AmtPaid*1000, creditRef)
			}
			if err2 != nil {
				log.Printf("incoming: credit error for %s: %v", acct.Name, err2)
			}
			log.Printf("incoming: msg stored for %s seq=%d amt=%d", acct.Name, seq, update.AmtPaid)
			// Blob mirror (spec 6.4): receiving relay fetches referenced blobs from the peer and grants ACL
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
			l.RegisterBlobRef(acctID, ref, st.Size(), "mail")
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
		l.RegisterBlobRef(acctID, ref, int64(len(raw)), "mail")
		log.Printf("mirror: blob %s gespiegelt fuer %s (%d bytes)", hexSha[:12], acctName, len(raw))
	}
}
