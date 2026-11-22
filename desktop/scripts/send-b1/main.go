// send-b1 — M2 evidence B1 headless: two throwaway accounts (alpha+beta
// relay over the CT114 tunnels), one mail with a 3 MiB crypto-random
// attachment via core.ComposeAndSend, delivery confirmed on beta's inbox.
// Keys/evidence land in cmd/lmdesk/evidence/ (600). NEVER a prod key.
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightningmail/desktop/core"
	"github.com/lightningmail/lm1/crypto"
)

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

type account struct {
	Name    string `json:"name"`
	Relay   string `json:"relay"`
	Keyfile string `json:"keyfile"`
}

func mkAccount(ctx context.Context, base, keyPath string) (*account, *core.Client, *btcec.PrivateKey) {
	for tries := 0; tries < 4; tries++ {
		priv, err := crypto.GenerateKeyPair()
		if err != nil {
			log.Fatalf("keygen: %v", err)
		}
		pem, _ := crypto.PrivatePEM(priv)
		if err := os.WriteFile(keyPath, pem, 0600); err != nil {
			log.Fatalf("key: %v", err)
		}
		pub := crypto.PublicBytes(priv)
		// account name = 12-hex pubkey prefix so replies derived from the
		// envelope's SenderPubkey resolve without a reverse lookup
		name := hex.EncodeToString(pub[:6])
		c := core.NewClient(&core.Config{Relay: base, Name: name, Keyfile: keyPath}, priv)
		if err := c.RegisterAccount(ctx, hex.EncodeToString(pub[:])); err != nil {
			log.Printf("register %s: %v — neuer Versuch", name, err)
			continue
		}
		if err := c.Auth(ctx); err != nil {
			log.Fatalf("auth: %v", err)
		}
		return &account{Name: name, Relay: base, Keyfile: keyPath}, c, priv
	}
	log.Fatal("account-Anlage fehlgeschlagen")
	return nil, nil, nil
}

func main() {
	log.SetPrefix("b1 ")
	evDir := envOr("LM_EV_DIR", "cmd/lmdesk/evidence")
	if err := os.MkdirAll(evDir, 0755); err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()
	relayA := envOr("LM_RELAY_A", "http://127.0.0.1:18443")
	relayB := envOr("LM_RELAY_B", "http://127.0.0.1:19443")

	alpha, aClient, _ := mkAccount(ctx, relayA, filepath.Join(evDir, "m2b-alpha.key"))
	log.Printf("alpha-Konto: %s@alpha", alpha.Name)
	beta, bClient, _ := mkAccount(ctx, relayB, filepath.Join(evDir, "m2b-beta.key"))
	log.Printf("beta-Konto: %s@beta", beta.Name)

	att := make([]byte, 3*1024*1024)
	if _, err := rand.Read(att); err != nil {
		log.Fatal(err)
	}
	sum := sha256.Sum256(att)
	attPath := filepath.Join(evDir, "m2b-zufall.bin")
	if err := os.WriteFile(attPath, att, 0600); err != nil {
		log.Fatal(err)
	}
	log.Printf("anhang zufall.bin: %d bytes, sha256=%x", len(att), sum)

	res, err := core.ComposeAndSend(ctx, aClient, corePriv(alpha.Keyfile), core.ComposeOpts{
		To:          beta.Name + "@beta",
		Subject:     "M2B — 3MB Anhang",
		Body:        "composeAndSend headless: 3 MiB Krypto-Zufall, Manifest-only Envelope.",
		Attachments: []core.ComposeAttachment{{Name: "zufall.bin", Bytes: att}},
	})
	if err != nil {
		log.Fatalf("send: %v", err)
	}
	log.Printf("send ok: msg=%s status=%s", res.MsgID, res.Status)

	// delivery wait on beta (cross-relay keysend settles asynchronously)
	msgRaw, _ := hex.DecodeString(res.MsgID)
	msgB64 := base64.StdEncoding.EncodeToString(msgRaw)
	_, page, err := waitInbox(ctx, bClient, msgB64)
	if err != nil {
		log.Fatalf("zustellung: %v", err)
	}
	log.Printf("zugestellt: beta inbox %d mails, seq=%d", len(page.Messages), page.Messages[0].Seq)

	// config for the GUI evidence run (lmdesk logs in as beta)
	cfgJSON, _ := json.MarshalIndent(map[string]string{
		"relay": relayB, "name": beta.Name, "keyfile": beta.Keyfile, "tor_socks": "",
	}, "", "  ")
	cfgPath := filepath.Join(evDir, "m2b-config-b.json")
	os.WriteFile(cfgPath, cfgJSON, 0644)

	out, _ := json.MarshalIndent(map[string]any{
		"alpha": alpha, "beta": beta,
		"msg_id": res.MsgID, "status": res.Status,
		"att_sha256": hex.EncodeToString(sum[:]), "att_size": len(att),
		"subject": "M2B — 3MB Anhang",
	}, "", "  ")
	os.WriteFile(filepath.Join(evDir, "m2b-accounts.json"), out, 0644)
	fmt.Printf("B1_OK msg=%s sha=%s\n", res.MsgID, hex.EncodeToString(sum[:]))
}

func corePriv(path string) *btcec.PrivateKey {
	k, err := core.LoadKeyFile(path, os.Getenv("BMAIL_KEYPASS"))
	if err != nil {
		log.Fatalf("key: %v", err)
	}
	return k
}

func waitInbox(ctx context.Context, c *core.Client, msgB64 string) (int64, *core.InboxPage, error) {
	for i := 0; i < 90; i++ {
		p, err := c.Inbox(ctx, 0, 50)
		if err == nil {
			for _, m := range p.Messages {
				if m.MsgIDB64 == msgB64 {
					return m.Seq, p, nil
				}
			}
		}
		time.Sleep(time.Second)
	}
	return 0, nil, fmt.Errorf("msg nach 90s nicht in inbox")
}
