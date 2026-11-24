// seed-inbox.go — M1b evidence seeding: creates a THROWAWAY account on the
// tunneled ALPHA relay and sends itself 3 mails:
//
//	(1) plain text, (2) colorful HTML with sanitize traps,
//	(3) ~2 MiB random PNG (chunked upload + manifest) with inline cid ref.
//
// Also writes ~/.config/lightningmail/config.json for lmdesk.
// Run on dev-sandbox:  go run scripts/seed-inbox.go   (newPrivKey-style throwaway
// key generated fresh per run — NEVER a prod key, spec M1b).
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"log"
	mrand "math/rand"
	"os"
	"path/filepath"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightningmail/desktop/core"
	"github.com/lightningmail/lm1/crypto"
	"github.com/lightningmail/lm1/envelope"
)

const chunkSize = 1024 * 1024 // chunks.ts CHUNK (1 MiB)

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	log.SetPrefix("seed ")
	relay := envOr("LM_RELAY", "http://127.0.0.1:18443")
	domain := envOr("LM_DOMAIN", "alpha")
	var nb [4]byte
	rand.Read(nb[:])
	name := envOr("LM_NAME", "desk-m1b-"+hex.EncodeToString(nb[:]))
	ctx := context.Background()

	priv, err := crypto.GenerateKeyPair()
	if err != nil {
		log.Fatalf("keygen: %v", err)
	}
	pem, err := crypto.PrivatePEM(priv)
	if err != nil {
		log.Fatalf("pem: %v", err)
	}
	wd, _ := os.Getwd()
	keyPath := filepath.Join(wd, "scripts", "seed.key")
	if err := os.WriteFile(keyPath, pem, 0600); err != nil {
		log.Fatalf("write key: %v", err)
	}

	cfg := &core.Config{Relay: relay, Name: name, Keyfile: keyPath}
	client := core.NewClient(cfg, priv)
	pub := crypto.PublicBytes(priv)
	if err := client.RegisterAccount(ctx, hex.EncodeToString(pub[:])); err != nil {
		log.Fatalf("account: %v", err)
	}
	if err := client.Auth(ctx); err != nil {
		log.Fatalf("auth: %v", err)
	}
	log.Printf("konto %s@%s angelegt (regtest-faucet), key %s", name, domain, keyPath)

	// (1) plain
	sendMail(ctx, client, priv, name, domain, "Seed 1 — reiner Text",
		"Mahlzeit!\n\nDas ist die erste Seed-Mail: reiner Text, zwei Zeilen.\n"+
			"Sie muss in der Liste als aelteste (unten) erscheinen.\n\n— seed-inbox.go",
		nil, nil)
	time.Sleep(2 * time.Second)

	// (2) HTML with the four sanitize traps (<style>, onclick, javascript:,
	// remote img) + allowed markup (colors, list, link, data-image).
	html := `<style>.gelb{background-color:yellow !important} .versteckt{display:none}</style>
<h2 style="color:#c0392b">Bunte HTML-Mail</h2>
<p style="font-size:15px">Dieser Absatz hat <b>fette</b> und <i>kursive</i> Teile.</p>
<div class="gelb">Dieser Text ist NICHT gelb — der style-Tag wurde entfernt.</div>
<ul><li>Punkt eins</li><li style="color:#1e8449">Punkt zwei (grün)</li><li>Punkt drei</li></ul>
<p><a href="https://lightningmail.app">Erlaubter Link</a> ·
<a href="javascript:alert(1)">Boeser JS-Link (muss weg)</a></p>
<button onclick="alert(2)">onclick-Button (muss weg)</button>
<img src="http://tracker.example.com/pixel.png" alt="remote-blockiert">
<img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAoAAAAKCAYAAACNMs+9AAAAFUlEQVR42mP8z8AARIQBEwMDwygAAP//AwCkqQoNAAAAAElFTkSuQmCC" alt="data-bild">
<p class="versteckt">Sichtbar trotz .versteckt-Klasse (CSS aus style-Tag wirkt nicht).</p>`
	sendMail(ctx, client, priv, name, domain, "Seed 2 — HTML bunt", html, nil, nil)
	time.Sleep(2 * time.Second)

	// (3) ~2 MiB random PNG, chunked (1 MiB slices + manifest, send.ts
	// convention) with an inline cid: reference in the HTML body.
	pngBytes := genPNG()
	log.Printf("bild.png generiert: %d bytes", len(pngBytes))
	var hashes []string
	for off := 0; off < len(pngBytes); off += chunkSize {
		end := min(off+chunkSize, len(pngBytes))
		sha, err := client.UploadBlob(ctx, pngBytes[off:end])
		if err != nil {
			log.Fatalf("chunk upload: %v", err)
		}
		hashes = append(hashes, sha)
	}
	manJSON, _ := json.Marshal(map[string]any{"v": 1, "size": len(pngBytes), "chunks": hashes})
	msha, err := client.UploadBlob(ctx, manJSON)
	if err != nil {
		log.Fatalf("manifest upload: %v", err)
	}
	log.Printf("chunked upload: %d scheiben, manifest %s…", len(hashes), msha[:12])
	atts := []core.Attachment{{
		SHA256: msha, Name: "bild.png", Size: int64(len(pngBytes)),
		Chunked: true, Chunks: len(hashes),
	}}
	var mref [32]byte
	mrefBytes, _ := hex.DecodeString(msha)
	copy(mref[:], mrefBytes)
	body := `<p>Die dritte Seed-Mail zeigt ein großes Zufallsbild (2 MiB), ` +
		`inline geladen über <code>lm-mail://blob/…</code>:</p>` +
		`<img src="cid:bild.png" alt="2-MiB-Zufallsbild">`
	sendMail(ctx, client, priv, name, domain, "Seed 3 — Inline-Bild", body, atts, [][32]byte{mref})

	// config for lmdesk
	home, _ := os.UserHomeDir()
	cfgDir := filepath.Join(home, ".config", "lightningmail")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		log.Fatalf("mkdir config: %v", err)
	}
	cfgJSON, _ := json.MarshalIndent(map[string]string{
		"relay": relay, "name": name, "keyfile": keyPath, "tor_socks": "",
	}, "", "  ")
	cfgPath := filepath.Join(cfgDir, "config.json")
	if err := os.WriteFile(cfgPath, cfgJSON, 0o644); err != nil {
		log.Fatalf("write config: %v", err)
	}

	bal, _ := client.Balance(ctx)
	inbox, err := client.Inbox(ctx, 0, 50)
	if err != nil {
		log.Fatalf("inbox check: %v", err)
	}
	log.Printf("balance=%d msat, inbox=%d mails, config=%s", bal, len(inbox.Messages), cfgPath)
	fmt.Printf("SEED_OK name=%s relay=%s balance_msat=%d inbox=%d\n", name, relay, bal, len(inbox.Messages))
}

// sendMail builds + signs + posts one envelope to the own mailbox,
// byte-identical to lmcli send / send.ts composeAndSend.
func sendMail(ctx context.Context, c *core.Client, priv *btcec.PrivateKey,
	name, domain, subject, body string, atts []core.Attachment, refs [][32]byte) {
	if atts == nil {
		atts = []core.Attachment{} // send.ts always writes []
	}
	payload, err := json.Marshal(map[string]any{
		"subject": subject, "body": body,
		"headers": map[string]string{}, "attachments": atts,
	})
	if err != nil {
		log.Fatalf("payload: %v", err)
	}
	// self-send: recipient = own mailbox key
	pub := crypto.PublicBytes(priv)
	rh := sha256.Sum256(pub[:])
	var msgID [32]byte
	rand.Read(msgID[:])
	aad := make([]byte, 64)
	copy(aad[:32], rh[:])
	copy(aad[32:], msgID[:])
	eph, sealed, err := crypto.EncryptForRecipient(priv.PubKey(), payload, aad)
	if err != nil {
		log.Fatalf("encrypt: %v", err)
	}
	env := &envelope.Envelope{
		RecipientHash:     rh,
		MsgID:             msgID,
		BlobRefs:          refs,
		SenderPubkey:      pub,
		Timestamp:         time.Now().Unix(),
		PayloadCiphertext: sealed,
		EphemeralPubkey:   eph,
	}
	sig, err := crypto.SignEnvelope(env, priv)
	if err != nil {
		log.Fatalf("sign: %v", err)
	}
	env.Signature = sig
	envBin, err := env.MarshalBinary()
	if err != nil {
		log.Fatalf("marshal: %v", err)
	}
	if err := c.Send(ctx, name+"@"+domain, envBin); err != nil {
		log.Fatalf("send %q: %v", subject, err)
	}
	log.Printf("gesendet: %q (%d bytes envelope, msg %s…)", subject, len(envBin), hex.EncodeToString(msgID[:])[:12])
}

// genPNG: 1000x1000 — top: coarse red/white checker + blue diagonal band
// (clearly visible in screenshots), bottom: seeded random noise (keeps the
// PNG ~2 MiB so the chunked-upload path is exercised).
func genPNG() []byte {
	const n = 1000
	img := image.NewRGBA(image.Rect(0, 0, n, n))
	rng := mrand.New(mrand.NewSource(42))
	red := color.RGBA{192, 57, 43, 255}
	white := color.RGBA{250, 247, 235, 255}
	blue := color.RGBA{36, 113, 163, 255}
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			var c color.RGBA
			switch {
			case y >= 380: // noise band (~2 MiB PNG total)
				c = color.RGBA{uint8(rng.Intn(256)), uint8(rng.Intn(256)), uint8(rng.Intn(256)), 255}
			case x-y > -60 && x-y < 60: // diagonal band
				c = blue
			case (x/125+y/125)%2 == 0:
				c = red
			default:
				c = white
			}
			img.Set(x, y, c)
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		log.Fatalf("png: %v", err)
	}
	return buf.Bytes()
}
