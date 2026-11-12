// lmcli: bmail command-line client (Etappe 3).
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightningmail/relay/internal/crypto"
	"github.com/lightningmail/relay/internal/envelope"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: lmcli <command> [args]")
		fmt.Fprintln(os.Stderr, "  init <name>            create mailbox keypair + account")
		fmt.Fprintln(os.Stderr, "  send <to> <subject> <body>")
		fmt.Fprintln(os.Stderr, "  inbox                  list inbox messages")
		fmt.Fprintln(os.Stderr, "  balance                show balance")
		os.Exit(1)
	}

	cmd := os.Args[1]
	home := os.Getenv("BMAIL_HOME")
	if home == "" {
		home = os.Getenv("HOME") + "/.bmail"
	}
	os.MkdirAll(home, 0700)

	switch cmd {
	case "init":
		cmdInit(home, os.Args[2:])
	case "send":
		cmdSend(home, os.Args[2:])
	case "inbox":
		cmdInbox(home, os.Args[2:])
	case "balance":
		cmdBalance(home, os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		os.Exit(1)
	}
}

func cmdInit(home string, args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: lmcli init <name>")
		os.Exit(1)
	}
	name := args[0]

	priv, err := crypto.GenerateKeyPair()
	if err != nil {
		fmt.Fprintf(os.Stderr, "keygen: %v\n", err)
		os.Exit(1)
	}
	pem, err := crypto.PrivatePEM(priv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pem: %v\n", err)
		os.Exit(1)
	}
	keyPath := home + "/" + name + ".key"
	if err := os.WriteFile(keyPath, pem, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "write key: %v\n", err)
		os.Exit(1)
	}
	pubHex := hex.EncodeToString(priv.PubKey().SerializeCompressed())

	relay := relayURL()
	reqBody, _ := json.Marshal(map[string]string{
		"name":   name,
		"pubkey": pubHex,
	})
	resp, err := http.Post(relay+"/v1/account", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		fmt.Printf("warning: relay not reachable for auto-registration: %v\n", err)
	} else {
		resp.Body.Close()
	}

	fmt.Printf("key: %s\npubkey: %s\n", keyPath, pubHex)
}

func relayURL() string {
	r := os.Getenv("BMAIL_RELAY")
	if r == "" {
		r = "http://127.0.0.1:8443"
	}
	return r
}

type session struct {
	client  *http.Client
	relay   string
	token   string
	priv    *btcec.PrivateKey
	account string
}

func mustAuth(home string) *session {
	relay := relayURL()
	account := os.Getenv("BMAIL_ACCOUNT")
	if account == "" {
		fmt.Fprintln(os.Stderr, "set BMAIL_ACCOUNT env")
		os.Exit(1)
	}
	keyPath := home + "/" + account + ".key"
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read key: %v (run 'lmcli init %s' first)\n", err, account)
		os.Exit(1)
	}
	priv, err := crypto.LoadPrivatePEM(keyPEM)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load key: %v\n", err)
		os.Exit(1)
	}

	pubHex := hex.EncodeToString(priv.PubKey().SerializeCompressed())
	challenge := []byte("bmail-auth-v1:" + account)
	digest := crypto.AuthDigest(challenge)
	sig, err := crypto.Sign(priv, digest)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sign: %v\n", err)
		os.Exit(1)
	}
	authReq, _ := json.Marshal(map[string]string{
		"address":    account,
		"pubkey_hex": pubHex,
		"sig":        hex.EncodeToString(sig),
	})
	resp, err := http.Post(relay+"/v1/auth", "application/json", bytes.NewReader(authReq))
	if err != nil {
		fmt.Fprintf(os.Stderr, "auth: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "auth failed (%d): %s\n", resp.StatusCode, body)
		os.Exit(1)
	}
	var authResp struct {
		Token string `json:"token"`
	}
	json.NewDecoder(resp.Body).Decode(&authResp)
	if authResp.Token == "" {
		fmt.Fprintln(os.Stderr, "auth: no token returned")
		os.Exit(1)
	}

	return &session{
		client:  &http.Client{},
		relay:   relay,
		token:   authResp.Token,
		priv:    priv,
		account: account,
	}
}

func (s *session) authHdr() string { return "Bearer " + s.token }

func cmdSend(home string, args []string) {
	if len(args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: lmcli send <to> <subject> <body>")
		os.Exit(1)
	}
	to := args[0]
	subject := args[1]
	body := args[2]

	s := mustAuth(home)

	parts := strings.SplitN(to, "@", 2)
	recipName := parts[0]

	profResp, err := s.client.Get(s.relay + "/v1/profile/" + recipName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "profile lookup: %v\n", err)
		os.Exit(1)
	}
	defer profResp.Body.Close()
	if profResp.StatusCode != 200 {
		b, _ := io.ReadAll(profResp.Body)
		fmt.Fprintf(os.Stderr, "profile: %s\n", b)
		os.Exit(1)
	}
	var profile struct {
		Pubkey string `json:"pubkey"`
	}
	json.NewDecoder(profResp.Body).Decode(&profile)

	recvPubBytes, err := hex.DecodeString(profile.Pubkey)
	if err != nil || len(recvPubBytes) != 33 {
		fmt.Fprintf(os.Stderr, "bad recipient pubkey\n")
		os.Exit(1)
	}
	recvPub, err := crypto.ParsePubKey(recvPubBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bad recipient pubkey: %v\n", err)
		os.Exit(1)
	}

	payload, _ := json.Marshal(map[string]any{
		"subject": subject,
		"body":    body,
		"headers": map[string]string{},
	})

	var msgID [32]byte
	rand.Read(msgID[:])
	recipientHash := sha256.Sum256(recvPubBytes)
	senderPub := crypto.PublicBytes(s.priv)

	aad := make([]byte, 64)
	copy(aad[:32], recipientHash[:])
	copy(aad[32:], msgID[:])
	ephPub, sealed, err := crypto.EncryptForRecipient(recvPub, payload, aad)
	if err != nil {
		fmt.Fprintf(os.Stderr, "encrypt: %v\n", err)
		os.Exit(1)
	}

	env := &envelope.Envelope{
		RecipientHash:     recipientHash,
		MsgID:             msgID,
		SenderPubkey:      senderPub,
		Timestamp:         time.Now().Unix(),
		PayloadCiphertext: sealed,
		EphemeralPubkey:   ephPub,
	}

	sig, err := crypto.SignEnvelope(env, s.priv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sign: %v\n", err)
		os.Exit(1)
	}
	env.Signature = sig

	envBin, err := env.MarshalBinary()
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal: %v\n", err)
		os.Exit(1)
	}

	req, _ := http.NewRequest("POST", s.relay+"/v1/send", bytes.NewReader(envBin))
	req.Header.Set("Authorization", s.authHdr())
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := s.client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "send: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 202 {
		fmt.Fprintf(os.Stderr, "send failed (%d): %s\n", resp.StatusCode, respBody)
		os.Exit(1)
	}
	fmt.Printf("sent: %s\n", respBody)
}

func cmdInbox(home string, args []string) {
	s := mustAuth(home)

	req, _ := http.NewRequest("GET", s.relay+"/v1/inbox", nil)
	req.Header.Set("Authorization", s.authHdr())
	resp, err := s.client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "inbox: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	var result struct {
		Messages []struct {
			Seq         int64  `json:"seq"`
			MsgID       string `json:"msg_id_b64"`
			ReceivedAt  int64  `json:"received_at"`
			EnvelopeB64 string `json:"envelope_b64"`
		} `json:"messages"`
	}
	json.NewDecoder(resp.Body).Decode(&result)

	for _, m := range result.Messages {
		envRaw, _ := base64.StdEncoding.DecodeString(m.EnvelopeB64)
		env, err := envelope.Decode(envRaw)
		if err != nil {
			fmt.Printf("[%d] bad envelope: %v\n", m.Seq, err)
			continue
		}
		aad := make([]byte, 64)
		copy(aad[:32], env.RecipientHash[:])
		copy(aad[32:], env.MsgID[:])
		pt, err := crypto.DecryptForRecipient(s.priv, env.EphemeralPubkey[:], env.PayloadCiphertext, aad)
		if err != nil {
			fmt.Printf("[%d] decrypt failed: %v\n", m.Seq, err)
			continue
		}
		var payload struct {
			Subject string `json:"subject"`
			Body    string `json:"body"`
		}
		json.Unmarshal(pt, &payload)
		preview := payload.Body
		if len(preview) > 40 {
			preview = preview[:40]
		}
		fmt.Printf("[%d] %s %s\n", m.Seq, hex.EncodeToString(env.MsgID[:])[:8], payload.Subject)
		_ = preview
	}
}

func cmdBalance(home string, args []string) {
	s := mustAuth(home)
	req, _ := http.NewRequest("GET", s.relay+"/v1/balance", nil)
	req.Header.Set("Authorization", s.authHdr())
	resp, err := s.client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "balance: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	io.Copy(os.Stdout, resp.Body)
	fmt.Println()
}
