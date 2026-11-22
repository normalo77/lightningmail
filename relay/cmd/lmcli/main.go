// lmcli: bmail command-line client (Etappe 3).
package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightningmail/lm1/crypto"
	"github.com/lightningmail/lm1/envelope"
)

func main() {
	if len(os.Args) < 2 {
		cmdGUI(nil) // no arguments: native Linux client (GUI)
		return
	}

	cmd := os.Args[1]
	home := os.Getenv("BMAIL_HOME")
	if home == "" {
		home = os.Getenv("HOME") + "/.bmail"
	}
	os.MkdirAll(home, 0700)

	switch cmd {
	case "gui":
		cmdGUI(os.Args[2:])
	case "init":
		cmdInit(home, os.Args[2:])
	case "send":
		cmdSend(home, os.Args[2:])
	case "inbox":
		cmdInbox(home, os.Args[2:])
	case "token":
		cmdToken(home, os.Args[2:])
	case "balance":
		cmdBalance(home, os.Args[2:])
	case "topup":
		cmdTopup(home, os.Args[2:])
	case "withdraw":
		cmdWithdraw(home, os.Args[2:])
	case "statement":
		cmdStatement(home, os.Args[2:])
	case "blob":
		cmdBlob(home, os.Args[2:])
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: lmcli <command> [args]")
	fmt.Fprintln(os.Stderr, "  (keine Args) | gui [--port N]  nativer Linux-Client (lokale GUI)")
	fmt.Fprintln(os.Stderr, "  init <name>            create mailbox keypair + account")
	fmt.Fprintln(os.Stderr, "  send <to> <subject> <body> [--signup] [--attach <sha256>]")
	fmt.Fprintln(os.Stderr, "  inbox                  list inbox messages")
	fmt.Fprintln(os.Stderr, "  balance                show balance")
	fmt.Fprintln(os.Stderr, "  topup <sats>           Bolt11-Invoice zum Aufladen erzeugen")
	fmt.Fprintln(os.Stderr, "  withdraw <bolt11>      Guthaben an Bolt11-Invoice auszahlen")
	fmt.Fprintln(os.Stderr, "  statement [--csv]      Kontoauszug (JSON, mit --csv als CSV)")
	fmt.Fprintln(os.Stderr, "  blob upload <file>     upload attachment blob")
	fmt.Fprintln(os.Stderr, "  blob get <sha256>      download blob to stdout")
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
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read key: %v (run 'lmcli init %s' first)\n", err, account)
		os.Exit(1)
	}
	defer clear(keyData)
	priv, err := loadKey(keyData)
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
	// Parse --attach <sha256_hex> / --signup optional flags before positional args.
	var attachRefs []string
	signup := false
	var holdUntil int64 // --hold-until <unix-secs>: tag 0x0B, receiver withholds delivery
	posArgs := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		if args[i] == "--attach" && i+1 < len(args) {
			attachRefs = append(attachRefs, args[i+1])
			i++
		} else if args[i] == "--hold-until" && i+1 < len(args) {
			v, err := strconv.ParseInt(args[i+1], 10, 64)
			if err != nil {
				fmt.Fprintln(os.Stderr, "--hold-until will unix seconds")
				os.Exit(1)
			}
			holdUntil = v
			i++
		} else if args[i] == "--signup" {
			signup = true // tag 0x0A: first contact → postage advance (welcome_sats)
		} else {
			posArgs = append(posArgs, args[i])
		}
	}
	if len(posArgs) < 3 {
		fmt.Fprintln(os.Stderr, "usage: lmcli send <to> <subject> <body> [--signup] [--attach <sha256>] [--hold-until <unix-secs>]")
		os.Exit(1)
	}
	to := posArgs[0]
	subject := posArgs[1]
	body := posArgs[2]

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

	// Build attachments list for the inner payload.
	type attInfo struct {
		SHA256 string `json:"sha256"`
		Name   string `json:"name"`
		Size   int    `json:"size"`
	}
	var attachments []attInfo
	for _, refHex := range attachRefs {
		attachments = append(attachments, attInfo{
			SHA256: refHex,
			Name:   refHex[:12] + ".bin",
			Size:   0, // unknown size without head request
		})
	}

	payload, _ := json.Marshal(map[string]any{
		"subject":     subject,
		"body":        body,
		"headers":     map[string]string{},
		"attachments": attachments,
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

	// Build blob_refs for envelope tag 0x03.
	var blobRefs [][32]byte
	for _, refHex := range attachRefs {
		refBytes, err := hex.DecodeString(refHex)
		if err != nil || len(refBytes) != 32 {
			fmt.Fprintf(os.Stderr, "bad blob ref: %s\n", refHex)
			os.Exit(1)
		}
		var ref32 [32]byte
		copy(ref32[:], refBytes)
		blobRefs = append(blobRefs, ref32)
	}

	env := &envelope.Envelope{
		RecipientHash:     recipientHash,
		MsgID:             msgID,
		BlobRefs:          blobRefs,
		SenderPubkey:      senderPub,
		Timestamp:         time.Now().Unix(),
		PayloadCiphertext: sealed,
		EphemeralPubkey:   ephPub,
		Signup:            signup,
		NotBefore:         holdUntil,
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

	// ?to= gives the relay the routing hint (name@relay)
	req, _ := http.NewRequest("POST", s.relay+"/v1/send?to="+url.QueryEscape(to), bytes.NewReader(envBin))
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

func cmdToken(home string, args []string) {
	s := mustAuth(home)
	fmt.Println(s.token)
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

// --- wallet commands (v1.0): topup, withdraw, statement ---

// doAuth: HTTP request with bearer token; body != nil → JSON POST.
func (s *session) doAuth(method, path string, body []byte) (*http.Response, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, _ := http.NewRequest(method, s.relay+path, rd)
	req.Header.Set("Authorization", s.authHdr())
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return s.client.Do(req)
}

func cmdTopup(home string, args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: lmcli topup <sats>")
		os.Exit(1)
	}
	sats, err := strconv.ParseInt(args[0], 10, 64)
	if err != nil || sats < 1 {
		fmt.Fprintln(os.Stderr, "topup: <sats> muss eine positive Ganzzahl sein")
		os.Exit(1)
	}
	s := mustAuth(home)
	body, _ := json.Marshal(map[string]int64{"amount_sats": sats})
	resp, err := s.doAuth("POST", "/v1/topup", body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "topup: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		fmt.Fprintf(os.Stderr, "topup failed (%d): %s\n", resp.StatusCode, raw)
		os.Exit(1)
	}
	var tr struct {
		PaymentRequest string `json:"payment_request"`
	}
	json.Unmarshal(raw, &tr)
	fmt.Println(tr.PaymentRequest)
}

func cmdWithdraw(home string, args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: lmcli withdraw <bolt11>")
		os.Exit(1)
	}
	s := mustAuth(home)
	body, _ := json.Marshal(map[string]string{"payment_request": args[0]})
	resp, err := s.doAuth("POST", "/v1/withdraw", body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "withdraw: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		fmt.Fprintf(os.Stderr, "withdraw failed (%d): %s\n", resp.StatusCode, raw)
		os.Exit(1)
	}
	var wr struct {
		AmountSats int64  `json:"amount_sats"`
		Preimage   string `json:"preimage"`
	}
	json.Unmarshal(raw, &wr)
	fmt.Printf("paid %d sats\npreimage: %s\n", wr.AmountSats, wr.Preimage)
}

func cmdStatement(home string, args []string) {
	fmtType := "json"
	for _, a := range args {
		if a == "--csv" {
			fmtType = "csv"
		}
	}
	s := mustAuth(home)
	resp, err := s.doAuth("GET", "/v1/statement?fmt="+fmtType, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "statement: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		raw, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "statement failed (%d): %s\n", resp.StatusCode, raw)
		os.Exit(1)
	}
	io.Copy(os.Stdout, resp.Body)
	fmt.Println()
}

// --- blob commands ---

func cmdBlob(home string, args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: lmcli blob <upload|get> ...")
		os.Exit(1)
	}
	switch args[0] {
	case "upload":
		cmdBlobUpload(home, args[1:])
	case "get":
		cmdBlobGet(home, args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown blob command: %s\n", args[0])
		os.Exit(1)
	}
}

func cmdBlobUpload(home string, args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: lmcli blob upload <file>")
		os.Exit(1)
	}
	s := mustAuth(home)
	data, err := os.ReadFile(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "read file: %v\n", err)
		os.Exit(1)
	}
	req, _ := http.NewRequest("POST", s.relay+"/v1/blob", bytes.NewReader(data))
	req.Header.Set("Authorization", s.authHdr())
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := s.client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "blob upload: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	io.Copy(os.Stdout, resp.Body)
	fmt.Println()
}

func cmdBlobGet(home string, args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: lmcli blob get <sha256_hex>")
		os.Exit(1)
	}
	s := mustAuth(home)
	sha := args[0]
	req, _ := http.NewRequest("GET", s.relay+"/v1/blob/"+sha, nil)
	req.Header.Set("Authorization", s.authHdr())
	resp, err := s.client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "blob get: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "blob get failed (%d): %s\n", resp.StatusCode, body)
		os.Exit(1)
	}
	io.Copy(os.Stdout, resp.Body)
}

// loadKey reads bare PEM or LMKEY1/LMKEY2 wraps (M-SEC.1). Passphrase comes
// from BMAIL_KEYPASS, else asked interactively.
func loadKey(data []byte) (*btcec.PrivateKey, error) {
	if !crypto.IsWrapped(string(data)) {
		return crypto.LoadPrivatePEM(data)
	}
	pass := os.Getenv("BMAIL_KEYPASS")
	if pass == "" {
		pass = promptPassphrase()
	}
	return crypto.LoadKey(data, pass)
}

func promptPassphrase() string {
	fmt.Fprint(os.Stderr, "Passphrase: ")
	// shortcut: prompt echoes; swap to golang.org/x/term.ReadPassword if a new
	// dependency is ever acceptable here.
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		fmt.Fprintln(os.Stderr, "no passphrase")
		os.Exit(1)
	}
	return strings.TrimRight(line, "\r\n")
}
