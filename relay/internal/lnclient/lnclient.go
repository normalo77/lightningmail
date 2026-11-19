// Package lnclient: LND client for keysend + invoice subscription.
// Uses lncli subprocess for keysend (more reliable than REST for custom records).
// shortcut: subprocess instead of gRPC avoids heavy deps; upgrade to gRPC in Etappe 4.
package lnclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	RESTHost     string // host:port of LND REST proxy
	Macaroon     string // hex-encoded admin macaroon
	TLSCert      string // path to tls.cert for lncli
	MacaroonPath string // path to admin.macaroon for lncli
	RPCAddr      string // host:port of LND gRPC for lncli
}

type NodeInfo struct {
	IdentityPubkey string `json:"identity_pubkey"`
}

type InvoiceUpdate struct {
	Settled         bool
	AmtPaid         int64  // sats
	PaymentPreimage string // hex
	CustomRecords   map[uint64][]byte
	Memo            string // Bolt11-Memo (z.B. "bmail-topup:ACCOUNT")
	RHashHex        string // payment_hash der Invoice, hex
	Error           error
}

type Client struct {
	cfg    Config
	client *http.Client
}

func New(cfg Config) *Client {
	return &Client{
		cfg: cfg,
		client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
			Timeout: 30 * time.Second,
		},
	}
}

func (c *Client) do(ctx context.Context, method, path string, body any) ([]byte, error) {
	url := fmt.Sprintf("https://%s%s", c.cfg.RESTHost, path)
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, r)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Grpc-Metadata-macaroon", c.cfg.Macaroon)
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("lnd: %s %s: %d: %s", method, path, resp.StatusCode, string(data))
	}
	return data, nil
}

// GetInfo returns the node's identity pubkey via REST.
func (c *Client) GetInfo(ctx context.Context) (*NodeInfo, error) {
	data, err := c.do(ctx, "GET", "/v1/getinfo", nil)
	if err != nil {
		return nil, err
	}
	var info NodeInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return nil, err
	}
	return &info, nil
}

// SendKeysend uses lncli sendpayment --keysend for reliable custom-record delivery.
// dest is hex-encoded 33B compressed pubkey.
// Writes custom-records CSV to a temp file and passes --data.
// Returns the payment preimage (hex).
func (c *Client) SendKeysend(ctx context.Context, dest string, amt int64, customRecords map[uint64][]byte) (string, error) {
	// Build the --data CSV: "key1=hexval1,key2=hexval2,..."
	var parts []string
	for k, v := range customRecords {
		parts = append(parts, fmt.Sprintf("%d=%s", k, hex.EncodeToString(v)))
	}
	dataStr := strings.Join(parts, ",")

	args := []string{
		"--network=regtest",
		"--rpcserver=" + c.cfg.RPCAddr,
	}
	if c.cfg.TLSCert != "" {
		args = append(args, "--tlscertpath="+c.cfg.TLSCert)
	}
	if c.cfg.MacaroonPath != "" {
		args = append(args, "--macaroonpath="+c.cfg.MacaroonPath)
	}
	args = append(args,
		"sendpayment",
		"--dest="+dest,
		"--amt="+fmt.Sprintf("%d", amt),
		"--keysend",
		"--data="+dataStr,
		"--fee_limit=1000",
		"--timeout=30s",
		"--json",
	)

	cmd := exec.CommandContext(ctx, "lncli", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("keysend: %v: %s", err, stderr.String())
	}

	// Parse the JSON response to extract payment_preimage
	var result struct {
		PaymentPreimage string `json:"payment_preimage"`
		PaymentError    string `json:"payment_error"`
		Status          string `json:"status"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		return "", fmt.Errorf("keysend parse: %v (output: %s)", err, stdout.String()[:200])
	}
	if result.PaymentError != "" {
		return "", fmt.Errorf("keysend failed: %s", result.PaymentError)
	}
	_ = "unused" // placeholder removed
	return result.PaymentPreimage, nil
}

// SubscribeInvoices polls the REST API for settled invoices with custom records.
func (c *Client) SubscribeInvoices(ctx context.Context) (<-chan *InvoiceUpdate, error) {
	ch := make(chan *InvoiceUpdate, 32)
	go func() {
		defer close(ch)
		var lastIndex int64
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
			// shortcut: LND-REST ignoriert first_index (0.21.8实测) — wir ziehen
			// die neuesten 100 und filtern numerisch. Upgrade: gRPC-Streaming.
			path := "/v1/invoices?reversed=true&num_max_invoices=100"
			data, err := c.do(ctx, "GET", path, nil)
			if err != nil {
				select {
				case ch <- &InvoiceUpdate{Error: err}:
				case <-ctx.Done():
					return
				}
				continue
			}
			var resp struct {
				Invoices []struct {
					State     string `json:"state"`
					Value     string `json:"value"`
					Memo      string `json:"memo"`
					RHash     string `json:"r_hash"` // base64
					RPreimage string `json:"r_preimage"`
					AddIndex  string `json:"add_index"`
					Htlcs     []struct {
						CustomRecords map[string]string `json:"custom_records"`
					} `json:"htlcs"`
				} `json:"invoices"`
				LastIndexOffset string `json:"last_index_offset"`
			}
			if err := json.Unmarshal(data, &resp); err != nil {
				continue
			}
			advanced := lastIndex
			for _, inv := range resp.Invoices {
				idx, perr := strconv.ParseInt(inv.AddIndex, 10, 64)
				if perr != nil || idx <= lastIndex {
					continue
				}
				if idx > advanced {
					advanced = idx
				}
				if inv.State != "SETTLED" {
					continue
				}
				recs := map[uint64][]byte{}
				for _, h := range inv.Htlcs {
					for k, v := range h.CustomRecords {
						var key uint64
						fmt.Sscanf(k, "%d", &key)
						b, derr := base64.StdEncoding.DecodeString(v)
						if derr != nil {
							b, derr = hex.DecodeString(strings.TrimPrefix(v, "0x"))
							if derr != nil {
								continue
							}
						}
						recs[key] = b
					}
				}
				// Kein TLV-Record ist kein Skip mehr: normale Bolt11-Invoices
				// (Top-Up, Memo "bmail-topup:ACCOUNT") werden auch emittiert.
				rHashHex := ""
				if rh, derr := base64.StdEncoding.DecodeString(inv.RHash); derr == nil {
					rHashHex = hex.EncodeToString(rh)
				}
				var amt int64
				fmt.Sscanf(inv.Value, "%d", &amt)
				update := &InvoiceUpdate{
					Settled:         true,
					AmtPaid:         amt,
					PaymentPreimage: inv.RPreimage,
					CustomRecords:   recs,
					Memo:            inv.Memo,
					RHashHex:        rHashHex,
				}
				select {
				case ch <- update:
				case <-ctx.Done():
					return
				}
			}
			if advanced > lastIndex {
				lastIndex = advanced
			}
			_ = resp.LastIndexOffset
		}
	}()
	return ch, nil
}

var ErrNotBmail = errors.New("lnclient: no bmail TLV in invoice")

// AddInvoice legt eine Bolt11-Invoice an (Top-Up / LUD-16).
// Gibt payment_request und r_hash (hex) zurück.
func (c *Client) AddInvoice(ctx context.Context, amtSats int64, memo string) (string, string, error) {
	data, err := c.do(ctx, "POST", "/v1/invoices", map[string]any{
		"value":  fmt.Sprintf("%d", amtSats),
		"memo":   memo,
		"expiry": "3600",
	})
	if err != nil {
		return "", "", err
	}
	var resp struct {
		PaymentRequest string `json:"payment_request"`
		RHash          string `json:"r_hash"` // base64
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return "", "", err
	}
	rHashHex := ""
	if rh, derr := base64.StdEncoding.DecodeString(resp.RHash); derr == nil {
		rHashHex = hex.EncodeToString(rh)
	}
	return resp.PaymentRequest, rHashHex, nil
}

// PayInvoice bezahlt eine Bolt11-Invoice (via lncli sendpayment --pay_req,
// wie SendKeysend — robust gegen LND-REST-Deprecation in v0.21+).
func (c *Client) PayInvoice(ctx context.Context, payReq string) (string, int64, error) {
	args := []string{
		"--network=regtest",
		"--rpcserver=" + c.cfg.RPCAddr,
	}
	if c.cfg.TLSCert != "" {
		args = append(args, "--tlscertpath="+c.cfg.TLSCert)
	}
	if c.cfg.MacaroonPath != "" {
		args = append(args, "--macaroonpath="+c.cfg.MacaroonPath)
	}
	args = append(args,
		"sendpayment",
		"--force",
		"--pay_req="+payReq,
		"--fee_limit=1000",
		"--timeout=30s",
		"--json",
	)
	cmd := exec.CommandContext(ctx, "lncli", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", 0, fmt.Errorf("pay: %v: %s", err, stderr.String())
	}
	var result struct {
		PaymentPreimage string `json:"payment_preimage"`
		PaymentError    string `json:"payment_error"`
		ValueSat        string `json:"value_sat"`
		PaymentRoute    struct {
			TotalAmt string `json:"total_amt"`
		} `json:"payment_route"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		return "", 0, fmt.Errorf("pay parse: %v", err)
	}
	if result.PaymentError != "" {
		return "", 0, fmt.Errorf("pay failed: %s", result.PaymentError)
	}
	var amtSats int64
	fmt.Sscanf(result.ValueSat, "%d", &amtSats)
	if amtSats == 0 {
		fmt.Sscanf(result.PaymentRoute.TotalAmt, "%d", &amtSats)
	}
	return result.PaymentPreimage, amtSats, nil
}

// DecodePayReq dekodiert eine Bolt11-Invoice: Betrag (sats) + payment_hash (hex).
func (c *Client) DecodePayReq(ctx context.Context, payReq string) (int64, string, error) {
	data, err := c.do(ctx, "GET", "/v1/payreq/"+url.PathEscape(payReq), nil)
	if err != nil {
		return 0, "", err
	}
	var resp struct {
		NumSatoshis any    `json:"num_satoshis"` // LND liefert string oder Zahl
		PaymentHash string `json:"payment_hash"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return 0, "", err
	}
	var amt int64
	fmt.Sscanf(fmt.Sprint(resp.NumSatoshis), "%d", &amt)
	return amt, resp.PaymentHash, nil
}
