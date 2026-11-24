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
	Network      string // lncli --network (regtest|testnet|signet|mainnet)
}

type NodeInfo struct {
	IdentityPubkey string `json:"identity_pubkey"`
}

type InvoiceUpdate struct {
	Settled         bool
	AmtPaid         int64  // sats
	PaymentPreimage string // hex
	CustomRecords   map[uint64][]byte
	Memo            string // Bolt11 memo (e.g. "bmail-topup:ACCOUNT")
	RHashHex        string // payment_hash of the invoice, hex
	Error           error
}

type Client struct {
	cfg    Config
	client *http.Client
}

func New(cfg Config) *Client {
	if cfg.Network == "" {
		cfg.Network = "regtest"
	}
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

// VerifyMessage asks lnd (via lncli verifymessage — LND 0.21.8 exposes no
// REST route for it, but the gRPC/CLI path is already wired for payments)
// to check a compact `lncli signmessage` signature over msg. Returns the
// recovered node pubkey. Used by the Etappe A admin panel login: nothing
// secret ever leaves the lnd wallet.
func (c *Client) VerifyMessage(ctx context.Context, msg, sig string) (string, error) {
	args := []string{"--network=" + c.cfg.Network, "--rpcserver=" + c.cfg.RPCAddr}
	if c.cfg.TLSCert != "" {
		args = append(args, "--tlscertpath="+c.cfg.TLSCert)
	}
	if c.cfg.MacaroonPath != "" {
		args = append(args, "--macaroonpath="+c.cfg.MacaroonPath)
	}
	args = append(args, "verifymessage", msg, sig)
	out, err := exec.CommandContext(ctx, "lncli", args...).Output()
	if err != nil {
		return "", fmt.Errorf("lnd: verifymessage: %w", err)
	}
	var res struct {
		Valid  bool   `json:"valid"`
		Pubkey string `json:"pubkey"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		return "", fmt.Errorf("lnd: verifymessage output: %w", err)
	}
	if !res.Valid {
		return "", fmt.Errorf("lnd: verifymessage: invalid signature")
	}
	return res.Pubkey, nil
}

func truncateStr(s string, max int) string {
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}

// SendKeysend uses lncli sendpayment --keysend for reliable custom-record delivery.
// dest is hex-encoded 33B compressed pubkey. Routing fee is capped at 0.3%.
// Returns the payment preimage (hex) and the actual routing fee paid (msat).
func (c *Client) SendKeysend(ctx context.Context, dest string, amt int64, customRecords map[uint64][]byte) (string, int64, error) {
	// Build the --data CSV: "key1=hexval1,key2=hexval2,..."
	var parts []string
	for k, v := range customRecords {
		parts = append(parts, fmt.Sprintf("%d=%s", k, hex.EncodeToString(v)))
	}
	dataStr := strings.Join(parts, ",")

	args := []string{
		"--network=" + c.cfg.Network,
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
		fmt.Sprintf("--fee_limit=%d", feeLimitSats(amt)),
		"--timeout=30s",
		"--json",
	)

	cmd := exec.CommandContext(ctx, "lncli", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", 0, fmt.Errorf("keysend: %v: %s", err, truncateStr(stderr.String(), 200))
	}

	var result struct {
		PaymentPreimage string `json:"payment_preimage"`
		PaymentError    string `json:"payment_error"`
		Status          string `json:"status"`
		FeeMsat         string `json:"fee_msat"`
		PaymentRoute    struct {
			TotalFeesMsat string `json:"total_fees_msat"`
		} `json:"payment_route"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		return "", 0, fmt.Errorf("keysend parse: %v (output: %s)", err, truncateStr(stdout.String(), 200))
	}
	if result.PaymentError != "" || result.Status == "FAILED" {
		return "", 0, fmt.Errorf("keysend failed: %s", result.PaymentError)
	}
	var feeMsat int64
	fmt.Sscanf(result.FeeMsat, "%d", &feeMsat)
	if feeMsat == 0 {
		fmt.Sscanf(result.PaymentRoute.TotalFeesMsat, "%d", &feeMsat)
	}
	return result.PaymentPreimage, feeMsat, nil
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
			// shortcut: LND REST ignores first_index (verified on 0.21.8) — we fetch
			// the latest 100 and filter numerically. Upgrade: gRPC streaming.
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
				// No TLV record is no longer a skip: normal Bolt11 invoices
				// (top-up, memo "bmail-topup:ACCOUNT") are emitted too.
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

// AddInvoice creates a Bolt11 invoice (top-up / LUD-16).
// Returns payment_request and r_hash (hex).
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

// PayInvoice pays a Bolt11 invoice (via lncli sendpayment --pay_req) with a
// hard 0.3% routing fee cap. confirmedFailed is true ONLY when LND explicitly
// reports a terminal failure (safe to refund); false on ambiguous timeout/kill.
func (c *Client) PayInvoice(ctx context.Context, payReq string) (preimage string, feeMsat int64, confirmedFailed bool, err error) {
	args := []string{
		"--network=" + c.cfg.Network,
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
		"--fee_limit_percent=1",
		"--timeout=30s",
		"--json",
	)
	cmd := exec.CommandContext(ctx, "lncli", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()

	var result struct {
		PaymentPreimage string `json:"payment_preimage"`
		PaymentError    string `json:"payment_error"`
		Status          string `json:"status"`
		FailureReason   string `json:"failure_reason"`
		FeeMsat         string `json:"fee_msat"`
		PaymentRoute    struct {
			TotalFeesMsat string `json:"total_fees_msat"`
		} `json:"payment_route"`
	}
	if jerr := json.Unmarshal(stdout.Bytes(), &result); jerr == nil {
		if result.PaymentError != "" || result.Status == "FAILED" {
			reason := result.PaymentError
			if reason == "" {
				reason = result.FailureReason
			}
			return "", 0, true, fmt.Errorf("pay failed: %s", reason)
		}
		if runErr == nil && (result.Status == "SUCCEEDED" || result.PaymentPreimage != "") {
			fmt.Sscanf(result.FeeMsat, "%d", &feeMsat)
			if feeMsat == 0 {
				fmt.Sscanf(result.PaymentRoute.TotalFeesMsat, "%d", &feeMsat)
			}
			return result.PaymentPreimage, feeMsat, false, nil
		}
	}
	if runErr != nil {
		msg := strings.TrimSpace(stderr.String())
		// Pre-flight rejections before HTLC dispatch are safe to refund
		safe := strings.Contains(msg, "invoice expired") || strings.Contains(msg, "already paid") ||
			strings.Contains(msg, "self-payments") || strings.Contains(msg, "unable to find a path")
		return "", 0, safe, fmt.Errorf("pay: %v: %s", runErr, truncateStr(msg, 200))
	}
	return "", 0, false, fmt.Errorf("pay parse: %s", truncateStr(stdout.String(), 200))
}

// DecodePayReq decodes a Bolt11 invoice: amount (sats) + payment_hash (hex).
func (c *Client) DecodePayReq(ctx context.Context, payReq string) (int64, string, error) {
	data, err := c.do(ctx, "GET", "/v1/payreq/"+url.PathEscape(payReq), nil)
	if err != nil {
		return 0, "", err
	}
	var resp struct {
		NumSatoshis any    `json:"num_satoshis"` // LND returns string or number
		PaymentHash string `json:"payment_hash"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return 0, "", err
	}
	var amt int64
	fmt.Sscanf(fmt.Sprint(resp.NumSatoshis), "%d", &amt)
	return amt, resp.PaymentHash, nil
}

// feeLimitSats returns the 0.3% routing fee cap as an integer satoshi value
// (minimum 1 sat) because lncli rejects fractional --fee_limit_percent values.
func feeLimitSats(amtSats int64) int64 {
	if amtSats <= 0 {
		return 1
	}
	f := (amtSats*3 + 999) / 1000
	if f < 1 {
		return 1
	}
	return f
}
