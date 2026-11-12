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
	"os/exec"
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
	AmtPaid         int64            // sats
	PaymentPreimage string           // hex
	CustomRecords   map[uint64][]byte
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
		var lastIndex string
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
			path := "/v1/invoices?reversed=true&num_max_invoices=10"
			if lastIndex != "" {
				path += "&index_offset=" + lastIndex
			}
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
			for _, inv := range resp.Invoices {
				if inv.AddIndex <= lastIndex {
					continue
				}
				if inv.State != "SETTLED" {
					continue
				}
				recs := map[uint64][]byte{}
				for _, h := range inv.Htlcs {
					for k, v := range h.CustomRecords {
						var key uint64
						fmt.Sscanf(k, "%d", &key)
						b, err := base64.StdEncoding.DecodeString(v)
						if err != nil {
							b, err = hex.DecodeString(strings.TrimPrefix(v, "0x"))
							if err != nil {
								continue
							}
						}
						recs[key] = b
					}
				}
				if len(recs) == 0 {
					continue
				}
				var amt int64
				fmt.Sscanf(inv.Value, "%d", &amt)
				update := &InvoiceUpdate{
					Settled:         true,
					AmtPaid:         amt,
					PaymentPreimage: inv.RPreimage,
					CustomRecords:   recs,
				}
				select {
				case ch <- update:
				case <-ctx.Done():
					return
				}
			}
			if resp.LastIndexOffset != "" {
				lastIndex = resp.LastIndexOffset
			}
		}
	}()
	return ch, nil
}

var ErrNotBmail = errors.New("lnclient: no bmail TLV in invoice")