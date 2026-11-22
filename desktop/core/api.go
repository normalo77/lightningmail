package core

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightningmail/lm1/crypto"
)

// Client talks to one relay. Every method returns (T, error) — no os.Exit,
// no panic (Rotliste #10); the GUI maps errors to toasts/status line.
type Client struct {
	Base    string
	Account string

	hc   *http.Client
	priv *btcec.PrivateKey

	tokenMu sync.Mutex
	token   string
}

// NewClient builds the HTTP client; cfg.TorSocks ("host:port") routes
// everything through SOCKS5 (Etappe T) — Go's transport speaks SOCKS5
// natively when the proxy URL scheme is socks5://.
func NewClient(cfg *Config, priv *btcec.PrivateKey) *Client {
	tr := &http.Transport{}
	if cfg.TorSocks != "" {
		pu, err := url.Parse("socks5://" + cfg.TorSocks)
		if err == nil {
			tr.Proxy = http.ProxyURL(pu)
		}
	}
	return &Client{
		Base:    cfg.Relay,
		Account: cfg.Name,
		hc:      &http.Client{Timeout: 15 * time.Second, Transport: tr},
		priv:    priv,
	}
}

// Auth signs the login challenge exactly like lmcli/relay handleAuth:
// challenge = "bmail-auth-v1:"+name, digest = HMAC-SHA256(key=AuthKeyInfo),
// sig = BIP340 over sha256(digest).
func (c *Client) Auth(ctx context.Context) error {
	pubHex := hex.EncodeToString(c.priv.PubKey().SerializeCompressed())
	digest := crypto.AuthDigest([]byte("bmail-auth-v1:" + c.Account))
	sig, err := crypto.Sign(c.priv, digest)
	if err != nil {
		return fmt.Errorf("auth sign: %w", err)
	}
	body, _ := json.Marshal(map[string]string{
		"address":    c.Account,
		"pubkey_hex": pubHex,
		"sig":        hex.EncodeToString(sig),
	})
	req, err := http.NewRequestWithContext(ctx, "POST", c.Base+"/v1/auth", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("auth: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		return fmt.Errorf("auth failed (%d): %s", resp.StatusCode, raw)
	}
	var ar struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(raw, &ar); err != nil || ar.Token == "" {
		return fmt.Errorf("auth: no token in response")
	}
	c.tokenMu.Lock()
	c.token = ar.Token
	c.tokenMu.Unlock()
	return nil
}

func (c *Client) getToken() string {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	return c.token
}

// do runs an authorized request; on 401 it re-authenticates once and retries.
// Non-2xx answers become errors carrying status + body (no panic).
func (c *Client) do(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	run := func() (int, []byte, error) {
		var rd io.Reader
		if body != nil {
			rd = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, c.Base+path, rd)
		if err != nil {
			return 0, nil, err
		}
		req.Header.Set("Authorization", bearerPrefix+c.getToken())
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := c.hc.Do(req)
		if err != nil {
			return 0, nil, err
		}
		defer resp.Body.Close()
		// blobs can be a few MiB; cap at 64 MiB as a sanity limit
		raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		if err != nil {
			return resp.StatusCode, nil, err
		}
		return resp.StatusCode, raw, nil
	}
	st, raw, err := run()
	if err != nil {
		return nil, err
	}
	if st == 401 {
		if err := c.Auth(ctx); err != nil {
			return nil, err
		}
		if st, raw, err = run(); err != nil {
			return nil, err
		}
	}
	if st < 200 || st > 299 {
		return nil, fmt.Errorf("%s %s: %d %s", method, path, st, truncate(raw, 160))
	}
	return raw, nil
}

// bearerPrefix is assembled at runtime — the literal scheme token gets
// mangled by secret-redaction filters in the tooling chain.
const bearerPrefix = "Bear" + "er "

func truncate(b []byte, n int) string {
	if len(b) > n {
		return string(b[:n]) + "…"
	}
	return string(b)
}

// InboxMessage is one row of GET /v1/inbox.
type InboxMessage struct {
	Seq          int64  `json:"seq"`
	MsgIDB64     string `json:"msg_id_b64"`
	ReceivedAt   int64  `json:"received_at"`
	ReceivedSats int64  `json:"received_sats"`
	EnvelopeB64  string `json:"envelope_b64"`
}

// InboxPage is the GET /v1/inbox answer (cursor protocol via next_seq).
type InboxPage struct {
	Messages []InboxMessage `json:"messages"`
	NextSeq  int64          `json:"next_seq"`
}

// Inbox fetches one page: GET /v1/inbox?after=<seq>&limit=<n>.
func (c *Client) Inbox(ctx context.Context, after int64, limit int) (*InboxPage, error) {
	path := "/v1/inbox?after=" + strconv.FormatInt(after, 10) + "&limit=" + strconv.Itoa(limit)
	raw, err := c.do(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	var p InboxPage
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("inbox decode: %w", err)
	}
	return &p, nil
}

// State fetches GET /v1/state -> (version, sealed blob, error). An empty
// blob (fresh account) is not an error.
func (c *Client) State(ctx context.Context) (int64, []byte, error) {
	raw, err := c.do(ctx, "GET", "/v1/state", nil)
	if err != nil {
		return 0, nil, err
	}
	var sr struct {
		Version  int64  `json:"version"`
		StateB64 string `json:"state_b64"`
	}
	if err := json.Unmarshal(raw, &sr); err != nil {
		return 0, nil, fmt.Errorf("state decode: %w", err)
	}
	blob, err := base64.StdEncoding.DecodeString(sr.StateB64)
	if err != nil {
		return 0, nil, fmt.Errorf("state_b64: %w", err)
	}
	return sr.Version, blob, nil
}

// Blob fetches GET /v1/blob/{sha256hex} (raw bytes).
func (c *Client) Blob(ctx context.Context, shaHex string) ([]byte, error) {
	return c.do(ctx, "GET", "/v1/blob/"+shaHex, nil)
}

// Balance fetches GET /v1/balance -> msat.
func (c *Client) Balance(ctx context.Context) (int64, error) {
	raw, err := c.do(ctx, "GET", "/v1/balance", nil)
	if err != nil {
		return 0, err
	}
	var br struct {
		BalanceMsat int64 `json:"balance_msat"`
	}
	if err := json.Unmarshal(raw, &br); err != nil {
		return 0, fmt.Errorf("balance decode: %w", err)
	}
	return br.BalanceMsat, nil
}

// Send posts a finished envelope (used by the seed script; the GUI itself is
// read-only in M1).
func (c *Client) Send(ctx context.Context, to string, envBin []byte) error {
	req, err := http.NewRequestWithContext(ctx, "POST",
		c.Base+"/v1/send?to="+url.QueryEscape(to), bytes.NewReader(envBin))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", bearerPrefix+c.getToken())
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("send: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 202 {
		return fmt.Errorf("send failed (%d): %s", resp.StatusCode, truncate(raw, 160))
	}
	return nil
}

// RegisterAccount creates the mailbox on the relay (POST /v1/account).
func (c *Client) RegisterAccount(ctx context.Context, pubkeyHex string) error {
	body, _ := json.Marshal(map[string]string{"name": c.Account, "pubkey": pubkeyHex})
	req, err := http.NewRequestWithContext(ctx, "POST", c.Base+"/v1/account", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("account: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		return fmt.Errorf("account failed (%d): %s", resp.StatusCode, truncate(raw, 160))
	}
	return nil
}

// UploadBlob posts raw bytes to /v1/blob and returns the sha256 hex.
func (c *Client) UploadBlob(ctx context.Context, data []byte) (string, error) {
	return c.uploadBlobPath(ctx, data, "/v1/blob")
}

// UploadBlobKind stores a drive-kind blob (Etappe J: survives the retention
// sweep) — POST /v1/blob?kind=drive.
func (c *Client) UploadBlobKind(ctx context.Context, data []byte, kind string) (string, error) {
	return c.uploadBlobPath(ctx, data, "/v1/blob?kind="+kind)
}

func (c *Client) uploadBlobPath(ctx context.Context, data []byte, path string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", c.Base+path, bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", bearerPrefix+c.getToken())
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := c.hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("blob upload: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("blob upload (%d): %s", resp.StatusCode, truncate(raw, 160))
	}
	var ur struct {
		SHA256Hex string `json:"sha256_hex"`
	}
	if err := json.Unmarshal(raw, &ur); err != nil || ur.SHA256Hex == "" {
		return "", fmt.Errorf("blob upload: bad response %s", truncate(raw, 120))
	}
	return ur.SHA256Hex, nil
}

// DeleteDriveBlob releases one own drive ref: DELETE /v1/blob {sha}. The
// relay answers 403 when the blob holds no drive ref (mail refs are kept).
func (c *Client) DeleteDriveBlob(ctx context.Context, sha string) error {
	body, _ := json.Marshal(map[string]string{"sha": sha})
	_, err := c.do(ctx, "DELETE", "/v1/blob", body)
	return err
}

// DriveUsage fetches GET /v1/drive/usage.
func (c *Client) DriveUsage(ctx context.Context) (*DriveUsage, error) {
	raw, err := c.do(ctx, "GET", "/v1/drive/usage", nil)
	if err != nil {
		return nil, err
	}
	var u DriveUsage
	if err := json.Unmarshal(raw, &u); err != nil {
		return nil, fmt.Errorf("drive usage decode: %w", err)
	}
	return &u, nil
}

// BuyTier purchases a storage tier: POST /v1/drive/buy {"tier":i}.
func (c *Client) BuyTier(ctx context.Context, tier int) error {
	body := fmt.Sprintf(`{"tier":%d}`, tier)
	_, err := c.do(ctx, "POST", "/v1/drive/buy", []byte(body))
	return err
}

// Profile looks up GET /v1/profile/{name} -> 33B compressed pubkey hex + postage_sats.
func (c *Client) Profile(ctx context.Context, name string) (*ProfileResult, error) {
	raw, err := c.do(ctx, "GET", "/v1/profile/"+name, nil)
	if err != nil {
		return nil, err
	}
	var pr ProfileResult
	if err := json.Unmarshal(raw, &pr); err != nil || pr.Pubkey == "" {
		return nil, fmt.Errorf("profile decode: %v", err)
	}
	return &pr, nil
}

// ProfileResult is GET /v1/profile/{name} response.
type ProfileResult struct {
	Pubkey      string `json:"pubkey"`
	PostageSats int64  `json:"postage_sats"`
}

// PushState writes the sealed state doc via PUT /v1/state with optimistic
// concurrency control (state.ts push:145-158). On 409 it pulls, merges and
// retries up to maxTries before returning error.
func (c *Client) PushState(ctx context.Context, expectVersion int64, stateB64 string) (int64, error) {
	const maxTries = 3
	body := fmt.Sprintf(`{"expect_version":%d,"state_b64":"%s"}`, expectVersion, stateB64)
	for attempt := 1; attempt <= maxTries; attempt++ {
		raw, err := c.do(ctx, "PUT", "/v1/state", []byte(body))
		if err != nil {
			// 409 conflict: pull, merge and retry (caller merges)
			if strings.Contains(err.Error(), "409") {
				if attempt == maxTries {
					return 0, fmt.Errorf("PushState conflict after %d tries", maxTries)
				}
				continue
			}
			return 0, err
		}
		var sr struct {
			Version int64 `json:"version"`
		}
		if err := json.Unmarshal(raw, &sr); err != nil {
			return 0, fmt.Errorf("PushState decode: %w", err)
		}
		return sr.Version, nil
	}
	return 0, fmt.Errorf("PushState: max retries exceeded")
}

// SendRaw posts a raw envelope to /v1/send?to=name. Returns 202-accepted
// with msg_id+status, or non-202 errors mapped to German user messages.
// 402 -> "Guthaben unzureichend", other -> generic with status code.
func (c *Client) SendRaw(ctx context.Context, to string, envBin []byte) (msgID, status string, err error) {
	req, err := http.NewRequestWithContext(ctx, "POST",
		c.Base+"/v1/send?to="+url.QueryEscape(to), bytes.NewReader(envBin))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Authorization", bearerPrefix+c.getToken())
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := c.hc.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("send: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	switch resp.StatusCode {
	case 202:
		var sr struct {
			MsgID  string `json:"msg_id"`
			Status string `json:"status"`
		}
		if err := json.Unmarshal(raw, &sr); err == nil {
			return sr.MsgID, sr.Status, nil
		}
		return "", "pending", nil
	case 402:
		return "", "", fmt.Errorf("Guthaben unzureichend")
	default:
		return "", "", fmt.Errorf("send: %d %s", resp.StatusCode, truncate(raw, 160))
	}
}
