// Etappe J1: drive endpoints — disabled/enabled, upload+usage+release via
// routes(), foreign-sha 403, tier purchase (money + quota + txlog), 402 when broke.
package relaysrv

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/lightningmail/relay/internal/config"
	"github.com/lightningmail/lm1/crypto"
	"github.com/lightningmail/relay/internal/ledger"
	"github.com/lightningmail/relay/internal/postage"
	"github.com/lightningmail/relay/internal/rates"
)

const driveTestYAML = `
name: relaytest
listen_addr: 127.0.0.1:0
data_dir: %s
lnd:
  rpc_host: 127.0.0.1:1
  tls_cert_path: /nonexistent
  macaroon_path: /nonexistent
postage:
  foreign_sats: 10
  min_sats: 1
drive:
  enabled: true
  quota_mb: 10
  tiers:
    - gb: 5
      sats: 5000
`

// driveServer: alice (tok-a) + bob (tok-b), httptest via routes() (ui_test pattern).
func driveServer(t *testing.T) (*Server, string) {
	t.Helper()
	cfg, err := config.ParseConfig([]byte(strings.Replace(driveTestYAML, "%s", t.TempDir(), 1)))
	if err != nil {
		t.Fatal(err)
	}
	l, err := ledger.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	for name, tok := range map[string]string{"alice": "tok-a", "bob": "tok-b"} {
		priv, _ := crypto.GenerateKeyPair()
		pub := crypto.PublicBytes(priv)
		if _, err := l.CreateAccount(name, pub[:], cfg.Drive.QuotaMB*1048576); err != nil {
			t.Fatal(err)
		}
		if err := l.StoreToken(tok, name); err != nil {
			t.Fatal(err)
		}
	}
	srv := New(cfg, l, nil, postage.New(cfg), rates.NewFeed("", 0))
	ts := httptest.NewServer(srv.routes())
	t.Cleanup(ts.Close)
	return srv, ts.URL
}

// driveReq: string body goes out raw (uploads), everything else as JSON.
func driveReq(t *testing.T, method, target, tok string, body any) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		if s, ok := body.(string); ok {
			rd = strings.NewReader(s)
		} else {
			j, _ := json.Marshal(body)
			rd = bytes.NewReader(j)
		}
	}
	r, _ := http.NewRequest(method, target, rd)
	if tok != "" {
		r.Header.Set("Authorization", "Bearer "+tok)
	}
	res, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(res.Body)
	res.Body.Close()
	return res.StatusCode, raw
}

func TestDriveDisabled(t *testing.T) {
	srv, url := driveServer(t)
	srv.cfg.Drive.Enabled = false
	if code, body := driveReq(t, "POST", url+"/v1/blob?kind=drive", "tok-a", "hello"); code != 404 ||
		!strings.Contains(string(body), "drive disabled") {
		t.Fatalf("drive-upload disabled: %d %s", code, body)
	}
	if code, _ := driveReq(t, "POST", url+"/v1/drive/buy", "tok-a", map[string]int{"tier": 0}); code != 404 {
		t.Fatalf("buy disabled: %d", code)
	}
	// mail uploads stay untouched
	if code, body := driveReq(t, "POST", url+"/v1/blob", "tok-a", "hello"); code != 200 {
		t.Fatalf("mail-upload: %d %s", code, body)
	}
	// broken kind → 400
	if code, _ := driveReq(t, "POST", url+"/v1/blob?kind=quux", "tok-a", "hello"); code != 400 {
		t.Fatalf("kind=quux: %d, want 400", code)
	}
}

func TestDriveUploadUsageRelease(t *testing.T) {
	srv, url := driveServer(t)
	// /health reports the drive section
	code, body := driveReq(t, "GET", url+"/health", "", nil)
	var hj map[string]any
	json.Unmarshal(body, &hj)
	d, _ := hj["drive"].(map[string]any)
	if code != 200 || d == nil || d["enabled"] != true || d["quota_mb"].(float64) != 10 {
		t.Fatalf("health: %d %s", code, body)
	}

	payload := "drive-file-content"
	h := sha256.Sum256([]byte(payload))
	hexSha := hex.EncodeToString(h[:])
	code, body = driveReq(t, "POST", url+"/v1/blob?kind=drive", "tok-a", payload)
	if code != 200 {
		t.Fatalf("upload: %d %s", code, body)
	}
	var up struct {
		Sha256Hex string `json:"sha256_hex"`
	}
	json.Unmarshal(body, &up)
	if up.Sha256Hex != hexSha {
		t.Fatalf("sha: %s, want %s", up.Sha256Hex, hexSha)
	}
	path := srv.cfg.DataDir + "/blob/" + hexSha[:2] + "/" + hexSha
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("datei fehlt: %v", err)
	}
	// usage counts the drive blob
	code, body = driveReq(t, "GET", url+"/v1/drive/usage", "tok-a", nil)
	var us struct {
		Enabled bool                       `json:"enabled"`
		Used    int64                      `json:"used_bytes"`
		Quota   int64                      `json:"quota_bytes"`
		Tiers   []struct{ GB, Sats int64 } `json:"tiers"`
	}
	json.Unmarshal(body, &us)
	if code != 200 || !us.Enabled || us.Used != int64(len(payload)) ||
		us.Quota != 10*1048576 || len(us.Tiers) != 1 || us.Tiers[0].GB != 5 || us.Tiers[0].Sats != 5000 {
		t.Fatalf("usage: %d %s", code, body)
	}
	// release: last ref → file gone, usage drops to 0
	code, body = driveReq(t, "DELETE", url+"/v1/blob", "tok-a", map[string]string{"sha": hexSha})
	if code != 200 {
		t.Fatalf("release: %d %s", code, body)
	}
	var rel struct {
		Released  bool  `json:"released"`
		Remaining int64 `json:"remaining_refs"`
	}
	json.Unmarshal(body, &rel)
	if !rel.Released || rel.Remaining != 0 {
		t.Fatalf("release body: %s", body)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("datei muesste nach letzter Ref geloescht sein")
	}
	_, body = driveReq(t, "GET", url+"/v1/drive/usage", "tok-a", nil)
	us = struct {
		Enabled bool                       `json:"enabled"`
		Used    int64                      `json:"used_bytes"`
		Quota   int64                      `json:"quota_bytes"`
		Tiers   []struct{ GB, Sats int64 } `json:"tiers"`
	}{}
	json.Unmarshal(body, &us)
	if us.Used != 0 {
		t.Fatalf("usage nach release: %s", body)
	}
}

func TestDriveReleaseForeign(t *testing.T) {
	srv, url := driveServer(t)
	payload := "bobs-secret-file"
	h := sha256.Sum256([]byte(payload))
	hexSha := hex.EncodeToString(h[:])
	if code, body := driveReq(t, "POST", url+"/v1/blob?kind=drive", "tok-b", payload); code != 200 {
		t.Fatalf("bob upload: %d %s", code, body)
	}
	// alice must not release bob's sha
	if code, _ := driveReq(t, "DELETE", url+"/v1/blob", "tok-a", map[string]string{"sha": hexSha}); code != 403 {
		t.Fatalf("fremdes sha: %d, want 403", code)
	}
	path := srv.cfg.DataDir + "/blob/" + hexSha[:2] + "/" + hexSha
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("datei darf nicht verschwinden: %v", err)
	}
	// broken sha → 400
	if code, _ := driveReq(t, "DELETE", url+"/v1/blob", "tok-a", map[string]string{"sha": "xyz"}); code != 400 {
		t.Fatalf("bad sha: %d, want 400", code)
	}
	// without token → 401 (auth middleware)
	if code, _ := driveReq(t, "DELETE", url+"/v1/blob", "", map[string]string{"sha": hexSha}); code != 401 {
		t.Fatalf("ohne token: %d, want 401", code)
	}
}

func TestDriveBuy(t *testing.T) {
	srv, url := driveServer(t)
	// alice: 10,000 sats balance
	if err := srv.ledger.ApplyDelta("alice", 10_000_000, ledger.KindTopup, "test-faucet"); err != nil {
		t.Fatal(err)
	}
	code, body := driveReq(t, "POST", url+"/v1/drive/buy", "tok-a", map[string]int{"tier": 0})
	if code != 200 {
		t.Fatalf("buy: %d %s", code, body)
	}
	var out struct {
		Quota    int64 `json:"quota_bytes"`
		CostSats int64 `json:"cost_sats"`
	}
	json.Unmarshal(body, &out)
	if want := int64(10*1048576 + 5*1073741824); out.Quota != want || out.CostSats != 5000 {
		t.Fatalf("buy body: %s (want quota %d)", body, want)
	}
	if bal, _ := srv.ledger.Balance("alice"); bal != 10_000_000-5_000_000 {
		t.Fatalf("balance: %d, want 5000000 msat", bal)
	}
	hist, err := srv.ledger.History("alice", 10)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, tx := range hist {
		if tx.Kind == ledger.KindFee && tx.Ref == "drive-tier:5GB" && tx.DeltaMsat == -5_000_000 {
			found = true
		}
	}
	if !found {
		t.Fatalf("txlog ref 'drive-tier:5GB' fehlt: %+v", hist)
	}
	// invalid tier index → 400
	if code, _ := driveReq(t, "POST", url+"/v1/drive/buy", "tok-a", map[string]int{"tier": 9}); code != 400 {
		t.Fatalf("tier=9: %d, want 400", code)
	}
	// broke → 402 (byteporto response shape)
	bal, _ := srv.ledger.Balance("alice")
	if err := srv.ledger.ApplyDelta("alice", -bal, ledger.KindWithdraw, "drain"); err != nil {
		t.Fatal(err)
	}
	code, body = driveReq(t, "POST", url+"/v1/drive/buy", "tok-a", map[string]int{"tier": 0})
	if code != 402 || !strings.Contains(string(body), "insufficient balance") {
		t.Fatalf("pleite: %d %s, want 402", code, body)
	}
}
