// Etappe A: admin panel — LAN guard, node-key login handshake, overview,
// cascade delete incl. orphan blob unlink. ln is nil here: the verify seam
// (adm.verify) replaces lnd REST, the pinned node_pubkey replaces GetInfo.
package relaysrv

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/lightningmail/relay/internal/config"
	"github.com/lightningmail/relay/internal/ledger"
	"github.com/lightningmail/relay/internal/postage"
	"github.com/lightningmail/relay/internal/rates"
)

const adminTestYAML = `
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
admin:
  listen: 127.0.0.1:0
  node_pubkey: "02aabbccddeeff00112233445566778899aabbccddeeff0011223344556677abcd"
`

const testNodePub = "02aabbccddeeff00112233445566778899aabbccddeeff0011223344556677abcd"

func adminServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	yaml := strings.Replace(adminTestYAML, "%s", t.TempDir(), 1)
	cfg, err := config.ParseConfig([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	l, err := ledger.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	srv := New(cfg, l, nil, postage.New(cfg), rates.NewFeed("", 0))
	srv.adm.verify = func(msg, sig string) (string, error) {
		if sig == "good:"+msg {
			return testNodePub, nil
		}
		return "03" + strings.Repeat("ee", 32), nil // foreign node
	}
	ts := httptest.NewServer(srv.AdminRoutes())
	t.Cleanup(ts.Close)
	return srv, ts
}

func admCall(t *testing.T, method, url, tok string, body any) (int, map[string]any) {
	t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, url, rd)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if tok != "" {
		req.Header.Set("Auth"+"orization", "Bearer "+tok)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		out = map[string]any{"__raw": string(raw)}
	}
	return resp.StatusCode, out
}

func admNonce(t *testing.T, ts *httptest.Server) string {
	t.Helper()
	code, out := admCall(t, "POST", ts.URL+"/v1/admin/challenge", "", nil)
	nonce, _ := out["nonce"].(string)
	if code != 200 || len(nonce) != 32 {
		t.Fatalf("challenge: %d %v", code, out)
	}
	return nonce
}

// admLogin: full handshake, returns bearer token.
func admLogin(t *testing.T, ts *httptest.Server) string {
	t.Helper()
	nonce := admNonce(t, ts)
	code, out := admCall(t, "POST", ts.URL+"/v1/admin/login", "",
		map[string]string{"nonce": nonce, "signature": "good:" + nonce})
	if code != 200 {
		t.Fatalf("login: %d %v", code, out)
	}
	return out["token"].(string)
}

func TestAdminLoginFlow(t *testing.T) {
	_, ts := adminServer(t)
	nonce := admNonce(t, ts)

	// overview without token -> 401
	code, _ := admCall(t, "GET", ts.URL+"/v1/admin/overview", "", nil)
	if code != 401 {
		t.Fatalf("unauth overview: %d", code)
	}

	// wrong signature -> 401, and the nonce is consumed (single-use)
	code, _ = admCall(t, "POST", ts.URL+"/v1/admin/login", "",
		map[string]string{"nonce": nonce, "signature": "bogus"})
	if code != 401 {
		t.Fatalf("bad sig: %d", code)
	}
	code, _ = admCall(t, "POST", ts.URL+"/v1/admin/login", "",
		map[string]string{"nonce": nonce, "signature": "good:" + nonce})
	if code != 400 {
		t.Fatalf("replayed nonce: %d", code)
	}

	// fresh challenge, foreign node key -> 401
	nonce = admNonce(t, ts)
	code, _ = admCall(t, "POST", ts.URL+"/v1/admin/login", "",
		map[string]string{"nonce": nonce, "signature": "wrongnode:" + nonce})
	if code != 401 {
		t.Fatalf("foreign node: %d", code)
	}

	// correct key -> overview OK
	tok := admLogin(t, ts)
	code, out := admCall(t, "GET", ts.URL+"/v1/admin/overview", tok, nil)
	if code != 200 || out["relay_name"] != "relaytest" {
		t.Fatalf("overview: %d %v", code, out)
	}
}

func TestAdminDeleteCascade(t *testing.T) {
	srv, ts := adminServer(t)
	tok := admLogin(t, ts)

	// victim account with a drive blob + blob file on disk
	a, err := srv.ledger.CreateAccount("victim", []byte{2, 1, 2, 3}, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	shaBytes := bytes.Repeat([]byte{0xab}, 32)
	sha := hex.EncodeToString(shaBytes)
	var s32 [32]byte
	copy(s32[:], shaBytes)
	if _, err := srv.ledger.RegisterBlobRef(a.ID, s32, 1234, "drive"); err != nil {
		t.Fatal(err)
	}
	dir := srv.cfg.DataDir + "/blob/" + sha[:2]
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	file := dir + "/" + sha
	if err := os.WriteFile(file, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}

	// overview must list the victim
	code, ov := admCall(t, "GET", ts.URL+"/v1/admin/overview", tok, nil)
	if !strings.Contains(fmt.Sprint(ov["accounts"]), "victim") {
		t.Fatalf("victim missing in overview: code=%d %v", code, ov)
	}

	// name validation must reject uppercase/garbage
	code, _ = admCall(t, "POST", ts.URL+"/v1/admin/delete", tok, map[string]string{"name": "VICTIM!"})
	if code != 400 {
		t.Fatalf("bad name accepted: %d", code)
	}
	code, res := admCall(t, "POST", ts.URL+"/v1/admin/delete", tok, map[string]string{"name": "victim"})
	if code != 200 || res["orphan_blobs"] != float64(1) || res["files_removed"] != float64(1) {
		t.Fatalf("delete: %d %v", code, res)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatal("orphan blob file survived")
	}
	if _, err := srv.ledger.GetAccount("victim"); err == nil {
		t.Fatal("account row survived")
	}
	// idempotent second delete must not 500
	code, _ = admCall(t, "POST", ts.URL+"/v1/admin/delete", tok, map[string]string{"name": "victim"})
	if code != 200 {
		t.Fatalf("re-delete: %d", code)
	}
}

func TestPrivateIPGuard(t *testing.T) {
	for ip, want := range map[string]bool{
		"127.0.0.1": true, "10.1.2.3": true, "<dev-lan-ip>": true, "172.16.0.1": true,
		"8.8.8.8": false, "2a02:8071::1": false, "not-an-ip": false,
	} {
		if got := privateIP(ip); got != want {
			t.Fatalf("privateIP(%s)=%v want %v", ip, got, want)
		}
	}
}
