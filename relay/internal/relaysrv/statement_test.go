// G2 handlers: /v1/statement (CSV/JSON, chain) + /v1/relay/statement (secret).
package relaysrv

import (
	"encoding/csv"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lightningmail/relay/internal/config"
	"github.com/lightningmail/relay/internal/crypto"
	"github.com/lightningmail/relay/internal/ledger"
	"github.com/lightningmail/relay/internal/postage"
	"github.com/lightningmail/relay/internal/rates"
)

const stmtTestYAML = `
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
relay_secret: stmt-secret
`

func stmtServer(t *testing.T) *Server {
	t.Helper()
	cfg, err := config.ParseConfig([]byte(strings.Replace(stmtTestYAML, "%s", t.TempDir(), 1)))
	if err != nil {
		t.Fatal(err)
	}
	l, err := ledger.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	priv, _ := crypto.GenerateKeyPair()
	pub := crypto.PublicBytes(priv)
	if _, err := l.CreateAccount("s1", pub[:], ledger.DefaultQuotaBytes); err != nil {
		t.Fatal(err)
	}
	if err := l.StoreToken("tok1", "s1"); err != nil {
		t.Fatal(err)
	}
	rate := &ledger.RateStamp{MEurPerBtc: 50_000_000, Ts: 1760000000, Src: "manual"}
	if err := l.ApplyDelta("s1", 1_000_000, ledger.KindTopup, "seed"); err != nil {
		t.Fatal(err)
	}
	if err := l.ApplyDeltaMeta("s1", -20_000, ledger.KindFee, "blob:abc", "btc", rate); err != nil {
		t.Fatal(err)
	}
	return New(cfg, l, nil, postage.New(cfg), rates.NewFeed("", 0))
}

func TestStatementCSVAndChain(t *testing.T) {
	srv := stmtServer(t)
	r := httptest.NewRequest("GET", "/v1/statement?fmt=csv", nil)
	r.Header.Set("X-Bmail-Account", "s1")
	w := httptest.NewRecorder()
	srv.handleStatement(w, r)
	if w.Code != 200 {
		t.Fatalf("csv: %d %s", w.Code, w.Body.String())
	}
	if ct := w.Result().Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Fatalf("content-type: %s", ct)
	}
	rd := csv.NewReader(strings.NewReader(w.Body.String()))
	rd.FieldsPerRecord = -1
	recs, err := rd.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(recs[0][0], "# bmail-statement") {
		t.Fatalf("Kopfkommentar fehlt: %v", recs[0])
	}
	// header row + 2 data rows
	hdr := recs[2]
	if hdr[0] != "id" || hdr[len(hdr)-1] != "hash" || hdr[len(hdr)-2] != "prev_hash" {
		t.Fatalf("Header: %v", hdr)
	}
	if len(recs) != 5 {
		t.Fatalf("Zeilen: %d (%v)", len(recs), recs)
	}
	// check the chain: genesis → row1 → row2
	gen := ledger.GenesisHash("s1")
	if recs[3][len(hdr)-2] != gen {
		t.Fatal("erste Zeile haengt nicht am Genesis")
	}
	if recs[3][len(hdr)-1] != recs[4][len(hdr)-2] {
		t.Fatal("Kette zwischen Zeile 1 und 2 gerissen")
	}
	// unrated row: eur_micro empty; stamped: 20000 msat fee → −20000 delta, eur_micro negative
	if recs[3][6] != "" {
		t.Fatalf("ungeratete Zeile mit eur_micro: %v", recs[3])
	}
	if recs[4][6] != "-10000" || recs[4][8] != "manual" {
		t.Fatalf("gestempelte Zeile: %v", recs[4])
	}
}

func TestStatementJSON(t *testing.T) {
	srv := stmtServer(t)
	r := httptest.NewRequest("GET", "/v1/statement", nil)
	r.Header.Set("X-Bmail-Account", "s1")
	w := httptest.NewRecorder()
	srv.handleStatement(w, r)
	var j map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &j); err != nil {
		t.Fatal(err)
	}
	if j["konto"] != "s1" || j["genesis"] != ledger.GenesisHash("s1") {
		t.Fatalf("json: %v", j)
	}
	rows := j["zeilen"].([]any)
	if len(rows) != 2 {
		t.Fatalf("zeilen: %d", len(rows))
	}
	z2 := rows[1].(map[string]any)
	if z2["art"] != "fee" || z2["eur"].(float64) != -0.01 {
		t.Fatalf("zeile2: %v", z2)
	}
}

func TestOperatorStatementSecret(t *testing.T) {
	srv := stmtServer(t)
	// without secret → 403
	w := httptest.NewRecorder()
	srv.handleOperatorStatement(w, httptest.NewRequest("GET", "/v1/relay/statement", nil))
	if w.Code != 403 {
		t.Fatalf("ohne secret: %d", w.Code)
	}
	// with secret → 200 + byte_porto row (sign flipped: +20000)
	r := httptest.NewRequest("GET", "/v1/relay/statement?fmt=csv", nil)
	r.Header.Set("X-Relay-Secret", "stmt-secret")
	w = httptest.NewRecorder()
	srv.handleOperatorStatement(w, r)
	if w.Code != 200 {
		t.Fatalf("mit secret: %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "byte_porto") || !strings.Contains(body, "20000") {
		t.Fatalf("operator-csv: %s", body)
	}
	if !strings.Contains(body, ledger.OperatorGenesisHash("relaytest")) {
		t.Fatal("operator-genesis fehlt")
	}
}
