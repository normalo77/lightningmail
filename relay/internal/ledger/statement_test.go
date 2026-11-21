// G2 (§25): Hash-Ketten-Statement — Konto- und Betreiber-Sicht.
package ledger

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func mustAccount(t *testing.T, l *Ledger, name string, seed int64) *Account {
	t.Helper()
	a, err := l.CreateAccount(name, bytes33(byte(len(name))), DefaultQuotaBytes)
	if err != nil {
		t.Fatal(err)
	}
	if seed > 0 {
		if err := l.ApplyDelta(name, seed, KindTopup, "seed"); err != nil {
			t.Fatal(err)
		}
	}
	return a
}

func TestStatementChainKonto(t *testing.T) {
	l := openTestLedger(t)
	mustAccount(t, l, "s1", 0)
	rate := &RateStamp{MEurPerBtc: 50_000_000, Ts: 1760000000, Src: "manual"}
	if err := l.ApplyDelta("s1", 1_000_000, KindTopup, "seed"); err != nil { // ungeratet
		t.Fatal(err)
	}
	if err := l.ApplyDeltaMeta("s1", 50_000, KindPostageIn, "msg1", "btc", rate); err != nil {
		t.Fatal(err)
	}
	rows, head, err := l.StatementChain("s1", 0, 0)
	if err != nil || len(rows) != 2 {
		t.Fatalf("rows=%d err=%v", len(rows), err)
	}
	// Genesis + Verkettung muss exakt der Doku-Formel folgen
	if rows[0].PrevHash != GenesisHash("s1") {
		t.Fatal("erste Zeile haengt nicht am Genesis")
	}
	if rows[0].Hash != shaHex(rows[0].PrevHash+rows[0].CanonRow()) {
		t.Fatal("hash(0) falsch")
	}
	if rows[1].PrevHash != rows[0].Hash || rows[1].Hash != shaHex(rows[1].PrevHash+rows[1].CanonRow()) {
		t.Fatal("Kette gerissen")
	}
	if head != rows[1].Hash {
		t.Fatal("head != letzter Hash")
	}
	// Zeile 1 ungeratet (NULL bleibt NULL → Canon ""), Zeile 2 gestempelt
	if rows[0].EurMicro != nil || rows[0].RateSrc != nil {
		t.Fatalf("ungeratete Zeile hat Stempel: %+v", rows[0])
	}
	if rows[1].EurMicro == nil || *rows[1].EurMicro != 25_000 || *rows[1].RateSrc != "manual" {
		t.Fatalf("Stempel falsch: %+v", rows[1])
	}
	// from filtert NUR die Ausgabe — Kopf bleibt derselbe (Kette laeuft durch)
	rows2, head2, err := l.StatementChain("s1", rows[1].CreatedAt+1, 0)
	if err != nil || len(rows2) != 0 || head2 != head {
		t.Fatalf("from-Filter: rows=%d head-gleich=%v err=%v", len(rows2), head2 == head, err)
	}
}

func TestOperatorChain(t *testing.T) {
	l := openTestLedger(t)
	mustAccount(t, l, "buyer", 500_000)
	rate := &RateStamp{MEurPerBtc: 50_000_000, Ts: 1760000000, Src: "manual"}
	// Byte-Porto (fee, negativ beim Nutzer) + Refund
	if err := l.ApplyDeltaMeta("buyer", -20_000, KindFee, "blob:abc", "btc", rate); err != nil {
		t.Fatal(err)
	}
	if err := l.ApplyDelta("buyer", 5_000, KindFee, "refund:blob:abc"); err != nil {
		t.Fatal(err)
	}
	rows, head, err := l.OperatorChain("relaytest", 0, 0)
	if err != nil || len(rows) != 2 {
		t.Fatalf("rows=%d err=%v", len(rows), err)
	}
	byLabel := map[string]OpRow{}
	for _, r := range rows {
		byLabel[r.Label] = r
	}
	if b := byLabel["byte_porto"]; b.AmountMsat != 20_000 || b.EurMicro == nil || *b.EurMicro != 10_000 || b.Source != "txlog" {
		t.Fatalf("byte_porto (Vorzeichen gedreht + EUR): %+v", b)
	}
	if rf := byLabel["refund"]; rf.AmountMsat != -5_000 {
		t.Fatalf("refund muss negativ sein (Betreiber zahlt zurueck): %+v", rf)
	}
	// Kette + Determinismus
	prev := OperatorGenesisHash("relaytest")
	for _, r := range rows {
		if r.PrevHash != prev || r.Hash != shaHex(prev+r.CanonRow()) {
			t.Fatal("Operator-Kette gerissen")
		}
		prev = r.Hash
	}
	if head != prev {
		t.Fatal("head falsch")
	}
	rows2, head2, _ := l.OperatorChain("relaytest", 0, 0)
	if head2 != head || len(rows2) != len(rows) {
		t.Fatal("nicht deterministisch")
	}
}

func TestRateStampEurMicro(t *testing.T) {
	r := &RateStamp{MEurPerBtc: 50_000_000} // 50k EUR/BTC
	// 100 sat = 1e-6 BTC = 0,05 EUR = 50000 µEUR
	if got := r.EurMicro(100_000); got != 50_000 {
		t.Fatalf("EurMicro(100sat) = %d, want 50000", got)
	}
	// 1 sat = 500 µEUR
	if got := r.EurMicro(1_000); got != 500 {
		t.Fatalf("EurMicro(1sat) = %d, want 500", got)
	}
	var nilRate *RateStamp
	if nilRate.EurMicro(1000) != 0 {
		t.Fatal("nil-Rate muss 0 liefern")
	}
}

func TestMigrate3to4(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ledger.db")
	oldDDL := `
CREATE TABLE account (
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE,
  mailbox_pubkey BLOB NOT NULL, recipient_hash BLOB NOT NULL UNIQUE,
  balance_msat INTEGER NOT NULL DEFAULT 0 CHECK (balance_msat >= 0),
  quota_bytes INTEGER NOT NULL DEFAULT 104857600,
  version INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
CREATE TABLE txlog (
  id INTEGER PRIMARY KEY AUTOINCREMENT, account_id INTEGER NOT NULL REFERENCES account(id),
  delta_msat INTEGER NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('postage_out','postage_in','topup','withdraw','fee')),
  ref TEXT, created_at INTEGER NOT NULL);
CREATE INDEX txlog_account_idx ON txlog(account_id, id);
CREATE TABLE IF NOT EXISTS mailbox (msg_id BLOB NOT NULL PRIMARY KEY, account_id INTEGER NOT NULL,
  envelope BLOB NOT NULL, received_msat INTEGER NOT NULL DEFAULT 0, seq INTEGER NOT NULL DEFAULT 0,
  seen INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS auth_tokens (token_hash BLOB NOT NULL PRIMARY KEY,
  account_name TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS blob_refs (sha256 BLOB NOT NULL, account_id INTEGER NOT NULL,
  bytes INTEGER NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY (sha256, account_id));
INSERT INTO account (name, mailbox_pubkey, recipient_hash, balance_msat, version, created_at, updated_at)
  VALUES ('alt', x'0201', x'aa', 12345, 3, 1700000000, 1700000000);
INSERT INTO txlog (account_id, delta_msat, kind, ref, created_at)
  VALUES (1, 12345, 'topup', 'alt-ref', 1700000000);
PRAGMA user_version=3;`
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(oldDDL); err != nil {
		t.Fatalf("v3-Anlage: %v", err)
	}
	raw.Close()

	l, err := Open(path) // → migrate3to4
	if err != nil {
		t.Fatalf("Open v3→v4: %v", err)
	}
	defer l.Close()
	var v int
	if err := l.db.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil || v != 4 {
		t.Fatalf("user_version = %d, want 4", v)
	}
	hist, err := l.History("alt", 10)
	if err != nil || len(hist) != 1 || hist[0].Ref != "alt-ref" || hist[0].DeltaMsat != 12345 || hist[0].Currency != "btc" {
		t.Fatalf("Altzeile verloren/kaputt: %+v %v", hist, err)
	}
	if hist[0].RateSrc != "" {
		t.Fatalf("Altzeile darf nicht geraten sein: %+v", hist[0])
	}
	if err := l.ApplyDeltaMeta("alt", 1000, KindPostageIn, "neu", "btc", &RateStamp{MEurPerBtc: 50_000_000, Ts: 1760000000, Src: "manual"}); err != nil {
		t.Fatalf("postage_in nach Migration: %v", err)
	}
	hist, _ = l.History("alt", 10)
	if hist[0].Kind != KindPostageIn || hist[0].EurMicro != 500 {
		t.Fatalf("Neuzeile falsch: %+v", hist[0])
	}
}
