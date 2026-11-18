// Etappe B: Directory-Ledger (Profile, gdpr1-Consent-Log, Kartenkauf mit
// Dedup + Steuerstempel) und Migration v3→v4 (txlog currency/rate/Kinds).
package ledger

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func mustAccount(t *testing.T, l *Ledger, name string, seed int64) *Account {
	t.Helper()
	a, err := l.CreateAccount(name, bytes33(byte(len(name))))
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

func TestProfilePutGetDelete(t *testing.T) {
	l := openTestLedger(t)
	a := mustAccount(t, l, "gisela", 0)
	card := `{"name":"Holzer","email":"g@example.org"}`
	consent := `{"v":"gdpr1","ts":1760000000,"fields":["name","email"],"purpose":"directory"}`

	if _, err := l.GetProfileByName("gisela"); !errors.Is(err, ErrNoProfile) {
		t.Fatalf("want ErrNoProfile, got %v", err)
	}
	p, err := l.PutProfile(a.ID, card, "aa", consent, 25)
	if err != nil {
		t.Fatal(err)
	}
	if p.CardHash != CardHashOf([]byte(card)) {
		t.Fatal("card_hash nicht sha256(card)")
	}
	got, err := l.GetProfileByName("gisela")
	if err != nil || got.CardJSON != card || got.PriceMEur != 25 || got.Consent != consent {
		t.Fatalf("roundtrip: %+v %v", got, err)
	}
	// Update = UPSERT, Consent-Log waechst append-only
	if _, err := l.PutProfile(a.ID, card+` `, "bb", consent, 40); err != nil {
		t.Fatal(err)
	}
	var nLog int
	if err := l.db.QueryRow(`SELECT COUNT(*) FROM consent_log WHERE account_id=?`, a.ID).Scan(&nLog); err != nil || nLog != 2 {
		t.Fatalf("consent_log Zeilen = %d (want 2), err=%v", nLog, err)
	}
	if ok, _ := l.HasProfile(a.ID); !ok {
		t.Fatal("HasProfile false nach PUT")
	}
	// DELETE = DSGVO: Karte + Consent-Historie weg, idempotent
	if err := l.DeleteProfile(a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := l.GetProfileByName("gisela"); !errors.Is(err, ErrNoProfile) {
		t.Fatalf("nach DELETE: %v", err)
	}
	if err := l.db.QueryRow(`SELECT COUNT(*) FROM consent_log WHERE account_id=?`, a.ID).Scan(&nLog); err != nil || nLog != 0 {
		t.Fatalf("consent_log nach DELETE = %d (want 0)", nLog)
	}
	if err := l.DeleteProfile(a.ID); err != nil {
		t.Fatalf("DELETE nicht idempotent: %v", err)
	}
}

func TestBuyCardDedupAndStamp(t *testing.T) {
	l := openTestLedger(t)
	mustAccount(t, l, "seller", 0)
	mustAccount(t, l, "buyer", 500_000) // 500 sat
	rate := &RateStamp{MEurPerBtc: 50_000_000, Ts: 1760000000, Src: "manual"} // 50k EUR/BTC
	// 5 ct gesamt = 100 sat; Split 50/50 (2,5+2,5 ct Default)
	fresh, err := l.BuyCard("buyer", "seller", "hash1", 100_000, 50_000, 50_000, "btc", rate)
	if err != nil || !fresh {
		t.Fatalf("erster Kauf: fresh=%v err=%v", fresh, err)
	}
	if b, _ := l.Balance("buyer"); b != 400_000 {
		t.Fatalf("Kaeufer-Balance %d, want 400000", b)
	}
	if s, _ := l.Balance("seller"); s != 50_000 {
		t.Fatalf("Verkaeufer-Balance %d, want 50000", s)
	}
	// Dedup: gleicher card_hash → keine Buchung, kein Geld
	fresh, err = l.BuyCard("buyer", "seller", "hash1", 100_000, 50_000, 50_000, "btc", rate)
	if err != nil || fresh {
		t.Fatalf("Dedup: fresh=%v err=%v", fresh, err)
	}
	if b, _ := l.Balance("buyer"); b != 400_000 {
		t.Fatalf("Dedup hat Geld bewegt: %d", b)
	}
	// Steuerstempel (§25 G1): card_in-Zeile des Verkaeufers mit µEUR + Kurs
	hist, err := l.History("seller", 10)
	if err != nil || len(hist) != 1 {
		t.Fatalf("seller history: %v %v", hist, err)
	}
	tx := hist[0]
	if tx.Kind != KindCardIn || tx.Currency != "btc" || tx.RateSrc != "manual" || tx.RateTs != 1760000000 {
		t.Fatalf("Stempel falsch: %+v", tx)
	}
	// 50 sat bei 50k EUR/BTC = 0,025 EUR = 25000 µEUR
	if tx.EurMicro != 25_000 {
		t.Fatalf("eur_micro = %d, want 25000", tx.EurMicro)
	}
	bh, _ := l.History("buyer", 10)
	found := false
	for _, x := range bh {
		if x.Kind == KindCardOut && x.Ref == "hash1" && x.EurMicro == -50_000 {
			found = true
		}
	}
	if !found {
		t.Fatalf("card_out-Zeile mit Stempel fehlt: %+v", bh)
	}
	// Insufficient + Self-Purchase
	if _, err := l.BuyCard("buyer", "seller", "hash2", 999_999_999, 1, 1, "btc", rate); !errors.Is(err, ErrInsufficient) {
		t.Fatalf("want ErrInsufficient, got %v", err)
	}
	if _, err := l.BuyCard("buyer", "buyer", "hash3", 1, 1, 0, "btc", rate); err == nil {
		t.Fatal("Self-Purchase akzepiert")
	}
	// HasPurchase / BoughtFrom
	if ok, _ := l.HasPurchase("buyer", "hash1"); !ok {
		t.Fatal("HasPurchase(hash1) false")
	}
	if ok, _ := l.HasPurchase("buyer", "hash9"); ok {
		t.Fatal("HasPurchase(hash9) true")
	}
	if ok, _ := l.BoughtFrom("buyer", "seller"); !ok {
		t.Fatal("BoughtFrom false")
	}
	if ok, _ := l.BoughtFrom("seller", "buyer"); ok {
		t.Fatal("BoughtFrom rückwaerts true")
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

// Alte v3-DB (txlog ohne currency/Stempel, altes kind-CHECK) muss nach
// Open() auf v4 sein: Zeilen erhalten, neue Kinds buchbar.
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
	// v3-DB direkt per Treiber anlegen (Open() wuerde sofort migrieren)
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
	// Neue Kinds muessen durch das umgebaute CHECK gehen
	if err := l.ApplyDeltaMeta("alt", 1000, KindCardIn, "neu", "btc", &RateStamp{MEurPerBtc: 50_000_000, Ts: 1760000000, Src: "manual"}); err != nil {
		t.Fatalf("card_in nach Migration: %v", err)
	}
	hist, _ = l.History("alt", 10)
	if hist[0].Kind != KindCardIn || hist[0].EurMicro != 500 {
		t.Fatalf("Neuzeile falsch: %+v", hist[0])
	}
}
