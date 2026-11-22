// Etappe J1 (Drive): kind promotion is sticky, sweep spares drive shas,
// RemoveDriveRef counting, AddQuotaBytes.
package ledger

import (
	"bytes"
	"errors"
	"testing"
)

func driveSha(b byte) [32]byte {
	var s [32]byte
	copy(s[:], bytes.Repeat([]byte{b}, 32))
	return s
}

func refKind(t *testing.T, l *Ledger, acctID int64, sha [32]byte) string {
	t.Helper()
	var k string
	if err := l.db.QueryRow(`SELECT kind FROM blob_refs WHERE sha256=? AND account_id=?`,
		sha[:], acctID).Scan(&k); err != nil {
		t.Fatal(err)
	}
	return k
}

func TestDrivePromotionSticky(t *testing.T) {
	l := openTestLedger(t)
	a, err := l.CreateAccount("alice", []byte{0x02, 1}, DefaultQuotaBytes)
	if err != nil {
		t.Fatal(err)
	}
	sha := driveSha(0xA1)
	fresh, err := l.RegisterBlobRef(a.ID, sha, 100, "mail")
	if err != nil || !fresh {
		t.Fatalf("erster Upload: fresh=%v err=%v", fresh, err)
	}
	if k := refKind(t, l, a.ID, sha); k != "mail" {
		t.Fatalf("kind nach mail-Upload: %s", k)
	}
	// promotion mail→drive: row already exists (fresh=false), kind flips.
	fresh, err = l.RegisterBlobRef(a.ID, sha, 100, "drive")
	if err != nil || fresh {
		t.Fatalf("promotion: fresh=%v err=%v", fresh, err)
	}
	if k := refKind(t, l, a.ID, sha); k != "drive" {
		t.Fatalf("kind nach promotion: %s, want drive", k)
	}
	// drive→mail must NOT reset it (sticky).
	if _, err = l.RegisterBlobRef(a.ID, sha, 100, "mail"); err != nil {
		t.Fatal(err)
	}
	if k := refKind(t, l, a.ID, sha); k != "drive" {
		t.Fatalf("promotion nicht stickig: kind=%s", k)
	}
}

func TestDriveSweepSpared(t *testing.T) {
	l := openTestLedger(t)
	a, _ := l.CreateAccount("alice", []byte{0x02, 1}, DefaultQuotaBytes)
	b, _ := l.CreateAccount("bob", []byte{0x03, 2}, DefaultQuotaBytes)
	if err := l.ensureRetention(); err != nil {
		t.Fatal(err)
	}
	if err := l.ensureDrive(); err != nil {
		t.Fatal(err)
	}
	mk := func(sha byte, acctID, created, dl int64, kind string) []byte {
		s := bytes.Repeat([]byte{sha}, 32)
		if _, err := l.db.Exec(
			`INSERT INTO blob_refs (sha256, account_id, bytes, created_at, downloaded_at, kind) VALUES (?,?,?,?,?,?)`,
			s, acctID, 100, created, dl, kind); err != nil {
			t.Fatal(err)
		}
		return s
	}
	now := int64(1_000_000_000)
	day := int64(86400)
	// all long overdue (uploaded +10d, grace 7d) — only kind decides:
	shaMail := mk(0xA1, a.ID, now-20*day, now-10*day, "mail")
	shaMix := mk(0xB2, a.ID, now-20*day, now-10*day, "mail")
	mk(0xB2, b.ID, now-20*day, now-10*day, "drive")               // mixed case: one drive ref is enough
	shaDrive := mk(0xC3, a.ID, now-200*day, now-150*day, "drive") // even beyond maxAge

	victims, err := l.RetentionSweep(now, 7*day, 90*day)
	if err != nil {
		t.Fatal(err)
	}
	has := func(want []byte) bool {
		for _, v := range victims {
			if bytes.Equal(v, want) {
				return true
			}
		}
		return false
	}
	if !has(shaMail) {
		t.Error("reiner mail-sha haette gefegt werden muessen")
	}
	if has(shaMix) {
		t.Error("Misch-sha (mail+drive) muss verschont bleiben")
	}
	if has(shaDrive) {
		t.Error("drive-sha muss verschont bleiben (auch ueber maxAge)")
	}
}

func TestRemoveDriveRef(t *testing.T) {
	l := openTestLedger(t)
	a, _ := l.CreateAccount("alice", []byte{0x02, 1}, DefaultQuotaBytes)
	b, _ := l.CreateAccount("bob", []byte{0x03, 2}, DefaultQuotaBytes)
	sha := driveSha(0xD4)
	if _, err := l.RegisterBlobRef(a.ID, sha, 100, "drive"); err != nil {
		t.Fatal(err)
	}
	if _, err := l.RegisterBlobRef(b.ID, sha, 100, "mail"); err != nil {
		t.Fatal(err)
	}
	// bob holds only a mail ref → no drive access
	if own, err := l.HasDriveRef(b.ID, sha); err != nil || own {
		t.Fatalf("HasDriveRef(bob, mail-ref)=%v err=%v", own, err)
	}
	// alice released: bob's mail ref stays → remaining 1
	rem, err := l.RemoveDriveRef(a.ID, sha)
	if err != nil || rem != 1 {
		t.Fatalf("remaining=%d err=%v, want 1", rem, err)
	}
	if own, _ := l.HasDriveRef(a.ID, sha); own {
		t.Error("drive-Ref von alice muesste weg sein")
	}
	// no drive branch twice: DELETE is a no-op, remaining unchanged
	if rem, err = l.RemoveDriveRef(a.ID, sha); err != nil || rem != 1 {
		t.Fatalf("repeat: remaining=%d err=%v", rem, err)
	}
	// last ref overall → remaining 0
	sha2 := driveSha(0xE5)
	if _, err := l.RegisterBlobRef(a.ID, sha2, 50, "drive"); err != nil {
		t.Fatal(err)
	}
	if rem, err = l.RemoveDriveRef(a.ID, sha2); err != nil || rem != 0 {
		t.Fatalf("letzte ref: remaining=%d err=%v, want 0", rem, err)
	}
}

func TestAddQuotaBytes(t *testing.T) {
	l := openTestLedger(t)
	if _, err := l.CreateAccount("alice", []byte{0x02, 1}, 1000); err != nil {
		t.Fatal(err)
	}
	if err := l.AddQuotaBytes("alice", 500); err != nil {
		t.Fatal(err)
	}
	a, err := l.GetAccount("alice")
	if err != nil || a.QuotaBytes != 1500 {
		t.Fatalf("quota=%d err=%v, want 1500", a.QuotaBytes, err)
	}
	if err := l.AddQuotaBytes("alice", -1000); err != nil {
		t.Fatal(err)
	}
	if a, _ = l.GetAccount("alice"); a.QuotaBytes != 500 {
		t.Fatalf("quota nach Senkung: %d, want 500", a.QuotaBytes)
	}
	if err := l.AddQuotaBytes("nobody", 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unbekanntes Konto: %v, want ErrNotFound", err)
	}
	// usage headroom: 900 of 1000 used → +200 doesn't fit; raise quota → fits.
	sha := driveSha(0xF6)
	if _, err := l.RegisterBlobRef(a.ID, sha, 900, "drive"); err != nil {
		t.Fatal(err)
	}
	if err := l.CheckQuota("alice", 200); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("vor Erhoehung: %v, want ErrQuotaExceeded", err)
	}
	if err := l.AddQuotaBytes("alice", 1000); err != nil {
		t.Fatal(err)
	}
	if err := l.CheckQuota("alice", 200); err != nil {
		t.Fatalf("nach Erhoehung: %v", err)
	}
}
