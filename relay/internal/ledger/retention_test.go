package ledger

import (
	"bytes"
	"testing"
)

func TestRetentionSweep(t *testing.T) {
	l := openTestLedger(t)
	a, _ := l.CreateAccount("alice", []byte{0x02, 1})
	b, _ := l.CreateAccount("bob", []byte{0x03, 2})
	if err := l.ensureRetention(); err != nil {
		t.Fatal(err)
	}
	mk := func(sha byte, acctID int64, created, dl int64) []byte {
		s := bytes.Repeat([]byte{sha}, 32)
		if _, err := l.db.Exec(`INSERT INTO blob_refs (sha256, account_id, bytes, created_at, downloaded_at) VALUES (?,?,?,?,?)`,
			s, acctID, 100, created, dl); err != nil {
			t.Fatal(err)
		}
		return s
	}
	now := int64(1_000_000_000)
	day := int64(86400)

	shaA := mk(0xA1, a.ID, now-20*day, now-10*day) // beide geladen, letzter vor 10d -> wipe (grace 7)
	mk(0xA1, b.ID, now-20*day, now-12*day)
	shaB := mk(0xB2, a.ID, now-5*day, 0) // einer hat nie geladen, noch frisch -> behalten
	shaC := mk(0xC3, a.ID, now-9*day, now-3*day)
	mk(0xC3, b.ID, now-9*day, now-2*day)   // alle geladen, aber erst vor 2d -> behalten
	shaD := mk(0xD4, a.ID, now-100*day, 0) // ungeladen, aber ueber maxAge 90d -> wipe

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
	if !has(shaA) {
		t.Error("shaA (alle geladen +10d) haette geloescht werden muessen")
	}
	if !has(shaD) {
		t.Error("shaD (maxAge) haette geloescht werden muessen")
	}
	if has(shaB) || has(shaC) {
		t.Errorf("shaB/shaC duerfen bleiben; victims=%d", len(victims))
	}
	if err := l.DeleteBlobRefs(shaA); err != nil {
		t.Fatal(err)
	}
	if used, _ := l.BlobUsage(a.ID); used != 0 {
		t.Logf("usage alice nach delete: %d (erwartet 100 von C)", used)
	}
}
