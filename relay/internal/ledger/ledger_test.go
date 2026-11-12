package ledger

import (
	"errors"
	"sync"
	"testing"
)

func openTestLedger(t *testing.T) *Ledger {
	t.Helper()
	l, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

func TestMigrateIdempotent(t *testing.T) {
	l := openTestLedger(t)
	if err := l.migrate(); err != nil {
		t.Fatalf("re-migrate: %v", err)
	}
	var v int
	if err := l.db.QueryRow("PRAGMA user_version").Scan(&v); err != nil || v != schemaVersion {
		t.Fatalf("user_version=%d err=%v", v, err)
	}
}

func TestCreateAccountAndLookup(t *testing.T) {
	l := openTestLedger(t)
	pub := make([]byte, 33)
	pub[0] = 0x02
	pub[5] = 0xAB
	a, err := l.CreateAccount("bernd", pub)
	if err != nil {
		t.Fatal(err)
	}
	if a.RecipientHash != RecipientHash(pub) {
		t.Fatal("recipient hash not sha256(mailbox_pubkey)")
	}
	if a.QuotaBytes != 104857600 {
		t.Fatalf("default quota: %d", a.QuotaBytes)
	}
	got, err := l.LookupByRecipientHash(a.RecipientHash)
	if err != nil || got.Name != "bernd" {
		t.Fatalf("lookup: %+v %v", got, err)
	}
	if _, err := l.LookupByRecipientHash([32]byte{9}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if _, err := l.CreateAccount("bernd", pub); !errors.Is(err, ErrDuplicateAccount) {
		t.Fatalf("duplicate name accepted: %v", err)
	}
}

func TestBalanceDeltaHistory(t *testing.T) {
	l := openTestLedger(t)
	pub := bytes33(1)
	if _, err := l.CreateAccount("gisela", pub); err != nil {
		t.Fatal(err)
	}
	if err := l.ApplyDelta("gisela", 10_000, KindPostageIn, "msg-a"); err != nil {
		t.Fatal(err)
	}
	if err := l.ApplyDelta("gisela", -4_000, KindWithdraw, "inv-b"); err != nil {
		t.Fatal(err)
	}
	bal, err := l.Balance("gisela")
	if err != nil || bal != 6_000 {
		t.Fatalf("balance=%d err=%v", bal, err)
	}
	a, _ := l.GetAccount("gisela")
	if a.Version != 2 {
		t.Fatalf("version must be 2 after two deltas, got %d", a.Version)
	}
	h, err := l.History("gisela", 10)
	if err != nil || len(h) != 2 {
		t.Fatalf("history len=%d err=%v", len(h), err)
	}
	if h[0].Kind != KindWithdraw || h[1].Kind != KindPostageIn {
		t.Fatalf("history order/kind: %+v", h)
	}
	if h[1].Ref != "msg-a" {
		t.Fatalf("ref lost: %+v", h[1])
	}
}

func TestInsufficientFundsLeavesNoTrace(t *testing.T) {
	l := openTestLedger(t)
	if _, err := l.CreateAccount("bernd", bytes33(2)); err != nil {
		t.Fatal(err)
	}
	if err := l.ApplyDelta("bernd", 5_000, KindTopup, "x"); err != nil {
		t.Fatal(err)
	}
	if err := l.ApplyDelta("bernd", -5_001, KindWithdraw, "y"); !errors.Is(err, ErrInsufficient) {
		t.Fatalf("want ErrInsufficient, got %v", err)
	}
	if err := l.ApplyDelta("bernd", 1, Kind("smoke_burn"), "z"); !errors.Is(err, ErrInvalidKind) {
		t.Fatalf("want ErrInvalidKind, got %v", err)
	}
	bal, _ := l.Balance("bernd")
	if bal != 5_000 {
		t.Fatalf("rejected delta changed balance to %d", bal)
	}
	h, _ := l.History("bernd", 10)
	if len(h) != 1 {
		t.Fatalf("failed ops wrote txlog: %+v", h)
	}
	if _, err := l.Balance("nobody"); !errors.Is(err, ErrNotFound) {
		t.Fatal("unknown account must error")
	}
}

func TestConcurrentNoLostUpdates(t *testing.T) {
	l := openTestLedger(t)
	if _, err := l.CreateAccount("busy", bytes33(3)); err != nil {
		t.Fatal(err)
	}
	const n = 64
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs <- l.ApplyDelta("busy", 1_000, KindPostageIn, "c")
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent ApplyDelta: %v", err)
		}
	}
	bal, _ := l.Balance("busy")
	if bal != n*1_000 {
		t.Fatalf("lost updates: balance=%d want=%d", bal, n*1_000)
	}
	h, _ := l.History("busy", n+10)
	if len(h) != n {
		t.Fatalf("txlog rows=%d want=%d", len(h), n)
	}
	a, _ := l.GetAccount("busy")
	if a.Version != n {
		t.Fatalf("version=%d want=%d", a.Version, n)
	}
}

func TestWALFileDB(t *testing.T) {
	l, err := Open(t.TempDir() + "/ledger.db")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if _, err := l.CreateAccount("bernd", bytes33(4)); err != nil {
		t.Fatal(err)
	}
	var jm string
	if err := l.db.QueryRow("PRAGMA journal_mode").Scan(&jm); err != nil || jm != "wal" {
		t.Fatalf("journal_mode=%q err=%v (WAL required for file DBs)", jm, err)
	}
}

// --- Etappe 4a: persistent tokens, blob ACL, quota ---

func TestPersistentTokens(t *testing.T) {
	l := openTestLedger(t)
	// Store a token
	if err := l.StoreToken("abc123", "bernd"); err != nil {
		t.Fatal(err)
	}
	// Lookup valid
	name, err := l.LookupToken("abc123")
	if err != nil || name != "bernd" {
		t.Fatalf("lookup: name=%q err=%v", name, err)
	}
	// Lookup invalid
	name, err = l.LookupToken("nonexistent")
	if err != nil || name != "" {
		t.Fatalf("lookup invalid: name=%q err=%v", name, err)
	}
	// Clean expired (token still valid, 24h)
	if err := l.CleanExpiredTokens(); err != nil {
		t.Fatal(err)
	}
	name, _ = l.LookupToken("abc123")
	if name != "bernd" {
		t.Fatal("token cleaned prematurely")
	}
}

func TestBlobACLAndQuota(t *testing.T) {
	l := openTestLedger(t)
	a, err := l.CreateAccount("bernd", bytes33(5))
	if err != nil {
		t.Fatal(err)
	}

	var sha [32]byte
	sha[0] = 0xAB
	sha[31] = 0xCD

	// Register blob ref
	if err := l.RegisterBlobRef(a.ID, sha, 1024); err != nil {
		t.Fatal(err)
	}

	// ACL: authorized
	ok, err := l.HasBlobAccess(a.ID, sha)
	if err != nil || !ok {
		t.Fatalf("HasBlobAccess: ok=%v err=%v", ok, err)
	}

	// ACL: other account
	ok2, err := l.HasBlobAccess(999, sha)
	if err != nil || ok2 {
		t.Fatalf("HasBlobAccess other account: ok=%v", ok2)
	}

	// Quota usage
	used, err := l.BlobUsage(a.ID)
	if err != nil || used != 1024 {
		t.Fatalf("BlobUsage: %d err=%v", used, err)
	}

	// CheckQuota: under limit
	if err := l.CheckQuota("bernd", 100); err != nil {
		t.Fatalf("CheckQuota under: %v", err)
	}

	// CheckQuota: over limit
	if err := l.CheckQuota("bernd", 200_000_000); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("CheckQuota over: want ErrQuotaExceeded, got %v", err)
	}
}

func bytes33(b byte) []byte {
	v := make([]byte, 33)
	v[0] = 0x02
	v[32] = b
	return v
}
