package ledger

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestDeliverLocalAtomic(t *testing.T) {
	l, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	alicePub := make([]byte, 33)
	alicePub[0] = 2
	alice, err := l.CreateAccount("alice", alicePub, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.ApplyDelta("alice", 50_000, KindTopup, "init"); err != nil {
		t.Fatal(err)
	}
	bobPub := make([]byte, 33)
	bobPub[0] = 3
	bob, err := l.CreateAccount("bob", bobPub, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.ApplyDelta("bob", 10_000, KindTopup, "init"); err != nil {
		t.Fatal(err)
	}

	var mid [32]byte
	mid[0] = 0x42
	ins, err := l.DeliverLocal("alice", bob.ID, "bob", mid, []byte("env"), 10_000, "42", nil)
	if err != nil || !ins {
		t.Fatalf("DeliverLocal: ins=%v err=%v", ins, err)
	}
	a, _ := l.GetAccount("alice")
	b, _ := l.GetAccount("bob")
	if a.BalanceMsat != 40_000 || b.BalanceMsat != 20_000 {
		t.Fatalf("balances mismatch: alice=%d bob=%d", a.BalanceMsat, b.BalanceMsat)
	}

	// Idempotent replay: must not debit/credit a second time
	ins2, err := l.DeliverLocal("alice", bob.ID, "bob", mid, []byte("env"), 10_000, "42", nil)
	if err != nil || ins2 {
		t.Fatalf("replay should be no-op: ins=%v err=%v", ins2, err)
	}
	a, _ = l.GetAccount("alice")
	b, _ = l.GetAccount("bob")
	if a.BalanceMsat != 40_000 || b.BalanceMsat != 20_000 {
		t.Fatalf("replay mutated balances: alice=%d bob=%d", a.BalanceMsat, b.BalanceMsat)
	}

	// Insufficient balance: rolls back completely, no mailbox row created
	var mid2 [32]byte
	mid2[0] = 0x43
	if _, err := l.DeliverLocal("alice", bob.ID, "bob", mid2, []byte("env2"), 999_000, "43", nil); !errors.Is(err, ErrInsufficient) {
		t.Fatalf("expected ErrInsufficient, got %v", err)
	}
	msgs, _ := l.ListMessages(bob.ID, 0, 10)
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message after rollback, got %d", len(msgs))
	}

	// Self-mail: net 0 balance change, message delivered
	var mid3 [32]byte
	mid3[0] = 0x44
	if ins3, err := l.DeliverLocal("alice", alice.ID, "alice", mid3, []byte("self"), 5_000, "44", nil); err != nil || !ins3 {
		t.Fatalf("self-mail failed: ins=%v err=%v", ins3, err)
	}
	a, _ = l.GetAccount("alice")
	if a.BalanceMsat != 40_000 {
		t.Fatalf("self-mail should net to 0, got %d", a.BalanceMsat)
	}
}

func TestSpoolMarkDeadAndRefundAtomic(t *testing.T) {
	l, err := Open(filepath.Join(t.TempDir(), "spool.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	alicePub := make([]byte, 33)
	alicePub[0] = 2
	if _, err := l.CreateAccount("alice", alicePub, 1<<20); err != nil {
		t.Fatal(err)
	}
	if err := l.ApplyDelta("alice", 5_000, KindTopup, "init"); err != nil {
		t.Fatal(err)
	}
	ok, err := l.SpoolEnqueue(&PendingSend{
		MsgID: "m1", Account: "alice", Recipient: "bob@beta", DestNode: "dest",
		Envelope: []byte("env"), Sats: 10, NextTry: 100,
	})
	if err != nil || !ok {
		t.Fatalf("SpoolEnqueue: ok=%v err=%v", ok, err)
	}
	due, err := l.SpoolDue(200, 10)
	if err != nil || len(due) != 1 {
		t.Fatalf("SpoolDue: len=%d err=%v", len(due), err)
	}
	id := due[0].ID

	// Missing account must roll back pending->dead transition!
	if dead, err := l.SpoolMarkDeadAndRefund(id, "nobody", 10_000, "m1", nil); err == nil || dead {
		t.Fatalf("expected error on missing account, got dead=%v err=%v", dead, err)
	}
	cnt, _ := l.SpoolPendingCount()
	if cnt != 1 {
		t.Fatalf("expected row to stay pending after rollback, pending=%d", cnt)
	}

	// Valid account: transitions pending->dead AND credits refund atomically
	dead, err := l.SpoolMarkDeadAndRefund(id, "alice", 10_000, "m1", nil)
	if err != nil || !dead {
		t.Fatalf("SpoolMarkDeadAndRefund failed: dead=%v err=%v", dead, err)
	}
	a, _ := l.GetAccount("alice")
	if a.BalanceMsat != 15_000 {
		t.Fatalf("expected 15000 msat after refund, got %d", a.BalanceMsat)
	}
	// Second call must be a no-op (no double refund)
	dead2, err := l.SpoolMarkDeadAndRefund(id, "alice", 10_000, "m1", nil)
	if err != nil || dead2 {
		t.Fatalf("second call should be no-op: dead=%v err=%v", dead2, err)
	}
	a, _ = l.GetAccount("alice")
	if a.BalanceMsat != 15_000 {
		t.Fatalf("double refund occurred: %d", a.BalanceMsat)
	}
}
