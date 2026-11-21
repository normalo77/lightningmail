package ledger

import (
	"bytes"
	"errors"
	"testing"
)

func TestStateCAS(t *testing.T) {
	l := openTestLedger(t)
	a, err := l.CreateAccount("multi", []byte{0x02, 1, 2, 3}, DefaultQuotaBytes)
	if err != nil {
		t.Fatal(err)
	}

	// empty start
	v, blob, err := l.GetState(a.ID)
	if err != nil || v != 0 || blob != nil {
		t.Fatalf("empty state: v=%d blob=%v err=%v", v, blob, err)
	}

	// first write case (expect 0)
	nv, err := l.PutState(a.ID, 0, []byte("geraet-a"))
	if err != nil || nv != 1 {
		t.Fatalf("first put: v=%d err=%v", nv, err)
	}

	// stale version must conflict 409-style, blob unchanged
	cur, err := l.PutState(a.ID, 0, []byte("verloren"))
	if !errors.Is(err, ErrConflict) || cur != 1 {
		t.Fatalf("stale put must conflict: err=%v cur=%d", err, cur)
	}
	_, blob, err = l.GetState(a.ID)
	if err != nil || !bytes.Equal(blob, []byte("geraet-a")) {
		t.Fatalf("blob must survive conflict: %q err=%v", blob, err)
	}

	// correct second write case
	nv, err = l.PutState(a.ID, 1, []byte("geraet-b"))
	if err != nil || nv != 2 {
		t.Fatalf("second put: v=%d err=%v", nv, err)
	}
	v, blob, err = l.GetState(a.ID)
	if err != nil || v != 2 || !bytes.Equal(blob, []byte("geraet-b")) {
		t.Fatalf("readback: v=%d blob=%q err=%v", v, blob, err)
	}
}
