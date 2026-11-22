package core

import (
	"encoding/base64"
	"reflect"
	"testing"

	"github.com/lightningmail/lm1/crypto"
)

// M2 SealDoc bidirectional: Go SealDoc -> OpenStateDoc must yield the same
// doc (mirrors the TS seal/open cycle in state.ts:105-121).
func TestSealDocRoundtrip(t *testing.T) {
	priv, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	doc := EmptyDoc()
	doc.Read["m1"] = 1
	doc.Read["m2"] = 1
	doc.Spam["s"] = 1
	doc.Deleted["d"] = 1
	doc.Drafts = append(doc.Drafts, Draft{
		ID: "d1", Ts: 100, To: "alice@alpha", Subject: "Test", Body: "Hallo Welt",
	})
	doc.Sent = append(doc.Sent, SentItem{
		MsgID: "m1", Ts: 200, To: "bob@beta", Subject: "Re: Test", Bytes: 500,
	})
	doc.Contacts["c1"] = Contact{ID: "c1", Ts: 50, Name: "Charlie"}

	b64, err := SealDoc(priv, doc)
	if err != nil {
		t.Fatalf("SealDoc: %v", err)
	}

	blob, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("base64: %v", err)
	}
	opened, err := OpenStateDoc(priv, blob)
	if err != nil {
		t.Fatalf("OpenStateDoc: %v", err)
	}
	if opened == nil {
		t.Fatal("OpenStateDoc returned nil")
	}
	opened.normalize()
	doc.normalize()
	if !reflect.DeepEqual(*opened, doc) {
		t.Errorf("roundtrip mismatch\n got: %+v\nwant: %+v", opened, doc)
	}
}

// Empty doc roundtrip also works.
func TestSealDocEmptyRoundtrip(t *testing.T) {
	priv, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	doc := EmptyDoc()
	b64, err := SealDoc(priv, doc)
	if err != nil {
		t.Fatalf("SealDoc: %v", err)
	}
	blob, _ := base64.StdEncoding.DecodeString(b64)
	opened, err := OpenStateDoc(priv, blob)
	if err != nil {
		t.Fatalf("OpenStateDoc: %v", err)
	}
	if opened == nil {
		t.Fatal("nil doc")
	}
	if len(opened.Read) != 0 || len(opened.Drafts) != 0 {
		t.Errorf("expected empty doc, got %+v", opened)
	}
}

// SealDoc uses crypto.EncryptForRecipient which creates fresh ephemeral key
// every call; two calls with same doc produce different sealed blobs but
// both must open to the same doc.
func TestSealDocIdempotent(t *testing.T) {
	priv, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	doc := EmptyDoc()
	doc.Read["x"] = 1

	b1, _ := SealDoc(priv, doc)
	b2, _ := SealDoc(priv, doc)
	if b1 == b2 {
		t.Error("two seals must differ (fresh eph key)")
	}

	blob1, _ := base64.StdEncoding.DecodeString(b1)
	blob2, _ := base64.StdEncoding.DecodeString(b2)
	d1, _ := OpenStateDoc(priv, blob1)
	d2, _ := OpenStateDoc(priv, blob2)
	if !reflect.DeepEqual(d1, d2) || d1.Read["x"] != 1 {
		t.Error("different sealed blobs must open to same doc")
	}
}
