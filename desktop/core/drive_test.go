package core

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
)

// mockRelay is a minimal in-memory relay for the drive roundtrip: blobs by
// sha256, drive-kind accounting, DELETE release.
type mockRelay struct {
	blobs   map[string][]byte
	drive   map[string]bool
	deletes []string
}

func (m *mockRelay) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/v1/blob" && r.Method == "POST":
		raw, _ := io.ReadAll(r.Body)
		sha := sha256.Sum256(raw)
		h := hex.EncodeToString(sha[:])
		m.blobs[h] = raw
		if r.URL.Query().Get("kind") == "drive" {
			m.drive[h] = true
		}
		json.NewEncoder(w).Encode(map[string]string{"sha256_hex": h})
	case r.URL.Path == "/v1/blob" && r.Method == "DELETE":
		var q struct{ Sha string }
		json.NewDecoder(r.Body).Decode(&q)
		if !m.drive[q.Sha] {
			http.Error(w, `{"error":"no drive ref"}`, 403)
			return
		}
		delete(m.blobs, q.Sha)
		m.deletes = append(m.deletes, q.Sha)
		w.Write([]byte(`{"released":true}`))
	case strings.HasPrefix(r.URL.Path, "/v1/blob/"):
		raw, ok := m.blobs[strings.TrimPrefix(r.URL.Path, "/v1/blob/")]
		if !ok {
			http.Error(w, "gone", 404)
			return
		}
		w.Write(raw)
	case r.URL.Path == "/v1/drive/usage":
		json.NewEncoder(w).Encode(DriveUsage{Enabled: true, UsedBytes: 1, QuotaBytes: 2})
	default:
		http.Error(w, "nf", 404)
	}
}

func TestDriveRoundtrip(t *testing.T) {
	m := &mockRelay{blobs: map[string][]byte{}, drive: map[string]bool{}}
	srv := httptest.NewServer(m)
	defer srv.Close()

	priv, _ := btcec.NewPrivateKey()
	c := &Client{Base: srv.URL, Account: "t", hc: srv.Client(), priv: priv}
	doc := EmptyDoc()

	plain := make([]byte, 2*1024*1024+500_000) // forces 3 slices after encryption
	rand.Read(plain)

	var prog []string
	e, err := UploadFile(context.Background(), c, priv, &doc, plain, "big.bin", "application/octet-stream", "",
		func(s string) { prog = append(prog, s) })
	if err != nil {
		t.Fatal(err)
	}
	if e.Kind != "f" || e.Msha == "" || e.SizePlain != int64(len(plain)) {
		t.Fatalf("entry mismatch: %+v", e)
	}
	// ciphertext + manifest must be bigger than plaintext and drive-refed
	if e.Size <= int64(len(plain)) || len(prog) < 2 {
		t.Fatalf("size/progress: %d %v", e.Size, prog)
	}

	got, err := DownloadFile(context.Background(), c, priv, &doc, e.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatal("roundtrip bytes differ")
	}

	if err := DeleteFile(context.Background(), c, &doc, e.ID); err != nil {
		t.Fatal(err)
	}
	if doc.Files[e.ID].Gone == 0 {
		t.Fatal("tombstone missing")
	}
	if len(m.deletes) != 4 { // manifest + 3 slices
		t.Fatalf("releases: %d", len(m.deletes))
	}
	for _, s := range m.deletes {
		if len(m.blobs[s]) != 0 {
			t.Fatal("blob survived release")
		}
	}

	// folder delete refuses non-empty
	f := Mkdir(&doc, "d", "")
	doc.SaveFile(DriveEntry{ID: "inner", Name: "x", Kind: "f", Parent: f.ID})
	if err := DeleteFile(context.Background(), c, &doc, f.ID); err == nil {
		t.Fatal("non-empty folder delete should fail")
	}
}
