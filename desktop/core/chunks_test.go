package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestNeedsChunking(t *testing.T) {
	if NeedsChunking(CHUNK) {
		t.Error("exactly 1 MiB should not need chunking")
	}
	if !NeedsChunking(CHUNK + 1) {
		t.Error("1 MiB + 1 should need chunking")
	}
}

func TestSplitChunks(t *testing.T) {
	// 2.5 MiB -> 3 chunks: 1M, 1M, 0.5M
	data := bytes.Repeat([]byte{0xAA}, 1024*1024*2+100)
	parts := SplitChunks(data)
	if len(parts) != 3 {
		t.Fatalf("want 3 chunks, got %d", len(parts))
	}
	if len(parts[0]) != 1024*1024 || len(parts[1]) != 1024*1024 || len(parts[2]) != 100 {
		t.Errorf("sizes: %d %d %d", len(parts[0]), len(parts[1]), len(parts[2]))
	}
	if parts[0][0] != 0xAA || parts[2][99] != 0xAA {
		t.Error("data corruption")
	}
}

func TestManifestRoundtrip(t *testing.T) {
	m := Manifest{V: 1, Size: 100, Chunks: []string{
		hex.EncodeToString(sha256.New().Sum(nil)),
		hex.EncodeToString(sha256.New().Sum(nil)),
	}}
	raw, err := ManifestBytes(m)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseManifest(raw)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.V != 1 || parsed.Size != 100 || len(parsed.Chunks) != 2 {
		t.Errorf("roundtrip: %+v", parsed)
	}
}

func TestParseManifestReject(t *testing.T) {
	if _, err := ParseManifest([]byte(`not json`)); err == nil {
		t.Error("non-JSON must fail")
	}
	if _, err := ParseManifest([]byte(`{"v":2,"size":10,"chunks":[]}`)); err == nil {
		t.Error("v:2 must fail")
	}
	if _, err := ParseManifest([]byte(`{"v":1,"size":0,"chunks":["aa"]}`)); err == nil {
		t.Error("size:0 must fail")
	}
	if _, err := ParseManifest([]byte(`{"v":1,"size":10,"chunks":[]}`)); err == nil {
		t.Error("empty chunks must fail")
	}
}
