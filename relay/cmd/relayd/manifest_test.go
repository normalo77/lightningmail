package main

// Unit tests for the mirror manifest walk parser — no LND, no network.
// Fixtures mirror what client/src/chunks.ts manifestBytes() actually emits.

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func hexRef(b byte) string {
	var h [32]byte
	h[0] = b
	return hex.EncodeToString(h[:])
}

func TestParseChunkManifestRealShape(t *testing.T) {
	// exact JSON.stringify(manifestBytes) output: {"v":1,"size":N,"chunks":[hex…]}
	raw := []byte(fmt.Sprintf(`{"v":1,"size":3145728,"chunks":["%s","%s","%s"]}`, hexRef(1), hexRef(2), hexRef(3)))
	parts, size, err := parseChunkManifest(raw)
	if err != nil {
		t.Fatalf("real manifest rejected: %v", err)
	}
	if size != 3145728 || len(parts) != 3 {
		t.Fatalf("parts=%d size=%d", len(parts), size)
	}
	want, _ := hex.DecodeString(hexRef(2))
	if parts[1] != ([32]byte)(want) {
		t.Fatal("slice ref decoded wrong")
	}
}

func TestParseChunkManifestNotManifest(t *testing.T) {
	nonManifests := [][]byte{
		{0x00, 0x01, 0x02, 0xff, 0xfe},                     // binary blob
		[]byte(`{"subject":"hi","body":"x"}`),              // payload-style JSON
		[]byte(fmt.Sprintf(`{"v":2,"size":1,"chunks":["%s"]}`, hexRef(1))),   // wrong version
		[]byte(`{"v":1,"chunks":["aaaaaaaa"]}`),                                // size missing
		[]byte(fmt.Sprintf(`{"v":1,"size":1}`)),                                // chunks missing
		[]byte(`{"v":1,"size":1,"chunks":[42]}`),                               // non-string chunk
		[]byte(``),                                                             // empty
	}
	for _, raw := range nonManifests {
		if _, _, err := parseChunkManifest(raw); !errors.Is(err, errNotManifest) {
			t.Fatalf("want errNotManifest for %q, got %v", raw, err)
		}
	}
}

func TestParseChunkManifestCaps(t *testing.T) {
	// > 255 parts: rejected (manifest-shaped, so NOT errNotManifest -> logged)
	var sb strings.Builder
	sb.WriteString(`{"v":1,"size":1,"chunks":["`)
	sb.WriteString(hexRef(1))
	for i := 1; i <= manifestMaxParts; i++ { // 256 entries total
		sb.WriteString(`","`)
		sb.WriteString(hexRef(byte(i)))
	}
	sb.WriteString(`"]}`)
	if _, _, err := parseChunkManifest([]byte(sb.String())); err == nil || errors.Is(err, errNotManifest) {
		t.Fatalf("256 parts must be a logged rejection, got %v", err)
	}
	// volume > 4 GiB
	big := []byte(fmt.Sprintf(`{"v":1,"size":%d,"chunks":["%s"]}`, uint64(manifestMaxVolume)+1, hexRef(1)))
	if _, _, err := parseChunkManifest(big); err == nil || errors.Is(err, errNotManifest) {
		t.Fatalf("over-volume manifest must be rejected, got %v", err)
	}
	// exactly at the cap stays walkable (255 parts, size at the limit)
	okParts := []string{hexRef(1)}
	for i := 1; i < manifestMaxParts; i++ {
		okParts = append(okParts, hexRef(byte(i+1)))
	}
	inner := make([]string, 0, len(okParts))
	for _, p := range okParts {
		inner = append(inner, `"`+p+`"`)
	}
	ok := []byte(fmt.Sprintf(`{"v":1,"size":%d,"chunks":[%s]}`, manifestMaxVolume, strings.Join(inner, ",")))
	parts, _, err := parseChunkManifest(ok)
	if err != nil || len(parts) != manifestMaxParts {
		t.Fatalf("255 parts at the volume cap must parse: %d %v", len(parts), err)
	}
}

func TestParseChunkManifestHexValidation(t *testing.T) {
	bad := [][]byte{
		[]byte(fmt.Sprintf(`{"v":1,"size":1,"chunks":["%s"]}`, strings.Repeat("z", 64))), // non-hex
		[]byte(fmt.Sprintf(`{"v":1,"size":1,"chunks":["%s"]}`, strings.Repeat("a", 62))), // short hex
		[]byte(`{"v":1,"size":-2,"chunks":[]}`),                                          // negative size
	}
	for _, raw := range bad {
		if _, _, err := parseChunkManifest(raw); err == nil || errors.Is(err, errNotManifest) {
			t.Fatalf("bad manifest accepted as plain/valid: %q -> %v", raw, err)
		}
	}
}
