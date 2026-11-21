package main

// Manifest walk (docs/spec.md §6.5, manifest-only blob refs): the envelope
// carries just the manifest hash; the receiving relay mirrors the slices by
// reading the mirrored manifest blob. Field names and tolerances mirror
// client/src/chunks.ts manifestBytes/parseManifest 1:1:
// {"v":1,"size":<number>,"chunks":["<sha256-hex>",…]}.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

var errNotManifest = errors.New("not a manifest")

const (
	manifestMaxParts  = 255      // envelope ref-count byte (chunks.ts MAX_REFS)
	manifestMaxVolume = 4 << 30  // 4 GiB
	// shortcut: caps hardcoded, config lands only if ever needed.
)

type chunkManifestJSON struct {
	V      int       `json:"v"`
	Size   *float64  `json:"size"` // pointer: absent/null must fail like `typeof size !== 'number'`
	Chunks *[]string `json:"chunks"` // pointer: absent must fail like `!Array.isArray(chunks)`
}

// parseChunkManifest sniffs a mirrored blob. Returns the slice refs (exactly
// one level — nested manifests are NOT walked) plus the declared total size.
// errors.Is(err, errNotManifest) means "plain blob" (normal case, no log);
// any other error means manifest-shaped but rejected (caller logs + skips).
func parseChunkManifest(raw []byte) ([][32]byte, int64, error) {
	t := bytes.TrimSpace(raw)
	if len(t) == 0 || t[0] != '{' {
		return nil, 0, errNotManifest
	}
	var m chunkManifestJSON
	if err := json.Unmarshal(t, &m); err != nil {
		return nil, 0, errNotManifest // arbitrary JSON blob, not a manifest
	}
	if m.V != 1 || m.Size == nil || m.Chunks == nil {
		return nil, 0, errNotManifest
	}
	size := int64(*m.Size)
	if *m.Size < 0 || float64(size) != *m.Size {
		return nil, 0, fmt.Errorf("manifest size %v invalid", *m.Size)
	}
	if len(*m.Chunks) > manifestMaxParts {
		return nil, 0, fmt.Errorf("manifest parts %d > %d", len(*m.Chunks), manifestMaxParts)
	}
	if size > manifestMaxVolume {
		return nil, 0, fmt.Errorf("manifest volume %d > %d", size, manifestMaxVolume)
	}
	parts := make([][32]byte, 0, len(*m.Chunks))
	for _, c := range *m.Chunks {
		b, err := hex.DecodeString(c)
		if err != nil || len(b) != 32 {
			return nil, 0, fmt.Errorf("manifest chunk %q not a sha256 hex", c)
		}
		parts = append(parts, [32]byte(b))
	}
	return parts, size, nil
}
