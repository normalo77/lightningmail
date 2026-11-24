package core

import (
	"encoding/json"
	"fmt"
)

// chunks.go mirrors client/src/chunks.ts: 1-MiB slices + manifest.
// MANIFEST-ONLY envelope refs (21.11. fix): one msha per attachment.

const CHUNK = 1024 * 1024 // chunks.ts CHUNK
const MAX_REFS = 255      // chunks.ts MAX_REFS

// Manifest matches chunks.ts Manifest: v=1, size, chunks[] (sha256 hex order).
type Manifest struct {
	V      int      `json:"v"`
	Size   int      `json:"size"`
	Chunks []string `json:"chunks"`
}

// NeedsChunking returns true when the blob > 1 MiB.
func NeedsChunking(size int) bool { return size > CHUNK }

// SplitChunks yields 1-MiB slices in file order (closure over b, use once).
func SplitChunks(b []byte) [][]byte {
	n := (len(b) + CHUNK - 1) / CHUNK
	parts := make([][]byte, n)
	for i := 0; i < n; i++ {
		off := i * CHUNK
		end := min(off+CHUNK, len(b))
		parts[i] = b[off:end]
	}
	return parts
}

// ManifestBytes serializes the manifest exactly as in chunks.ts (JSON).
func ManifestBytes(m Manifest) ([]byte, error) {
	return json.Marshal(m)
}

// ParseManifest decodes a blob into a Manifest (chunks.ts parseManifest).
func ParseManifest(raw []byte) (*Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	if m.V != 1 || len(m.Chunks) == 0 || m.Size <= 0 {
		return nil, fmt.Errorf("ungültiges Manifest")
	}
	return &m, nil
}
