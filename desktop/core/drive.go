// drive.go mirrors client/src/drive.ts (Etappe J2): encrypted storage on the
// relay. Crypto = existing ECIES with the OWN mailbox pubkey (same wire shape
// as SealDoc: eph33|sealed, empty AAD). Storage = chunks pipeline, EVERY file
// gets a manifest blob (even <1 MiB) so download/delete uniformly walk
// msha -> manifest -> chunks. Deletion releases server blobs FIRST, the
// tombstone only afterwards (a failed release keeps the entry retryable).
package core

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightningmail/lm1/crypto"
)

// DriveTier is one purchasable storage package.
type DriveTier struct {
	GB   int64 `json:"gb"`
	Sats int64 `json:"sats"`
}

// DriveUsage is GET /v1/drive/usage.
type DriveUsage struct {
	Enabled    bool        `json:"enabled"`
	UsedBytes  int64       `json:"used_bytes"`
	QuotaBytes int64       `json:"quota_bytes"`
	Tiers      []DriveTier `json:"tiers"`
}

// newDriveId: 8 random hex bytes (drive.ts newDriveId).
func newDriveId() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// UploadFile encrypts + stores one drive file, then saves the state entry.
// size = stored ciphertext bytes (slices + manifest), size_plain = input.
func UploadFile(ctx context.Context, c *Client, priv *btcec.PrivateKey,
	doc *StateDoc, data []byte, name, mime, parent string,
	onProgress func(string)) (*DriveEntry, error) {

	own := priv.PubKey()
	eph, sealed, err := crypto.EncryptForRecipient(own, data, []byte{})
	if err != nil {
		return nil, fmt.Errorf("drive encrypt: %w", err)
	}
	enc := make([]byte, 33+len(sealed))
	copy(enc, eph[:])
	copy(enc[33:], sealed)

	total := (len(enc) + CHUNK - 1) / CHUNK
	hashes := make([]string, 0, total)
	i := 0
	for _, chunk := range SplitChunks(enc) {
		i++
		if onProgress != nil {
			onProgress(fmt.Sprintf("„%s“: Scheibe %d/%d…", name, i, total))
		}
		sha, err := c.UploadBlobKind(ctx, chunk, "drive")
		if err != nil {
			return nil, fmt.Errorf("drive upload %q #%d: %w", name, i, err)
		}
		hashes = append(hashes, sha)
	}
	mb, err := ManifestBytes(Manifest{V: 1, Size: len(enc), Chunks: hashes})
	if err != nil {
		return nil, err
	}
	if onProgress != nil {
		onProgress(fmt.Sprintf("„%s“: Manifest…", name))
	}
	msha, err := c.UploadBlobKind(ctx, mb, "drive")
	if err != nil {
		return nil, fmt.Errorf("drive manifest %q: %w", name, err)
	}
	e := DriveEntry{ID: newDriveId(), Name: name, Parent: parent, Kind: "f",
		Size: int64(len(enc) + len(mb)), SizePlain: int64(len(data)),
		Mime: mime, Msha: msha}
	doc.SaveFile(e)
	saved := doc.Files[e.ID]
	return &saved, nil
}

// DownloadFile: state entry -> msha -> manifest -> chunk GETs -> decrypt.
func DownloadFile(ctx context.Context, c *Client, priv *btcec.PrivateKey,
	doc *StateDoc, id string) ([]byte, error) {

	e, ok := doc.Files[id]
	if !ok || e.Gone != 0 {
		return nil, fmt.Errorf("Datei nicht gefunden")
	}
	if e.Kind != "f" || e.Msha == "" {
		return nil, fmt.Errorf("Eintrag ist keine Datei")
	}
	raw, err := c.Blob(ctx, e.Msha)
	if err != nil {
		return nil, err
	}
	man, err := ParseManifest(raw)
	if err != nil {
		return nil, err
	}
	// reassemble in order (chunks.ts reassemble)
	enc := make([]byte, 0, man.Size)
	for _, sha := range man.Chunks {
		part, err := c.Blob(ctx, sha)
		if err != nil {
			return nil, err
		}
		enc = append(enc, part...)
	}
	if len(enc) < 33 {
		return nil, fmt.Errorf("drive blob zu klein")
	}
	pt, err := crypto.DecryptForRecipient(priv, enc[:33], enc[33:], []byte{})
	if err != nil {
		return nil, fmt.Errorf("drive decrypt: %w", err)
	}
	return pt, nil
}

// DeleteFile releases server blobs first (manifest + every chunk), then the
// tombstone. Folders must be empty (checked here, same as drive.ts).
func DeleteFile(ctx context.Context, c *Client, doc *StateDoc, id string) error {
	e, ok := doc.Files[id]
	if !ok || e.Gone != 0 {
		return fmt.Errorf("Eintrag nicht gefunden")
	}
	if e.Kind == "d" {
		for _, x := range doc.LiveFiles() {
			if x.Parent == id {
				return fmt.Errorf("Ordner ist nicht leer")
			}
		}
		doc.DelFile(id)
		return nil
	}
	if e.Msha == "" {
		return fmt.Errorf("Datei ohne Blob-Referenz")
	}
	raw, err := c.Blob(ctx, e.Msha)
	if err != nil {
		return err
	}
	man, err := ParseManifest(raw)
	if err != nil {
		return err
	}
	if err := c.DeleteDriveBlob(ctx, e.Msha); err != nil {
		return err
	}
	for _, sha := range man.Chunks {
		if err := c.DeleteDriveBlob(ctx, sha); err != nil {
			return err
		}
	}
	doc.DelFile(id)
	return nil
}

// Mkdir creates a live folder entry (drive.ts d-mkdir path).
func Mkdir(doc *StateDoc, name, parent string) DriveEntry {
	e := DriveEntry{ID: newDriveId(), Name: name, Parent: parent, Kind: "d"}
	doc.SaveFile(e)
	return e
}

// Rename updates name (and for folders nothing else — flat ids).
func RenameFile(doc *StateDoc, id, name string) error {
	e, ok := doc.Files[id]
	if !ok || e.Gone != 0 {
		return fmt.Errorf("Eintrag nicht gefunden")
	}
	e.Name = name
	doc.SaveFile(e)
	return nil
}

// Statement fetches GET /v1/statement?fmt=json (Etappe G2) and decodes rows.
type StatementRow struct {
	ID       int64    `json:"id"`
	Ts       int64    `json:"ts"`
	Zeit     string   `json:"zeit"`
	Art      string   `json:"art"`
	Waehrung string   `json:"waehrung"`
	Msat     int64    `json:"msat"`
	Sat      int64    `json:"sat"`
	Ref      string   `json:"referenz"`
	Eur      *float64 `json:"eur"`
}

func (c *Client) Statement(ctx context.Context) ([]StatementRow, error) {
	raw, err := c.do(ctx, "GET", "/v1/statement?fmt=json", nil)
	if err != nil {
		return nil, err
	}
	var sr struct {
		Zeilen []StatementRow `json:"zeilen"`
	}
	if err := json.Unmarshal(raw, &sr); err != nil {
		return nil, fmt.Errorf("statement decode: %w", err)
	}
	return sr.Zeilen, nil
}

// CsvDownload fetches the raw CSV export (settings page save dialog).
func (c *Client) CsvStatement(ctx context.Context) ([]byte, error) {
	return c.do(ctx, "GET", "/v1/statement?fmt=csv", nil)
}
