package core

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
	"unicode/utf16"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightningmail/lm1/crypto"
)

// StateDoc mirrors client/src/state.ts byte-for-byte (field names, optionals,
// merge semantics). M1 only READS it: open (self-ECIES) + pure merge for
// display. Re-stamping ts = max(now,prev)+1 happens only on save — that is
// M2, not here. shortcut: Seal()/push come with M2 write path.

// Draft (state.ts Draft): tombstones carry gone:1.
type Draft struct {
	ID      string `json:"id"`
	Ts      int64  `json:"ts"`
	To      string `json:"to"`
	Subject string `json:"subject"`
	Body    string `json:"body"`
	Gone    int    `json:"gone,omitempty"`
}

// SentItem (state.ts SentItem): body optional (omitempty!), max 2000 chars.
type SentItem struct {
	MsgID   string `json:"msg_id"`
	Ts      int64  `json:"ts"`
	To      string `json:"to"`
	Subject string `json:"subject"`
	Body    string `json:"body,omitempty"`
	Bytes   int64  `json:"bytes"`
}

// Contact (state.ts Contact, Etappe A): vCard-ish fields, all plain strings.
type Contact struct {
	ID     string `json:"id"`
	Ts     int64  `json:"ts"`
	Gone   int    `json:"gone,omitempty"`
	Name   string `json:"name"`
	Given  string `json:"given"`
	Org    string `json:"org"`
	Title  string `json:"title"`
	URL    string `json:"url"`
	Cell   string `json:"cell"`
	Phone  string `json:"phone"`
	Fax    string `json:"fax"`
	Email  string `json:"email"`
	Addr   string `json:"addr"`
	Lnaddr string `json:"lnaddr"`
	Pubkey string `json:"pubkey"`
	PGP    string `json:"pgp"`
	Note   string `json:"note"`
	BTC    string `json:"btc"`
	Crypto string `json:"crypto"`
}

// DriveEntry (state.ts DriveEntry, Etappe J).
type DriveEntry struct {
	ID        string `json:"id"`
	Ts        int64  `json:"ts"`
	Gone      int    `json:"gone,omitempty"`
	Name      string `json:"name"`
	Parent    string `json:"parent"`
	Kind      string `json:"kind"` // 'f' | 'd'
	Size      int64  `json:"size"`
	SizePlain int64  `json:"size_plain"`
	Mime      string `json:"mime"`
	Msha      string `json:"msha,omitempty"`
}

// StateDoc (state.ts StateDoc) — field order matters for JSON re-marshal (M2).
type StateDoc struct {
	Read     map[string]int        `json:"read"`
	Spam     map[string]int        `json:"spam"`
	Deleted  map[string]int        `json:"deleted"`
	Drafts   []Draft               `json:"drafts"`
	Sent     []SentItem            `json:"sent"`
	Contacts map[string]Contact    `json:"contacts"`
	Files    map[string]DriveEntry `json:"files"`
}

// EmptyDoc is the zero doc (state.ts emptyDoc).
func EmptyDoc() StateDoc {
	return StateDoc{
		Read:     map[string]int{},
		Spam:     map[string]int{},
		Deleted:  map[string]int{},
		Drafts:   []Draft{},
		Sent:     []SentItem{},
		Contacts: map[string]Contact{},
		Files:    map[string]DriveEntry{},
	}
}

// normalize maps TS's `d.read || {}` fallbacks after JSON.parse.
func (d *StateDoc) normalize() {
	if d.Read == nil {
		d.Read = map[string]int{}
	}
	if d.Spam == nil {
		d.Spam = map[string]int{}
	}
	if d.Deleted == nil {
		d.Deleted = map[string]int{}
	}
	if d.Drafts == nil {
		d.Drafts = []Draft{}
	}
	if d.Sent == nil {
		d.Sent = []SentItem{}
	}
	if d.Contacts == nil {
		d.Contacts = map[string]Contact{}
	}
	if d.Files == nil {
		d.Files = map[string]DriveEntry{}
	}
}

// OpenStateDoc decrypts the sealed state blob exactly like StateSync.open
// (state.ts:111-121): wire = ephPub(33B) || sealed(24B nonce + ct + 16B tag),
// self-ECIES with the own mailbox key, AAD = empty (NOT nil-vs-empty: both
// are zero-length for the AEAD). Blobs < 34 bytes are "no state" (null),
// matching the TS length guard.
func OpenStateDoc(priv *btcec.PrivateKey, blob []byte) (*StateDoc, error) {
	if len(blob) == 0 {
		return nil, nil // fresh account: no state yet (TS returns null)
	}
	if len(blob) < 34 {
		return nil, nil
	}
	pt, err := crypto.DecryptForRecipient(priv, blob[:33], blob[33:], []byte{})
	if err != nil {
		return nil, fmt.Errorf("state open: %w", err)
	}
	var doc StateDoc
	if err := json.Unmarshal(pt, &doc); err != nil {
		return nil, fmt.Errorf("state json: %w", err)
	}
	doc.normalize()
	return &doc, nil
}

// utf16Len returns the JS .length of s (UTF-16 code units) — sent-merge
// compares body lengths the way state.ts:72 does.
func utf16Len(s string) int {
	return len(utf16.Encode([]rune(s)))
}

// draftWins is state.ts:61-62 `wins(cand, cur)`: newer ts wins; on a tie the
// tombstone wins ONLY when the candidate is the tombstone (the 15.11. bug was
// gone-priority everywhere).
func draftWins(d, cur Draft, hasCur bool) bool {
	if !hasCur {
		return true
	}
	return d.Ts > cur.Ts || (d.Ts == cur.Ts && d.Gone != 0 && cur.Gone == 0)
}

// MergeDocs is a 1:1 port of mergeDocs (state.ts:47-86). Pure: no re-stamping
// (that only happens in saveDraft/saveContact/saveFile — M2).
func MergeDocs(a, b StateDoc) StateDoc {
	out := EmptyDoc()
	// flags OR (read stays read; un-marking is a separate state change)
	for k, v := range a.Read {
		out.Read[k] = v
	}
	for k, v := range b.Read {
		out.Read[k] = v
	}
	for k, v := range a.Spam {
		out.Spam[k] = v
	}
	for k, v := range b.Spam {
		out.Spam[k] = v
	}
	for k, v := range a.Deleted {
		out.Deleted[k] = v
	}
	for k, v := range b.Deleted {
		out.Deleted[k] = v
	}

	// drafts: LWW per id, insertion order = first appearance in [...a, ...b]
	// (JS Object.values order), stable sort asc by ts, keep the LAST 30.
	byID := map[string]Draft{}
	order := make([]string, 0, len(a.Drafts)+len(b.Drafts))
	for _, d := range append(append([]Draft{}, a.Drafts...), b.Drafts...) {
		cur, seen := byID[d.ID]
		if !seen {
			order = append(order, d.ID)
		}
		if draftWins(d, cur, seen) {
			byID[d.ID] = d
		}
	}
	drafts := make([]Draft, 0, len(order))
	for _, id := range order {
		drafts = append(drafts, byID[id])
	}
	sortStableAsc(drafts)
	if len(drafts) > 30 {
		drafts = drafts[len(drafts)-30:]
	}
	out.Drafts = drafts

	// sent: one entry per msg_id — longer body wins (JS UTF-16 length!),
	// else newer ts; newest 150, descending.
	bySent := map[string]SentItem{}
	sentOrder := make([]string, 0, len(a.Sent)+len(b.Sent))
	for _, s := range append(append([]SentItem{}, a.Sent...), b.Sent...) {
		cur, seen := bySent[s.MsgID]
		if !seen {
			sentOrder = append(sentOrder, s.MsgID)
		}
		if !seen || utf16Len(s.Body) > utf16Len(cur.Body) || s.Ts > cur.Ts {
			bySent[s.MsgID] = s
		}
	}
	sent := make([]SentItem, 0, len(sentOrder))
	for _, id := range sentOrder {
		sent = append(sent, bySent[id])
	}
	sortStableDesc(sent)
	if len(sent) > 150 {
		sent = sent[:150]
	}
	out.Sent = sent

	// contacts + files: map-LWW, b wins on strictly newer ts; on ts tie the
	// tombstone wins (y gone && x live). Otherwise x (from a) stays.
	for k, x := range a.Contacts {
		out.Contacts[k] = x
	}
	for k, y := range b.Contacts {
		if x, ok := out.Contacts[k]; !ok ||
			y.Ts > x.Ts || (y.Ts == x.Ts && y.Gone != 0 && x.Gone == 0) {
			out.Contacts[k] = y
		}
	}
	for k, x := range a.Files {
		out.Files[k] = x
	}
	for k, y := range b.Files {
		if x, ok := out.Files[k]; !ok ||
			y.Ts > x.Ts || (y.Ts == x.Ts && y.Gone != 0 && x.Gone == 0) {
			out.Files[k] = y
		}
	}
	return out
}

// stable sorts mirroring Array.prototype.sort((x,y) => x.ts - y.ts) / reverse.
// Insertion order is preserved for equal ts (JS sort is stable since ES2019).
func sortStableAsc(d []Draft) {
	for i := 1; i < len(d); i++ { // insertion sort: stable, n is tiny (<=~60)
		for j := i; j > 0 && d[j].Ts < d[j-1].Ts; j-- {
			d[j], d[j-1] = d[j-1], d[j]
		}
	}
}

func sortStableDesc(s []SentItem) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j].Ts > s[j-1].Ts; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// SealDoc is the EXACT complement of StateSync.seal (state.ts:105-110):
// self-ECIES with own pubkey, AAD = empty, wire = eph(33B) || sealed.
// Returns the standard base64 string ready for state_b64 in PUT /v1/state.
func SealDoc(priv *btcec.PrivateKey, doc StateDoc) (string, error) {
	own := priv.PubKey()
	b, err := json.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("seal marshal: %w", err)
	}
	eph, sealed, err := crypto.EncryptForRecipient(own, b, []byte{})
	if err != nil {
		return "", fmt.Errorf("seal encrypt: %w", err)
	}
	out := make([]byte, 33+len(sealed))
	copy(out, eph[:])
	copy(out[33:], sealed)
	return base64.StdEncoding.EncodeToString(out), nil
}

// reStamp returns max(now, prev) + 1 (state.ts re-stamp rule).
func reStamp(prev int64) int64 {
	now := time.Now().Unix()
	if now > prev {
		return now + 1
	}
	return prev + 1
}

// MarkRead sets doc.read[msgID]=1 (M1 only local; M2: schedule push).
func (d *StateDoc) MarkRead(msgID string) {
	d.Read[msgID] = 1
}

// MarkDeleted sets doc.deleted[msgID]=1.
func (d *StateDoc) MarkDeleted(msgID string) {
	d.Deleted[msgID] = 1
}

// SaveDraft upserts a draft (state.ts saveDraft:173-175): it re-stamps,
// replaces any same-id draft, keeps last 30 sorted asc by ts.
func (d *StateDoc) SaveDraft(dr Draft) {
	prev := int64(0)
	for _, x := range d.Drafts {
		if x.ID == dr.ID && x.Ts > prev {
			prev = x.Ts
		}
	}
	dr.Ts = reStamp(prev)
	// filter out old same-id, append new
	filtered := make([]Draft, 0, len(d.Drafts)+1)
	for _, x := range d.Drafts {
		if x.ID != dr.ID {
			filtered = append(filtered, x)
		}
	}
	filtered = append(filtered, dr)
	sortStableAsc(filtered)
	if len(filtered) > 30 {
		filtered = filtered[len(filtered)-30:]
	}
	d.Drafts = filtered
}

// DelDraft tombstoned the draft (gone:1) — state.ts delDraft.
func (d *StateDoc) DelDraft(id string) {
	d.SaveDraft(Draft{ID: id, To: "", Subject: "", Body: "", Gone: 1})
}

// LiveDrafts returns non-gone drafts (state.ts liveDrafts).
func (d *StateDoc) LiveDrafts() []Draft {
	var out []Draft
	for _, x := range d.Drafts {
		if x.Gone == 0 {
			out = append(out, x)
		}
	}
	return out
}

// AddSent prepends a SentItem, dedups by MsgID, keeps first 150 desc by ts.
// body truncated to 2000 chars (state.ts addSent:179-183).
func (d *StateDoc) AddSent(s SentItem) {
	if len(s.Body) > 2000 {
		s.Body = s.Body[:2000]
	}
	filtered := make([]SentItem, 0, len(d.Sent)+1)
	for _, x := range d.Sent {
		if x.MsgID != s.MsgID {
			filtered = append(filtered, x)
		}
	}
	filtered = append([]SentItem{s}, filtered...)
	sortStableDesc(filtered)
	if len(filtered) > 150 {
		filtered = filtered[:150]
	}
	d.Sent = filtered
}

// LiveSent returns sent items sorted desc by ts.
func (d *StateDoc) LiveSent() []SentItem {
	out := make([]SentItem, len(d.Sent))
	copy(out, d.Sent)
	sortStableDesc(out)
	return out
}
