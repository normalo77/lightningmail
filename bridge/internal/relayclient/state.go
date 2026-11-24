// The /v1/state slot: self-ECIES sealed JSON with CAS writes via
// expect_version (409 = version conflict). The bridge only ever touches the
// read/deleted flag maps and the sent list; every other top-level field
// (contacts, drafts, files, spam, whatever future clients add) is preserved
// verbatim as raw JSON, so a bridge flag push can never clobber them.

package relayclient

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/lightningmail/lm1/crypto"
)

// maxStateCASRetries bounds the 409 loop; each retry is a fresh GET+PUT pair.
const maxStateCASRetries = 5

// Caps from state.ts addSent. The relay caps the blob at 256 KiB, so the
// bridge must not grow the doc past them even though client-side mergeDocs
// would re-trim eventually.
const (
	sentBodyCap = 2000
	sentListCap = 150
)

// SentItem is one state.sent entry (1:1 with desktop/core/statedoc.go).
type SentItem struct {
	MsgID   string `json:"msg_id"`
	Ts      int64  `json:"ts"`
	To      string `json:"to"`
	Subject string `json:"subject"`
	Body    string `json:"body,omitempty"`
	Bytes   int64  `json:"bytes"`
}

// StateDoc is the raw view of the sealed state JSON: every top-level key is
// kept as-is and only read/deleted/sent are decoded for modification.
type StateDoc struct {
	fields map[string]json.RawMessage
}

func (d *StateDoc) ensure() {
	if d.fields == nil {
		d.fields = map[string]json.RawMessage{}
	}
}

// UnmarshalJSON keeps every field (including unknown ones) verbatim.
func (d *StateDoc) UnmarshalJSON(b []byte) error {
	d.ensure()
	return json.Unmarshal(b, &d.fields)
}

// MarshalJSON re-emits the raw field map. encoding/json sorts map keys, so
// the sealed bytes are not byte-identical to a PWA seal — irrelevant because
// the relay stores an opaque blob and every consumer JSON.parses it.
func (d *StateDoc) MarshalJSON() ([]byte, error) {
	d.ensure()
	return json.Marshal(d.fields)
}

// Raw returns one untouched top-level field (tests use it to assert that
// bridge writes preserve other clients' data byte-for-byte).
func (d *StateDoc) Raw(key string) (json.RawMessage, bool) {
	v, ok := d.fields[key]
	return v, ok
}

func (d *StateDoc) flagMap(key string) map[string]int {
	m := map[string]int{}
	if raw, ok := d.fields[key]; ok {
		// A corrupt flag map degrades to empty instead of stalling the sync.
		_ = json.Unmarshal(raw, &m)
	}
	return m
}

func (d *StateDoc) setFlagMap(key string, m map[string]int) {
	d.ensure()
	b, _ := json.Marshal(m)
	d.fields[key] = b
}

// Read and Deleted return copies of the msg_id-keyed flag maps.
func (d *StateDoc) Read() map[string]int    { return d.flagMap("read") }
func (d *StateDoc) Deleted() map[string]int { return d.flagMap("deleted") }

// SetRead and SetDeleted mark one message flag. Flags are sticky (state.ts
// merge is OR-only, un-marking is a separate state change), so mutate
// closures calling these are idempotent — required by the CAS retry loop.
func (d *StateDoc) SetRead(msgID string) {
	m := d.flagMap("read")
	m[msgID] = 1
	d.setFlagMap("read", m)
}

func (d *StateDoc) SetDeleted(msgID string) {
	m := d.flagMap("deleted")
	m[msgID] = 1
	d.setFlagMap("deleted", m)
}

// Sent returns a copy of the sent list.
func (d *StateDoc) Sent() []SentItem {
	var s []SentItem
	if raw, ok := d.fields["sent"]; ok {
		_ = json.Unmarshal(raw, &s)
	}
	return s
}

// AddSent dedupes by msg_id, prepends and enforces the state.ts caps.
func (d *StateDoc) AddSent(s SentItem) {
	// shortcut: truncation counts runes, state.ts counts UTF-16 units —
	// differs only for non-BMP bodies and client merge re-caps anyway.
	if r := []rune(s.Body); len(r) > sentBodyCap {
		s.Body = string(r[:sentBodyCap])
	}
	old := d.Sent()
	out := make([]SentItem, 0, len(old)+1)
	out = append(out, s)
	for _, x := range old {
		if x.MsgID != s.MsgID {
			out = append(out, x)
		}
	}
	if len(out) > sentListCap {
		out = out[:sentListCap]
	}
	d.ensure()
	b, _ := json.Marshal(out)
	d.fields["sent"] = b
}

// State is one GET /v1/state read.
type State struct {
	Version int64
	Doc     *StateDoc
}

// GetState fetches and opens the sealed state document. Wire format is the
// state.ts StateSync.open convention (identical to desktop/core OpenStateDoc):
// blob = ephPub(33B) || nonce+ct+tag, self-ECIES under the own mailbox key,
// AAD empty. A blob shorter than 34 bytes means "no state yet" → empty doc.
func (c *Client) GetState(ctx context.Context) (*State, error) {
	st, raw, err := c.do(ctx, "GET", "/v1/state", nil, "")
	if err != nil {
		return nil, err
	}
	if st != 200 {
		return nil, &RelayError{Op: "state get", Status: st, Body: string(raw)}
	}
	var resp struct {
		Version  int64  `json:"version"`
		StateB64 string `json:"state_b64"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("state decode: %w", err)
	}
	doc := &StateDoc{}
	if resp.StateB64 != "" {
		blob, err := base64.StdEncoding.DecodeString(resp.StateB64)
		if err != nil {
			return nil, fmt.Errorf("state b64: %w", err)
		}
		if len(blob) >= 34 {
			pt, err := crypto.DecryptForRecipient(c.priv, blob[:33], blob[33:], []byte{})
			if err != nil {
				return nil, fmt.Errorf("state open: %w", err)
			}
			if err := json.Unmarshal(pt, doc); err != nil {
				return nil, fmt.Errorf("state json: %w", err)
			}
		}
	}
	return &State{Version: resp.Version, Doc: doc}, nil
}

// sealState is the exact complement of state.ts StateSync.seal: self-ECIES
// with the own pubkey, AAD empty, wire = eph(33B) || sealed, standard base64.
func (c *Client) sealState(doc *StateDoc) (string, error) {
	b, err := json.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("state marshal: %w", err)
	}
	eph, sealed, err := crypto.EncryptForRecipient(c.priv.PubKey(), b, []byte{})
	if err != nil {
		return "", fmt.Errorf("state encrypt: %w", err)
	}
	out := make([]byte, 33+len(sealed))
	copy(out, eph[:])
	copy(out[33:], sealed)
	return base64.StdEncoding.EncodeToString(out), nil
}

// UpdateState performs a read-modify-write of the state document under the
// relay's CAS (PUT with expect_version). On 409 it re-reads the current doc
// and re-applies mutate — the state.ts pull/merge/retry, except the merge is
// implicit: mutate only adds our own flags/sent entries on top of whatever a
// concurrent client just committed, so their fields always win untouched.
// mutate must therefore be idempotent. Returns the new version.
func (c *Client) UpdateState(ctx context.Context, mutate func(*StateDoc) error) (int64, error) {
	for attempt := 0; ; attempt++ {
		cur, err := c.GetState(ctx)
		if err != nil {
			return 0, err
		}
		if err := mutate(cur.Doc); err != nil {
			return 0, err
		}
		sealed, err := c.sealState(cur.Doc)
		if err != nil {
			return 0, err
		}
		body, _ := json.Marshal(map[string]any{
			"expect_version": cur.Version,
			"state_b64":      sealed,
		})
		st, raw, err := c.do(ctx, "PUT", "/v1/state", body, "application/json")
		if err != nil {
			return 0, err
		}
		switch st {
		case 200:
			var pr struct {
				Version int64 `json:"version"`
			}
			_ = json.Unmarshal(raw, &pr)
			return pr.Version, nil
		case 409:
			if attempt >= maxStateCASRetries-1 {
				return 0, &RelayError{Op: "state put", Status: 409,
					Body: fmt.Sprintf("version conflicts exhausted (%d attempts)", maxStateCASRetries)}
			}
			// A concurrent writer won: merge our idempotent changes onto
			// their fresh document on the next loop pass.
		default:
			return 0, &RelayError{Op: "state put", Status: st, Body: string(raw)}
		}
	}
}
