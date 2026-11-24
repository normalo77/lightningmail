package relayclient

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightningmail/lm1/crypto"
)

// sealTestDoc seals docJSON for priv like state.ts StateSync.seal.
func sealTestDoc(t *testing.T, priv *btcec.PrivateKey, docJSON string) string {
	t.Helper()
	eph, sealed, err := crypto.EncryptForRecipient(priv.PubKey(), []byte(docJSON), []byte{})
	if err != nil {
		t.Fatal(err)
	}
	out := make([]byte, 33+len(sealed))
	copy(out, eph[:])
	copy(out[33:], sealed)
	return base64.StdEncoding.EncodeToString(out)
}

// fakeStateRelay serves GET/PUT /v1/state with the relay's CAS semantics.
type fakeStateRelay struct {
	mu      sync.Mutex
	priv    *btcec.PrivateKey
	version int64
	blob    string // state_b64, empty = no state yet
	puts    int
	// conflictOnce makes the first PUT bump the version behind the client's
	// back (simulating a concurrent writer) and answer 409.
	conflictOnce   bool
	conflictWriter func(doc map[string]any)
	alwaysConflict bool
}

func (f *fakeStateRelay) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/state" {
			http.NotFound(w, r)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		switch r.Method {
		case "GET":
			json.NewEncoder(w).Encode(map[string]any{"version": f.version, "state_b64": f.blob})
		case "PUT":
			f.puts++
			var req struct {
				ExpectVersion int64  `json:"expect_version"`
				StateB64      string `json:"state_b64"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, `{"error":"bad json"}`, 400)
				return
			}
			if req.ExpectVersion != f.version || (f.alwaysConflict && f.version != -1) {
				w.WriteHeader(409)
				json.NewEncoder(w).Encode(map[string]any{"error": "version conflict", "version": f.version})
				return
			}
			if f.conflictOnce {
				// A concurrent writer commits its own change first.
				f.conflictOnce = false
				var doc map[string]any
				blob, _ := base64.StdEncoding.DecodeString(f.blob)
				if pt, err := crypto.DecryptForRecipient(f.priv, blob[:33], blob[33:], []byte{}); err == nil {
					json.Unmarshal(pt, &doc)
				}
				f.conflictWriter(doc)
				f.blob = sealTestDocRaw(f.priv, doc)
				f.version++
				w.WriteHeader(409)
				json.NewEncoder(w).Encode(map[string]any{"error": "version conflict", "version": f.version})
				return
			}
			f.blob = req.StateB64
			f.version++
			json.NewEncoder(w).Encode(map[string]any{"version": f.version})
		default:
			http.Error(w, `{"error":"method"}`, 405)
		}
	})
}

func sealTestDocRaw(priv *btcec.PrivateKey, doc map[string]any) string {
	b, _ := json.Marshal(doc)
	eph, sealed, _ := crypto.EncryptForRecipient(priv.PubKey(), b, []byte{})
	out := make([]byte, 33+len(sealed))
	copy(out, eph[:])
	copy(out[33:], sealed)
	return base64.StdEncoding.EncodeToString(out)
}

// fullDoc exercises every state.ts field so preservation can be asserted.
const fullDocJSON = `{"read":{"aaa":1},"spam":{"sp1":1},"deleted":{"ddd":1},` +
	`"drafts":[{"id":"dr1","ts":5,"to":"x@y","subject":"s","body":"b"}],` +
	`"sent":[{"msg_id":"old1","ts":9,"to":"o@p","subject":"old","body":"ob","bytes":2}],` +
	`"contacts":{"c1":{"id":"c1","ts":7,"name":"Alice","given":"","org":"","title":"","url":"","cell":"","phone":"","fax":"","email":"","addr":"","lnaddr":"","pubkey":"pk","pgp":"","note":"","btc":"","crypto":""}},` +
	`"files":{"f1":{"id":"f1","ts":8,"parent":"","kind":"f","name":"n.txt","size":3,"size_plain":3,"mime":"text/plain"}}}`

func TestUpdateStatePreservesUnknownFields(t *testing.T) {
	priv, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeStateRelay{priv: priv, version: 1, blob: sealTestDoc(t, priv, fullDocJSON)}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()
	c := New(srv.URL, "acct", priv)
	ctx := context.Background()

	if _, err := c.UpdateState(ctx, func(d *StateDoc) error {
		d.SetRead("bbb")
		d.SetDeleted("eee")
		d.AddSent(SentItem{MsgID: "new1", Ts: 20, To: "n@o", Subject: "new", Body: "nb", Bytes: 2})
		return nil
	}); err != nil {
		t.Fatalf("UpdateState: %v", err)
	}

	st, err := c.GetState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.Version != 2 {
		t.Fatalf("version = %d, want 2", st.Version)
	}
	if st.Doc.Read()["aaa"] != 1 || st.Doc.Read()["bbb"] != 1 {
		t.Fatalf("read map wrong: %v", st.Doc.Read())
	}
	if st.Doc.Deleted()["ddd"] != 1 || st.Doc.Deleted()["eee"] != 1 {
		t.Fatalf("deleted map wrong: %v", st.Doc.Deleted())
	}
	sent := st.Doc.Sent()
	if len(sent) != 2 || sent[0].MsgID != "new1" || sent[1].MsgID != "old1" {
		t.Fatalf("sent list wrong: %+v", sent)
	}
	// Untouched fields must survive byte-for-byte (raw JSON round-trip).
	var orig map[string]json.RawMessage
	if err := json.Unmarshal([]byte(fullDocJSON), &orig); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"spam", "drafts", "contacts", "files"} {
		got, ok := st.Doc.Raw(key)
		if !ok {
			t.Fatalf("field %q vanished from the state doc", key)
		}
		if string(got) != string(orig[key]) {
			t.Fatalf("field %q changed:\n got %s\nwant %s", key, got, orig[key])
		}
	}
}

func TestUpdateStateRetriesOn409AndMerges(t *testing.T) {
	priv, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeStateRelay{priv: priv, version: 1, blob: sealTestDoc(t, priv, fullDocJSON)}
	fake.conflictOnce = true
	fake.conflictWriter = func(doc map[string]any) {
		// Concurrent PWA writer marks its own read flag.
		read, _ := doc["read"].(map[string]any)
		if read == nil {
			read = map[string]any{}
		}
		read["ccc"] = 1
		doc["read"] = read
	}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()
	c := New(srv.URL, "acct", priv)

	if _, err := c.UpdateState(context.Background(), func(d *StateDoc) error {
		d.SetRead("bbb")
		return nil
	}); err != nil {
		t.Fatalf("UpdateState: %v", err)
	}
	if fake.puts != 2 {
		t.Fatalf("puts = %d, want 2 (409 then retry)", fake.puts)
	}
	st, err := c.GetState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Merge: our flag AND the concurrent writer's flag must both be present,
	// and the concurrent writer's contacts must be untouched.
	for _, id := range []string{"aaa", "bbb", "ccc"} {
		if st.Doc.Read()[id] != 1 {
			t.Fatalf("read[%s] missing after 409 merge: %v", id, st.Doc.Read())
		}
	}
	if raw, ok := st.Doc.Raw("contacts"); !ok || !strings.Contains(string(raw), "Alice") {
		t.Fatalf("contacts lost in merge: %s", raw)
	}
}

func TestUpdateStateConflictExhausted(t *testing.T) {
	priv, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeStateRelay{priv: priv, version: 1, blob: sealTestDoc(t, priv, fullDocJSON), alwaysConflict: true}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()
	c := New(srv.URL, "acct", priv)

	_, err = c.UpdateState(context.Background(), func(d *StateDoc) error {
		d.SetRead("bbb")
		return nil
	})
	if err == nil {
		t.Fatal("exhausted CAS retries must fail")
	}
	if fake.puts != maxStateCASRetries {
		t.Fatalf("puts = %d, want %d", fake.puts, maxStateCASRetries)
	}
}

func TestGetStateFreshAccount(t *testing.T) {
	priv, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeStateRelay{priv: priv} // version 0, no blob
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()
	c := New(srv.URL, "acct", priv)

	st, err := c.GetState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.Version != 0 || len(st.Doc.Read()) != 0 {
		t.Fatalf("fresh account = version 0 + empty doc, got %+v", st)
	}
	// Writing onto a fresh account must work with expect_version 0.
	if v, err := c.UpdateState(context.Background(), func(d *StateDoc) error {
		d.SetRead("x")
		return nil
	}); err != nil || v != 1 {
		t.Fatalf("first write: v=%d err=%v", v, err)
	}
}
