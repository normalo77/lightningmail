package imapserver

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	"mime"
	"mime/multipart"
	"net"
	netmail "net/mail"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	goimap "github.com/emersion/go-imap/v2/imapserver"

	"github.com/lightningmail/bridge/internal/relayclient"
)

// firstTextPart decodes the first text/* part of a built message (they are
// base64 CTE by construction).
func firstTextPart(t *testing.T, raw []byte) string {
	t.Helper()
	msg, err := netmail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	ct := msg.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "multipart/") {
		return string(decodePart(t, msg.Body))
	}
	_, params, err := mime.ParseMediaType(ct)
	if err != nil {
		t.Fatal(err)
	}
	mr := multipart.NewReader(msg.Body, params["boundary"])
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			t.Fatal("no text part found")
		}
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(p.Header.Get("Content-Type"), "text/") &&
			strings.EqualFold(p.Header.Get("Content-Transfer-Encoding"), "base64") {
			return string(decodePart(t, p))
		}
	}
}

// findAttachmentPart decodes the base64 body of the named attachment part.
func findAttachmentPart(t *testing.T, raw []byte, name string) []byte {
	t.Helper()
	msg, err := netmail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	_, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil {
		t.Fatal(err)
	}
	mr := multipart.NewReader(msg.Body, params["boundary"])
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			t.Fatal(err)
		}
		if p.FileName() == name {
			return decodePart(t, p)
		}
	}
}

type testServer struct {
	store *Store
	addr  string
	user  string
	pass  string
	srv   *goimap.Server
	ln    net.Listener
}

func newTestServer(t *testing.T) *testServer {
	t.Helper()
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	rb := make([]byte, 8)
	rand.Read(rb)
	ts := &testServer{
		store: store,
		user:  "bridge",
		pass:  hex.EncodeToString(rb), // throwaway credential, never a literal
	}
	ts.srv = NewServer(Options{AuthUser: ts.user, AuthPass: ts.pass, Store: store})
	ts.ln, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ts.addr = ts.ln.Addr().String()
	go ts.srv.Serve(ts.ln)
	t.Cleanup(func() {
		ts.srv.Close()
		store.Close()
	})
	return ts
}

func (ts *testServer) dial(t *testing.T) *imapclient.Client {
	t.Helper()
	c, err := imapclient.DialInsecure(ts.addr, nil)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (ts *testServer) login(t *testing.T) *imapclient.Client {
	t.Helper()
	c := ts.dial(t)
	if err := c.Login(ts.user, ts.pass).Wait(); err != nil {
		t.Fatalf("LOGIN: %v", err)
	}
	return c
}

func TestIMAPLoginAuth(t *testing.T) {
	ts := newTestServer(t)
	c := ts.dial(t)
	defer c.Close()
	if err := c.Login(ts.user, "wrong-password").Wait(); err == nil {
		t.Fatal("bad password accepted")
	}
	if err := c.Login("someone-else", ts.pass).Wait(); err == nil {
		t.Fatal("bad username accepted")
	}
	if err := c.Login(ts.user, ts.pass).Wait(); err != nil {
		t.Fatalf("good credentials rejected after failures: %v", err)
	}
}

func TestIMAPListStatusNoop(t *testing.T) {
	ts := newTestServer(t)
	c := ts.login(t)
	defer c.Close()

	list, err := c.List("", "*", nil).Collect()
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, l := range list {
		names[l.Mailbox] = true
		if l.Delim != '/' {
			t.Fatalf("delimiter = %q", l.Delim)
		}
	}
	for _, want := range []string{"INBOX", "Sent", "Trash"} {
		if !names[want] {
			t.Fatalf("LIST missing %s: %v", want, names)
		}
	}
	st, err := c.Status("INBOX", &imap.StatusOptions{NumMessages: true, UIDValidity: true, UIDNext: true}).Wait()
	if err != nil {
		t.Fatal(err)
	}
	if st.NumMessages == nil || *st.NumMessages != 0 || st.UIDValidity == 0 {
		t.Fatalf("STATUS = %+v", st)
	}
	if err := c.Noop().Wait(); err != nil {
		t.Fatal(err)
	}
	// fixed mailbox set: CREATE must be refused
	if err := c.Create("Archive", nil).Wait(); err == nil {
		t.Fatal("CREATE accepted on a fixed mailbox set")
	}
}

// seed puts one multipart letter (body + attachment) into INBOX.
func (ts *testServer) seed(t *testing.T, msgID, subject, body string, attName string, attData []byte) imap.UID {
	t.Helper()
	m := &relayclient.Mail{
		MsgID: msgID, Subject: subject, Body: body,
		Headers:    map[string]string{"from": "alice@world.example", "to": "bob@alpha"},
		ReceivedAt: time.Now().Unix(), SenderPub: "02aabbccddeeff0011",
	}
	atts := []AttachmentBlob{{Att: relayclient.Attachment{Name: attName, Size: int64(len(attData))}, Data: attData}}
	raw := BuildRFC822(m, "bob", atts)
	if _, err := ts.store.AddMessage(FolderInbox, msgID, 1, time.Now(), raw, false); err != nil {
		t.Fatal(err)
	}
	f, _ := ts.store.Folder(FolderInbox)
	return f.msgs[len(f.msgs)-1].UID
}

func TestIMAPFetchStoreMoveExpunge(t *testing.T) {
	ts := newTestServer(t)
	attData := bytes.Repeat([]byte("XYZ"), 50)
	msgID := "deadbeefcafe"
	ts.seed(t, msgID, "wire test", "hello over the wire", "payload.bin", attData)

	c := ts.login(t)
	defer c.Close()

	sel, err := c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatal(err)
	}
	if sel.NumMessages != 1 || sel.UIDValidity == 0 || sel.UIDNext < 2 {
		t.Fatalf("SELECT = %+v", sel)
	}

	// FETCH everything (peek → must not mark seen)
	fcmd := c.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{
		UID: true, Flags: true, Envelope: true, InternalDate: true, RFC822Size: true,
		BodyStructure: &imap.FetchItemBodyStructure{},
		BodySection:   []*imap.FetchItemBodySection{{Peek: true}},
	})
	msgs, err := fcmd.Collect()
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 {
		t.Fatalf("FETCH returned %d messages", len(msgs))
	}
	got := msgs[0]
	if got.Envelope == nil || got.Envelope.Subject != "wire test" {
		t.Fatalf("envelope = %+v", got.Envelope)
	}
	if got.Envelope.From == nil || len(got.Envelope.From) != 1 || got.Envelope.From[0].Addr() != "alice@world.example" {
		t.Fatalf("envelope from = %+v", got.Envelope.From)
	}
	if got.RFC822Size <= 0 || got.InternalDate.IsZero() || got.BodyStructure == nil {
		t.Fatalf("size/date/structure missing: %+v", got)
	}
	if len(got.BodySection) != 1 || len(got.BodySection[0].Bytes) != int(got.RFC822Size) {
		t.Fatalf("BODY[] = %d bytes, RFC822.SIZE = %d", len(got.BodySection[0].Bytes), got.RFC822Size)
	}
	raw := got.BodySection[0].Bytes
	if firstTextPart(t, raw) != "hello over the wire" {
		t.Fatalf("body part = %q", firstTextPart(t, raw))
	}
	if !bytes.Equal(findAttachmentPart(t, raw, "payload.bin"), attData) {
		t.Fatal("attachment missing or corrupt in BODY[]")
	}
	for _, fl := range got.Flags {
		if fl == imap.FlagSeen {
			t.Fatal("BODY.PEEK[] must not set \\Seen")
		}
	}

	// UID FETCH BODY[] without peek → implicit \Seen + pending state push
	fcmd2 := c.Fetch(imap.UIDSetNum(imap.UID(got.UID)), &imap.FetchOptions{
		BodySection: []*imap.FetchItemBodySection{{}},
	})
	if _, err := fcmd2.Collect(); err != nil {
		t.Fatal(err)
	}
	pf, _ := ts.store.PeekPendingFlags()
	if len(pf) != 1 || pf[0].MsgID != msgID || !pf[0].Seen {
		t.Fatalf("non-peek fetch did not queue a read push: %+v", pf)
	}

	// STORE +FLAGS \Seen (non-silent) → echoed flags
	sres, err := c.Store(imap.SeqSetNum(1),
		&imap.StoreFlags{Op: imap.StoreFlagsAdd, Flags: []imap.Flag{imap.FlagSeen}}, nil).Collect()
	if err != nil {
		t.Fatal(err)
	}
	if len(sres) != 1 || !hasFlag(sres[0].Flags, imap.FlagSeen) {
		t.Fatalf("STORE echo = %+v", sres)
	}

	// SEARCH UNSEEN finds nothing now, ALL finds the message
	sres2, err := c.Search(&imap.SearchCriteria{NotFlag: []imap.Flag{imap.FlagSeen}}, nil).Wait()
	if err != nil {
		t.Fatal(err)
	}
	if sres2.Count != 0 {
		t.Fatalf("SEARCH UNSEEN = %+v", sres2)
	}

	// MOVE to Trash
	mdata, err := c.Move(imap.SeqSetNum(1), "Trash").Wait()
	if err != nil {
		t.Fatalf("MOVE: %v", err)
	}
	if mdata.SourceUIDs == nil || mdata.DestUIDs == nil {
		t.Fatalf("MOVE data = %+v", mdata)
	}
	// INBOX is empty, Trash has the row, and the state tombstone is queued
	selI, _ := c.Select("INBOX", nil).Wait()
	if selI.NumMessages != 0 {
		t.Fatalf("INBOX after MOVE = %d messages", selI.NumMessages)
	}
	selT, _ := c.Select("Trash", nil).Wait()
	if selT.NumMessages != 1 {
		t.Fatalf("Trash after MOVE = %d messages", selT.NumMessages)
	}
	pf, _ = ts.store.PeekPendingFlags()
	var sawDeleted bool
	for _, f := range pf {
		if f.MsgID == msgID && f.Deleted {
			sawDeleted = true
		}
	}
	if !sawDeleted {
		t.Fatalf("MOVE out of INBOX did not queue a deleted push: %+v", pf)
	}

	// EXPUNGE in Trash: mark \Deleted, expunge, mailbox empties
	if _, err := c.Store(imap.SeqSetNum(1),
		&imap.StoreFlags{Op: imap.StoreFlagsAdd, Silent: true, Flags: []imap.Flag{imap.FlagDeleted}}, nil).Collect(); err != nil {
		t.Fatal(err)
	}
	ecmd := c.Expunge()
	if err := ecmd.Close(); err != nil { // drains the expunge responses
		t.Fatal(err)
	}
	selT2, _ := c.Select("Trash", nil).Wait()
	if selT2.NumMessages != 0 {
		t.Fatalf("Trash after EXPUNGE = %d messages", selT2.NumMessages)
	}
	if _, err := ts.store.Raw(imap.UID(got.UID)); err == nil {
		t.Fatal("expunged row still in SQLite")
	}

	if err := c.Logout().Wait(); err != nil {
		t.Fatalf("LOGOUT: %v", err)
	}
}

func TestIMAPUnselectedAndUnknownMailbox(t *testing.T) {
	ts := newTestServer(t)
	c := ts.login(t)
	defer c.Close()
	if _, err := c.Select("Archive", nil).Wait(); err == nil {
		t.Fatal("SELECT of unknown mailbox accepted")
	}
	if err := c.Noop().Wait(); err != nil {
		t.Fatalf("connection must survive a NO: %v", err)
	}
}

func hasFlag(flags []imap.Flag, want imap.Flag) bool {
	for _, f := range flags {
		if f == want {
			return true
		}
	}
	return false
}
