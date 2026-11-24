package imapserver

import (
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
)

func TestStorePersistenceAndDedupe(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	added, err := s.AddMessage(FolderInbox, "m1", 7, time.Unix(1000, 0), []byte("raw1"), false)
	if err != nil || !added {
		t.Fatalf("first insert: added=%v err=%v", added, err)
	}
	added, err = s.AddMessage(FolderInbox, "m1", 7, time.Unix(1000, 0), []byte("raw1"), false)
	if err != nil || added {
		t.Fatalf("duplicate msg_id must be ignored: added=%v err=%v", added, err)
	}
	if _, err := s.AddMessage(FolderSent, "m1", 0, time.Unix(1000, 0), []byte("raw-sent"), true); err != nil {
		t.Fatal(err) // same msg_id in another folder is fine (unique per folder)
	}

	f, ok := s.Folder(FolderInbox)
	if !ok || len(f.msgs) != 1 {
		t.Fatalf("INBOX = %+v", f)
	}
	m := f.msgs[0]
	if m.UID != 1 || m.MsgID != "m1" || m.Seq != 7 || m.Size != 4 {
		t.Fatalf("index entry wrong: %+v", m)
	}
	raw, err := s.Raw(m.UID)
	if err != nil || string(raw) != "raw1" {
		t.Fatalf("raw = %q %v", raw, err)
	}
	inboxUV := f.uidValidity
	if inboxUV == 0 {
		t.Fatal("uid_validity must be nonzero")
	}
	if err := s.SetMetaInt(metaLastInboxSeq, 7); err != nil {
		t.Fatal(err)
	}

	// pending flags merge OR-sticky
	if err := s.MarkPendingFlag("m1", true, false); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkPendingFlag("m1", false, true); err != nil {
		t.Fatal(err)
	}
	pf, err := s.PeekPendingFlags()
	if err != nil {
		t.Fatal(err)
	}
	if len(pf) != 1 || pf[0].MsgID != "m1" || !pf[0].Seen || !pf[0].Deleted {
		t.Fatalf("pending flags = %+v", pf)
	}
	if err := s.ClearPending(pf, nil); err != nil {
		t.Fatal(err)
	}
	if pf2, _ := s.PeekPendingFlags(); len(pf2) != 0 {
		t.Fatalf("pending flags not cleared: %+v", pf2)
	}

	// sent queue
	rec := SentRecord{MsgID: "s1", Ts: 123, To: "x@y", Subject: "subj", Body: "body"}
	if err := s.QueueSent(rec); err != nil {
		t.Fatal(err)
	}
	sents, err := s.PeekPendingSent()
	if err != nil || len(sents) != 1 || sents[0] != rec {
		t.Fatalf("pending sent = %+v %v", sents, err)
	}

	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen: everything survived, UIDVALIDITY is stable, UIDs keep growing.
	s2, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	f2, _ := s2.Folder(FolderInbox)
	if len(f2.msgs) != 1 || f2.msgs[0].UID != 1 || f2.msgs[0].MsgID != "m1" || f2.msgs[0].Seq != 7 {
		t.Fatalf("INBOX after reopen = %+v", f2.msgs)
	}
	if f2.uidValidity != inboxUV {
		t.Fatalf("uid_validity changed across restart: %d -> %d", inboxUV, f2.uidValidity)
	}
	if v, _ := s2.MetaInt(metaLastInboxSeq); v != 7 {
		t.Fatalf("last_inbox_seq = %d", v)
	}
	added, err = s2.AddMessage(FolderInbox, "m2", 8, time.Unix(2000, 0), []byte("raw2"), true)
	if err != nil || !added {
		t.Fatalf("insert after reopen: %v %v", added, err)
	}
	if f2.msgs[1].UID <= f2.msgs[0].UID {
		t.Fatalf("UIDs must be monotonic: %d then %d", f2.msgs[0].UID, f2.msgs[1].UID)
	}
	if !f2.msgs[1].has(imap.FlagSeen) {
		t.Fatal("seen flag not restored")
	}
	sents2, _ := s2.PeekPendingSent()
	if len(sents2) != 1 || sents2[0].MsgID != "s1" {
		t.Fatalf("pending sent lost across restart: %+v", sents2)
	}
}

func TestStoreApplyRemoteFlags(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	s.AddMessage(FolderInbox, "m1", 1, time.Unix(1, 0), []byte("r1"), false)
	s.AddMessage(FolderInbox, "m2", 2, time.Unix(2, 0), []byte("r2"), false)

	if err := s.ApplyRemoteFlags(map[string]int{"m1": 1}, map[string]int{"m2": 1}); err != nil {
		s.Close()
		t.Fatal(err)
	}
	f, _ := s.Folder(FolderInbox)
	if !f.msgs[0].has(imap.FlagSeen) || f.msgs[0].has(imap.FlagDeleted) {
		t.Fatalf("m1 flags = %v", f.msgs[0].flagList())
	}
	if !f.msgs[1].has(imap.FlagDeleted) || f.msgs[1].has(imap.FlagSeen) {
		t.Fatalf("m2 flags = %v", f.msgs[1].flagList())
	}
	// Remote flags must not create a local push (they came FROM the state).
	if pf, _ := s.PeekPendingFlags(); len(pf) != 0 {
		t.Fatalf("remote flag application queued a push: %+v", pf)
	}
	// Flags survived to disk.
	s.Close()
	s2, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	f2, _ := s2.Folder(FolderInbox)
	if !f2.msgs[0].has(imap.FlagSeen) || !f2.msgs[1].has(imap.FlagDeleted) {
		t.Fatalf("flags not persisted: %v %v", f2.msgs[0].flagList(), f2.msgs[1].flagList())
	}
}
