package core

import "testing"

// M3 save rules mirrored from state.ts: a live save resurrects a tombstoned
// id and re-stamps; deletion keeps a tombstone.

func TestContactSaveResurrectAndTombstone(t *testing.T) {
	d := EmptyDoc()
	d.SaveContact(Contact{ID: "k1", Name: "Alice", Pubkey: "aa"})
	d.DelContact("k1")
	if got := d.LiveContacts(); len(got) != 0 {
		t.Fatalf("after delete: %d live contacts", len(got))
	}
	// resurrect: same id, live fields come back, gone stripped
	d.SaveContact(Contact{ID: "k1", Name: "Alice II"})
	live := d.LiveContacts()
	if len(live) != 1 || live[0].Gone != 0 || live[0].Name != "Alice II" {
		t.Fatalf("resurrect mismatch: %+v", live)
	}
	if live[0].Ts <= d.Contacts["k1"].Ts-2 { // restamped forward
		t.Fatalf("ts not restamped")
	}
}

func TestFileSaveAndRename(t *testing.T) {
	d := EmptyDoc()
	f := Mkdir(&d, "dokumente", "")
	d.SaveFile(DriveEntry{ID: "f1", Name: "a.txt", Kind: "f", Parent: f.ID})
	if len(d.LiveFiles()) != 2 {
		t.Fatalf("want folder+file, got %d", len(d.LiveFiles()))
	}
	if err := RenameFile(&d, "f1", "b.txt"); err != nil {
		t.Fatal(err)
	}
	if d.Files["f1"].Name != "b.txt" || d.Files["f1"].Parent != f.ID {
		t.Fatalf("rename lost fields: %+v", d.Files["f1"])
	}
}

func TestContactDisplayLabel(t *testing.T) {
	if got := ContactDisplay(Contact{ID: "x", Pubkey: "0123456789abcdef"}); got != "0123456789ab…" {
		t.Fatalf("display label: %q", got)
	}
	if got := ContactDisplay(Contact{ID: "x", Name: "Bernd", Given: "ignored"}); got != "Bernd" {
		t.Fatalf("display label: %q", got)
	}
}
