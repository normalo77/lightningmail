package ledger

import "testing"

// Etappe 6: Roundtrip des WebAuthn-Speichers.
func TestWACredentialRoundtrip(t *testing.T) {
	l := openTestLedger(t)
	acct := "gisela"
	pub := make([]byte, 33)
	pub[0] = 0x02
	if _, err := l.CreateAccount(acct, pub); err != nil {
		t.Fatal(err)
	}
	c := WACredential{CredID: "cred-abc", Account: acct, Name: "YubiKey 5", PublicKey: []byte{1, 2, 3}, SignCount: 7}
	if err := l.WAStoreCredential(c); err != nil {
		t.Fatal(err)
	}
	got, err := l.WALookupCredential("cred-abc")
	if err != nil || got.Name != "YubiKey 5" || got.SignCount != 7 || got.Account != acct {
		t.Fatalf("lookup mismatch: %+v err=%v", got, err)
	}
	// unbekanntes Credential → Zero-Wert, kein Fehler
	miss, err := l.WALookupCredential("nope")
	if err != nil || miss.CredID != "" {
		t.Fatalf("expected empty miss, got %+v err=%v", miss, err)
	}
	// SignCount-Update
	if err := l.WAUpdateSignCount("cred-abc", 9); err != nil {
		t.Fatal(err)
	}
	if got, _ := l.WALookupCredential("cred-abc"); got.SignCount != 9 {
		t.Fatalf("signcount not updated: %d", got.SignCount)
	}
	// Wraps
	if err := l.WAStoreWraps("cred-abc", "LMKEY1$PRF$n$c", "LMKEY1$s$n$c"); err != nil {
		t.Fatal(err)
	}
	prf, pass, err := l.WAGetWraps("cred-abc")
	if err != nil || prf != "LMKEY1$PRF$n$c" || pass != "LMKEY1$s$n$c" {
		t.Fatalf("wraps mismatch: %q %q err=%v", prf, pass, err)
	}
	// Wraps ohne Eintrag → leer, kein Fehler
	if p1, p2, err := l.WAGetWraps("nope"); err != nil || p1 != "" || p2 != "" {
		t.Fatalf("expected empty wraps, got %q %q err=%v", p1, p2, err)
	}
	// Liste pro Konto
	c2 := c
	c2.CredID = "cred-def"
	c2.Name = "Pixel"
	if err := l.WAStoreCredential(c2); err != nil {
		t.Fatal(err)
	}
	list, err := l.WACredentialsFor(acct)
	if err != nil || len(list) != 2 {
		t.Fatalf("expected 2 credentials, got %d err=%v", len(list), err)
	}
	// Löschen kaskadiert auf Wraps
	if err := l.WADeleteCredential("cred-abc"); err != nil {
		t.Fatal(err)
	}
	if list, _ := l.WACredentialsFor(acct); len(list) != 1 {
		t.Fatalf("expected 1 after delete, got %d", len(list))
	}
	if p1, p2, _ := l.WAGetWraps("cred-abc"); p1 != "" || p2 != "" {
		t.Fatal("wraps not deleted")
	}
}
