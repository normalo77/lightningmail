// G2 (§25): Hash-Ketten-Statement — Konto- und Betreiber-Sicht.
package ledger

import "testing"

func TestStatementChainKonto(t *testing.T) {
	l := openTestLedger(t)
	mustAccount(t, l, "s1", 0)
	rate := &RateStamp{MEurPerBtc: 50_000_000, Ts: 1760000000, Src: "manual"}
	if err := l.ApplyDelta("s1", 1_000_000, KindTopup, "seed"); err != nil { // ungeratet
		t.Fatal(err)
	}
	if err := l.ApplyDeltaMeta("s1", 50_000, KindCardIn, "hash1", "btc", rate); err != nil {
		t.Fatal(err)
	}
	rows, head, err := l.StatementChain("s1", 0, 0)
	if err != nil || len(rows) != 2 {
		t.Fatalf("rows=%d err=%v", len(rows), err)
	}
	// Genesis + Verkettung muss exakt der Doku-Formel folgen
	if rows[0].PrevHash != GenesisHash("s1") {
		t.Fatal("erste Zeile haengt nicht am Genesis")
	}
	if rows[0].Hash != shaHex(rows[0].PrevHash+rows[0].CanonRow()) {
		t.Fatal("hash(0) falsch")
	}
	if rows[1].PrevHash != rows[0].Hash || rows[1].Hash != shaHex(rows[1].PrevHash+rows[1].CanonRow()) {
		t.Fatal("Kette gerissen")
	}
	if head != rows[1].Hash {
		t.Fatal("head != letzter Hash")
	}
	// Zeile 1 ungeratet (NULL bleibt NULL → Canon ""), Zeile 2 gestempelt
	if rows[0].EurMicro != nil || rows[0].RateSrc != nil {
		t.Fatalf("ungeratete Zeile hat Stempel: %+v", rows[0])
	}
	if rows[1].EurMicro == nil || *rows[1].EurMicro != 25_000 || *rows[1].RateSrc != "manual" {
		t.Fatalf("Stempel falsch: %+v", rows[1])
	}
	// from filtert NUR die Ausgabe — Kopf bleibt derselbe (Kette laeuft durch)
	rows2, head2, err := l.StatementChain("s1", rows[1].CreatedAt+1, 0)
	if err != nil || len(rows2) != 0 || head2 != head {
		t.Fatalf("from-Filter: rows=%d head-gleich=%v err=%v", len(rows2), head2 == head, err)
	}
}

func TestOperatorChain(t *testing.T) {
	l := openTestLedger(t)
	mustAccount(t, l, "buyer", 500_000)
	mustAccount(t, l, "seller", 0)
	rate := &RateStamp{MEurPerBtc: 50_000_000, Ts: 1760000000, Src: "manual"}
	// Kartenkauf: fee 50 sat an den Betreiber
	if _, err := l.BuyCard("buyer", "seller", "h1", 100_000, 50_000, 50_000, "btc", rate); err != nil {
		t.Fatal(err)
	}
	// Byte-Porto (fee, negativ beim Nutzer) + Refund
	if err := l.ApplyDeltaMeta("buyer", -20_000, KindFee, "blob:abc", "btc", rate); err != nil {
		t.Fatal(err)
	}
	if err := l.ApplyDelta("buyer", 5_000, KindFee, "refund:blob:abc"); err != nil {
		t.Fatal(err)
	}
	rows, head, err := l.OperatorChain("relaytest", 0, 0)
	if err != nil || len(rows) != 3 {
		t.Fatalf("rows=%d err=%v", len(rows), err)
	}
	byLabel := map[string]OpRow{}
	for _, r := range rows {
		byLabel[r.Label] = r
	}
	if c := byLabel["card_fee"]; c.AmountMsat != 50_000 || c.EurMicro == nil || *c.EurMicro != 25_000 || c.Source != "card" {
		t.Fatalf("card_fee: %+v", c)
	}
	if b := byLabel["byte_porto"]; b.AmountMsat != 20_000 || b.EurMicro == nil || *b.EurMicro != 10_000 || b.Source != "txlog" {
		t.Fatalf("byte_porto (Vorzeichen gedreht + EUR): %+v", b)
	}
	if rf := byLabel["refund"]; rf.AmountMsat != -5_000 {
		t.Fatalf("refund muss negativ sein (Betreiber zahlt zurueck): %+v", rf)
	}
	// Kette + Determinismus
	prev := OperatorGenesisHash("relaytest")
	for _, r := range rows {
		if r.PrevHash != prev || r.Hash != shaHex(prev+r.CanonRow()) {
			t.Fatal("Operator-Kette gerissen")
		}
		prev = r.Hash
	}
	if head != prev {
		t.Fatal("head falsch")
	}
	rows2, head2, _ := l.OperatorChain("relaytest", 0, 0)
	if head2 != head || len(rows2) != len(rows) {
		t.Fatal("nicht deterministisch")
	}
}
