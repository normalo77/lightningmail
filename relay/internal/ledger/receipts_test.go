package ledger

import (
	"encoding/hex"
	"testing"
)

// Etappe 6b: Stempel-Dedup, Pending/Mirror-Markierung, Zuordnung per
// recipientHash und Fremd-Sender-Abweisung.
func TestReceiptsStampAndIncoming(t *testing.T) {
	l := openTestLedger(t)

	recipPub := make([]byte, 33)
	recipPub[0] = 0x02
	recipPub[1] = 0xAA
	recip, err := l.CreateAccount("bernd", recipPub, DefaultQuotaBytes)
	if err != nil {
		t.Fatal(err)
	}
	senderPub := make([]byte, 33)
	senderPub[0] = 0x02
	senderPub[1] = 0xBB
	sender, err := l.CreateAccount("gisela", senderPub, DefaultQuotaBytes)
	if err != nil {
		t.Fatal(err)
	}

	var msgID [32]byte
	copy(msgID[:], []byte("m1"))
	stamp := ReceiptStamp{MsgID: msgID, SenderPub: senderPub, Ts: 100}

	fresh, err := l.StampReceipts(recip.ID, []ReceiptStamp{stamp})
	if err != nil || len(fresh) != 1 {
		t.Fatalf("erster Stempel muss fresh sein: %d err=%v", len(fresh), err)
	}
	fresh, err = l.StampReceipts(recip.ID, []ReceiptStamp{stamp})
	if err != nil || len(fresh) != 0 {
		t.Fatalf("zweiter Abruf darf nicht erneut stempeln: %d err=%v", len(fresh), err)
	}

	pend, err := l.PendingReceipts(10)
	if err != nil || len(pend) != 1 || pend[0].AccountID != recip.ID {
		t.Fatalf("pending ungueltig: %+v err=%v", pend, err)
	}
	if err := l.MarkReceiptsMirrored(pend); err != nil {
		t.Fatal(err)
	}
	if pend, _ := l.PendingReceipts(10); len(pend) != 0 {
		t.Fatalf("nach Mirror-Markierung keine Pendings erwartet, got %d", len(pend))
	}

	// Incoming: sha256(sender_pub) muss giselas Konto treffen
	ok, err := l.StoreIncomingReceipt(msgID, senderPub, 100)
	if err != nil || !ok {
		t.Fatalf("store incoming: ok=%v err=%v", ok, err)
	}
	list, err := l.ListIncomingReceipts(sender.ID, 10)
	if err != nil || len(list) != 1 {
		t.Fatalf("list incoming: %d err=%v", len(list), err)
	}
	if list[0]["msg_id"] != hex.EncodeToString(msgID[:]) {
		t.Fatalf("msg_id mismatch: %v", list[0]["msg_id"])
	}
	if list[0]["ts"].(int64) != 100 {
		t.Fatalf("ts mismatch: %v", list[0]["ts"])
	}
	// Duplikat (zweiter Peer meldet dasselbe) → bleibt 1 Eintrag
	l.StoreIncomingReceipt(msgID, senderPub, 200)
	if list, _ := l.ListIncomingReceipts(sender.ID, 10); len(list) != 1 {
		t.Fatalf("Duplikat erzeugte zweiten Eintrag: %d", len(list))
	}
	// Unbekannter Sender → ok=false, kein Fehler (fremder Peer)
	unknown := make([]byte, 33)
	unknown[0] = 0x02
	unknown[5] = 0x99
	ok, err = l.StoreIncomingReceipt(msgID, unknown, 100)
	if err != nil || ok {
		t.Fatalf("unbekannter Sender: ok=%v err=%v", ok, err)
	}
	// Empfaenger sieht keine eigenen Incoming-Receipts
	if list, _ := l.ListIncomingReceipts(recip.ID, 10); len(list) != 0 {
		t.Fatalf("Empfaenger-Konto duerfte keine Receipts sehen: %d", len(list))
	}
}
