package crypto

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lightningmail/lm1/envelope"
)

func TestPEMRoundTrip(t *testing.T) {
	priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	data, err := PrivatePEM(priv)
	if err != nil {
		t.Fatal(err)
	}
	back, err := LoadPrivatePEM(data)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back.Serialize(), priv.Serialize()) {
		t.Fatal("PEM round trip changed the key")
	}
	if PublicBytes(back) != PublicBytes(priv) {
		t.Fatal("public key mismatch")
	}
	for _, bad := range [][]byte{nil, []byte("not pem"),
		[]byte("-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n")} {
		if _, err := LoadPrivatePEM(bad); !errors.Is(err, ErrBadPEM) {
			t.Fatalf("bad PEM accepted: %v", err)
		}
	}
}

func TestSealOpen(t *testing.T) {
	key := [32]byte{1, 2, 3}
	aad := []byte("binding")
	pt := []byte("hallo gisela")
	ct, err := Seal(&key, pt, aad)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ct, pt) {
		t.Fatal("plaintext leaks in ciphertext")
	}
	back, err := Open(&key, ct, aad)
	if err != nil || !bytes.Equal(back, pt) {
		t.Fatalf("open: %v %q", err, back)
	}
	// wrong key
	if _, err := Open(&[32]byte{9}, ct, aad); err != ErrOpenAEAD {
		t.Fatal("wrong key must fail")
	}
	// wrong AAD: recipient_hash||msg_id binding must be enforced
	if _, err := Open(&key, ct, []byte("other")); err != ErrOpenAEAD {
		t.Fatal("wrong AAD must fail")
	}
	// tampered ct
	mut := append([]byte(nil), ct...)
	mut[len(mut)-1] ^= 0xFF
	if _, err := Open(&key, mut, aad); err != ErrOpenAEAD {
		t.Fatal("tampered ciphertext must fail")
	}
	// truncated
	if _, err := Open(&key, ct[:10], aad); err == nil {
		t.Fatal("truncated sealed data accepted")
	}
}

func TestSignVerify(t *testing.T) {
	priv, _ := GenerateKeyPair()
	msg := []byte("envelope bytes")
	sig, err := Sign(priv, msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != 64 {
		t.Fatalf("schnorr sig must be 64B, got %d", len(sig))
	}
	if err := Verify(priv.PubKey(), msg, sig); err != nil {
		t.Fatal(err)
	}
	if err := Verify(priv.PubKey(), []byte("other"), sig); err != ErrBadSig {
		t.Fatal("tampered message verified")
	}
	other, _ := GenerateKeyPair()
	if err := Verify(other.PubKey(), msg, sig); err != ErrBadSig {
		t.Fatal("wrong pubkey verified")
	}
}

func TestEnvelopeSignVerify(t *testing.T) {
	sender, _ := GenerateKeyPair()
	recv, _ := GenerateKeyPair()
	e := &envelope.Envelope{
		Timestamp:         1731300000,
		SenderPubkey:      PublicBytes(sender),
		PayloadCiphertext: bytes.Repeat([]byte{0x11}, envelope.NonceLen+16),
	}
	aad := append(e.RecipientHash[:], e.MsgID[:]...)
	var err error
	e.EphemeralPubkey, e.PayloadCiphertext, err = EncryptForRecipient(recv.PubKey(), []byte(`{"body":"hi"}`), aad)
	if err != nil {
		t.Fatal(err)
	}
	e.Signature, err = SignEnvelope(e, sender)
	if err != nil {
		t.Fatal(err)
	}
	// wire round trip then verify
	raw, err := e.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	got, err := envelope.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEnvelope(got, got.SenderPubkey[:], got.Signature); err != nil {
		t.Fatalf("verify after wire round trip: %v", err)
	}
	// tamper: change msg_id, verification must fail
	got2, _ := envelope.Decode(raw)
	got2.MsgID[0] ^= 1
	if err := VerifyEnvelope(got2, got2.SenderPubkey[:], got2.Signature); err != ErrBadSig {
		t.Fatal("tampered envelope verified")
	}
	// recipient decrypts
	aad2 := append(got.RecipientHash[:], got.MsgID[:]...)
	pt, err := DecryptForRecipient(recv, got.EphemeralPubkey[:], got.PayloadCiphertext, aad2)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != `{"body":"hi"}` {
		t.Fatalf("payload: %q", pt)
	}
	// wrong recipient cannot decrypt
	other, _ := GenerateKeyPair()
	if _, err := DecryptForRecipient(other, got.EphemeralPubkey[:], got.PayloadCiphertext, aad2); err != ErrOpenAEAD {
		t.Fatal("wrong mailbox key must not open payload")
	}
}

func TestECIESFreshEphemeral(t *testing.T) {
	recv, _ := GenerateKeyPair()
	pt := []byte("x")
	p1, c1, _ := EncryptForRecipient(recv.PubKey(), pt, nil)
	p2, _, _ := EncryptForRecipient(recv.PubKey(), pt, nil)
	if p1 == p2 {
		t.Fatal("ephemeral key reused")
	}
	_ = c1
}

func TestParsePubKeyForms(t *testing.T) {
	priv, _ := GenerateKeyPair()
	comp := priv.PubKey().SerializeCompressed()
	xOnly := xOnlyBytes(priv.PubKey())
	a, err := ParsePubKey(comp)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParsePubKey(xOnly)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.X().Bytes(), b.X().Bytes()) {
		t.Fatal("x-only and compressed must share the x coordinate")
	}
	if _, err := ParsePubKey([]byte{0x01, 0x02}); err == nil {
		t.Fatal("garbage pubkey accepted")
	}
}

// x-only pubkey = compressed serialization minus the 1B parity prefix.
func xOnlyBytes(pub *btcec.PublicKey) []byte {
	c := pub.SerializeCompressed()
	return c[1:]
}

func TestAuthDigestSeparation(t *testing.T) {
	d1 := AuthDigest([]byte("challenge-1"))
	d2 := AuthDigest([]byte("challenge-1"))
	if !bytes.Equal(d1, d2) {
		t.Fatal("AuthDigest must be deterministic")
	}
	sum := sha256.Sum256([]byte("challenge-1"))
	if bytes.Equal(d1, sum[:]) {
		t.Fatal("AuthDigest must not equal bare sha256 (domain separation)")
	}
}
