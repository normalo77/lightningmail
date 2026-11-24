package envelope

import (
	"bytes"
	"math/rand"
	"testing"
)

func testEnv(t *testing.T) *Envelope {
	t.Helper()
	e := &Envelope{
		Timestamp:         1731300000,
		BlobRefs:          [][32]byte{{1, 2, 3}, {4, 5, 6}},
		Receipt:           &PostageReceipt{AmountSats: 10, Preimage: [32]byte{9, 8, 7}},
		PayloadCiphertext: append(make([]byte, NonceLen), bytes.Repeat([]byte{0xAA}, 40)...),
	}
	for i := range e.RecipientHash {
		e.RecipientHash[i] = byte(i)
	}
	for i := range e.MsgID {
		e.MsgID[i] = byte(0x80 + i)
	}
	e.SenderPubkey[0] = 0x02
	e.SenderPubkey[32] = 0x11
	e.EphemeralPubkey[0] = 0x03
	e.EphemeralPubkey[32] = 0x22
	e.Signature = bytes.Repeat([]byte{0x55}, SignatureLen)
	return e
}

func TestRoundTrip(t *testing.T) {
	e := testEnv(t)
	raw, err := e.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	reRaw, err := got.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, reRaw) {
		t.Fatal("re-encode differs from original wire bytes")
	}
	if got.Receipt == nil || got.Receipt.AmountSats != 10 || got.Receipt.Preimage != (e.Receipt.Preimage) {
		t.Fatalf("receipt lost: %+v", got.Receipt)
	}
	if len(got.BlobRefs) != 2 || got.BlobRefs[1] != (e.BlobRefs[1]) {
		t.Fatalf("blob refs lost: %v", got.BlobRefs)
	}
}

func TestRoundTripOptionalFields(t *testing.T) {
	e := testEnv(t)
	e.BlobRefs = nil
	e.Receipt = nil
	raw, err := e.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.BlobRefs != nil || got.Receipt != nil {
		t.Fatal("optional fields should stay absent")
	}
}

func TestSigningBytesOmitsSignature(t *testing.T) {
	e := testEnv(t)
	sb, err := e.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(sb); err == nil {
		t.Fatal("signing bytes must not decode as a complete envelope (sig missing)")
	}
	// signature-only changes must not change the digest input
	e2 := testEnv(t)
	e2.Signature = bytes.Repeat([]byte{0x77}, SignatureLen)
	sb2, _ := e2.SigningBytes()
	if !bytes.Equal(sb, sb2) {
		t.Fatal("SigningBytes depends on signature")
	}
}

func TestSignupTagRoundTrip(t *testing.T) {
	e := testEnv(t)
	e.Signup = true
	raw, err := e.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Signup {
		t.Fatal("signup lost in round trip")
	}
	reRaw, err := got.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, reRaw) {
		t.Fatal("signup re-encode differs")
	}
	// without the tag, Signup must stay false
	plain, err := testEnv(t).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if g2, err := Decode(plain); err != nil || g2.Signup {
		t.Fatalf("signup set without tag (err=%v)", err)
	}
	// signup must be covered by SigningBytes
	sbOn, err := e.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	sbOff, err := testEnv(t).SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(sbOn, sbOff) {
		t.Fatal("signup not covered by SigningBytes")
	}
	// invalid value (0x02) and wrong lengths must be rejected
	body := raw[:len(raw)-4] // strip tag|len|val of the trailing signup field
	for _, bad := range [][]byte{
		{TagSignup, 0x00, 0x01, 0x02},       // value != 1
		{TagSignup, 0x00, 0x02, 0x01, 0x01}, // len 2
		{TagSignup, 0x00, 0x00},             // len 0
	} {
		if _, err := Decode(append(append([]byte(nil), body...), bad...)); err == nil {
			t.Fatalf("bad signup field %v accepted", bad)
		}
	}
}

func TestTruncation(t *testing.T) {
	raw, err := testEnv(t).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n < len(raw); n++ {
		if _, err := Decode(raw[:n]); err == nil {
			t.Fatalf("truncation at %d decoded without error", n)
		}
	}
	if _, err := Decode(raw); err != nil {
		t.Fatalf("full length must decode: %v", err)
	}
}

// Fuzz-lite: every single-byte mutation must either fail cleanly or decode
// into an envelope that re-encodes — never panic.
func TestByteFlipsNoPanic(t *testing.T) {
	raw, err := testEnv(t).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < len(raw); i++ {
		for _, delta := range []byte{0x01, 0x7F, 0xFF} {
			mut := append([]byte(nil), raw...)
			mut[i] += delta
			e, err := Decode(mut)
			if err != nil {
				continue
			}
			out, err := e.MarshalBinary()
			if err != nil {
				t.Fatalf("mutated at %d decodes but re-encode fails: %v", i, err)
			}
			if !bytes.Equal(out, mut) && i >= 4 {
				t.Fatalf("mutation at %d not preserved through round trip", i)
			}
		}
	}
	// random full-body mutations
	for i := 0; i < 2000; i++ {
		mut := append([]byte(nil), raw...)
		mut[rng.Intn(len(mut))] += byte(rng.Intn(256))
		if e, err := Decode(mut); err == nil {
			if _, err := e.MarshalBinary(); err != nil {
				t.Fatalf("decode+re-encode mismatch: %v", err)
			}
		}
	}
}

func TestMagicAndVersion(t *testing.T) {
	raw, _ := testEnv(t).MarshalBinary()
	bad := append([]byte(nil), raw...)
	bad[2] = '2'
	if _, err := Decode(bad); err == nil || !bytes.Contains([]byte(err.Error()), []byte("magic")) {
		t.Fatalf("want magic error, got %v", err)
	}
	bad = append([]byte(nil), raw...)
	bad[3] = 0x02
	if _, err := Decode(bad); err != ErrVersion {
		t.Fatalf("want version error, got %v", err)
	}
}

func TestMissingRequiredAndUnknownTag(t *testing.T) {
	e := testEnv(t)
	e.Signature = nil
	if _, err := e.MarshalBinary(); err == nil {
		t.Fatal("MarshalBinary must require a signature")
	}
	// encode valid, then splice out tag 0x06 (timestamp) by rebuilding:
	raw, _ := testEnv(t).MarshalBinary()
	// append an unknown tag 0x0B — must be rejected
	rawB := append(append([]byte(nil), raw...), 0x0B, 0x00, 0x01, 0xFF)
	if _, err := Decode(rawB); err == nil {
		t.Fatal("unknown tag accepted")
	}
}
