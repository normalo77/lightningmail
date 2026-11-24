// Package envelope implements the bmail v0.1 wire format (docs/spec.md §3):
// magic "LM1" + version byte, then length-prefixed TLV fields
// (tag 1B | BE length 2B | value). Hand-rolled binary on purpose —
// proto/bmail/v1/envelope.proto is documentation-only, no codegen in v0.1.
package envelope

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	MagicByte0 = 0x4C // 'L'
	MagicByte1 = 0x4D // 'M'
	MagicByte2 = 0x31 // '1'
	Version1   = 0x01

	TagRecipientHash     = 0x01
	TagMsgID             = 0x02
	TagBlobRefs          = 0x03
	TagSenderPubkey      = 0x04
	TagSignature         = 0x05
	TagTimestamp         = 0x06
	TagReceipt           = 0x07
	TagPayloadCiphertext = 0x08
	TagEphemeralPubkey   = 0x09
	TagSignup            = 0x0A // optional: first contact, value 0x01 → welcome postage

	MaxBlobRefs  = 16
	SignatureLen = 64 // BIP340 schnorr
	ReceiptLen   = 40 // 8B BE sats + 32B preimage
	NonceLen     = 24 // XChaCha20-Poly1305
)

var (
	ErrShort      = errors.New("envelope: truncated input")
	ErrMagic      = errors.New("envelope: bad magic")
	ErrVersion    = errors.New("envelope: unsupported version")
	ErrUnknownTag = errors.New("envelope: unknown tag")
	ErrOrder      = errors.New("envelope: tags not in ascending order")
	ErrSize       = errors.New("envelope: wrong field length")
	ErrMissing    = errors.New("envelope: missing required tag")
)

// PostageReceipt is envelope tag 0x07: the preimage of a settled postage
// payment doubles as the delivery receipt (receipt model, spec §4).
type PostageReceipt struct {
	AmountSats int64
	Preimage   [32]byte
}

type Envelope struct {
	RecipientHash     [32]byte
	MsgID             [32]byte
	BlobRefs          [][32]byte // optional, <=16
	SenderPubkey      [33]byte
	Signature         []byte // 64B, set by crypto.SignEnvelope; nil in SigningBytes
	Timestamp         int64
	Receipt           *PostageReceipt // optional
	PayloadCiphertext []byte          // 24B nonce + XChaCha20-Poly1305 ct||tag
	EphemeralPubkey   [33]byte
	Signup            bool // optional tag 0x0A: first contact (welcome_sats)
}

func (e *Envelope) validate(requireSig bool) error {
	if requireSig && len(e.Signature) != SignatureLen {
		return fmt.Errorf("%w: signature must be %d bytes", ErrSize, SignatureLen)
	}
	if len(e.BlobRefs) > MaxBlobRefs {
		return fmt.Errorf("%w: %d blob refs > %d", ErrSize, len(e.BlobRefs), MaxBlobRefs)
	}
	if len(e.PayloadCiphertext) < NonceLen+16 { // nonce + AEAD tag minimum
		return fmt.Errorf("%w: ciphertext too short", ErrSize)
	}
	return nil
}

// MarshalBinary encodes the full envelope (signature required).
func (e *Envelope) MarshalBinary() ([]byte, error) {
	if err := e.validate(true); err != nil {
		return nil, err
	}
	return e.encode(true), nil
}

// SigningBytes returns the serialization WITHOUT tag 0x05 — the bytes whose
// sha256 digest is the BIP340 signature input (spec §3.2).
func (e *Envelope) SigningBytes() ([]byte, error) {
	if err := e.validate(false); err != nil {
		return nil, err
	}
	return e.encode(false), nil
}

func (e *Envelope) encode(includeSig bool) []byte {
	var b bytes.Buffer
	b.Grow(256)
	b.Write([]byte{MagicByte0, MagicByte1, MagicByte2, Version1})
	field := func(tag byte, val []byte) {
		var l [2]byte
		binary.BigEndian.PutUint16(l[:], uint16(len(val)))
		b.WriteByte(tag)
		b.Write(l[:])
		b.Write(val)
	}
	fixed := func(tag byte, v [32]byte) { field(tag, v[:]) }
	u64 := func(v int64) []byte {
		var b8 [8]byte
		binary.BigEndian.PutUint64(b8[:], uint64(v))
		return b8[:]
	}
	fixed(TagRecipientHash, e.RecipientHash)
	fixed(TagMsgID, e.MsgID)
	if len(e.BlobRefs) > 0 {
		val := make([]byte, 0, 1+32*len(e.BlobRefs))
		val = append(val, byte(len(e.BlobRefs)))
		for _, r := range e.BlobRefs {
			val = append(val, r[:]...)
		}
		field(TagBlobRefs, val)
	}
	field(TagSenderPubkey, e.SenderPubkey[:])
	if includeSig && len(e.Signature) > 0 {
		field(TagSignature, e.Signature)
	}
	field(TagTimestamp, u64(e.Timestamp))
	if e.Receipt != nil {
		val := append(u64(e.Receipt.AmountSats), e.Receipt.Preimage[:]...)
		field(TagReceipt, val)
	}
	field(TagPayloadCiphertext, e.PayloadCiphertext)
	field(TagEphemeralPubkey, e.EphemeralPubkey[:])
	if e.Signup {
		field(TagSignup, []byte{0x01})
	}
	return b.Bytes()
}

// Decode parses the wire form. Canonical form is enforced: ascending unique
// known tags, fixed-size fields exact, no trailing bytes.
func Decode(raw []byte) (*Envelope, error) {
	if len(raw) < 4 {
		return nil, ErrShort
	}
	if raw[0] != MagicByte0 || raw[1] != MagicByte1 || raw[2] != MagicByte2 {
		return nil, ErrMagic
	}
	if raw[3] != Version1 {
		return nil, ErrVersion
	}
	e := &Envelope{}
	seen := map[byte]bool{}
	prev := byte(0)
	i := 4
	for i < len(raw) {
		tag := raw[i]
		if tag <= prev {
			return nil, fmt.Errorf("%w: 0x%02x after 0x%02x", ErrOrder, tag, prev)
		}
		prev = tag
		if tag < TagRecipientHash || tag > TagSignup {
			return nil, fmt.Errorf("%w: 0x%02x", ErrUnknownTag, tag)
		}
		if i+3 > len(raw) {
			return nil, ErrShort
		}
		l := int(binary.BigEndian.Uint16(raw[i+1 : i+3]))
		start := i + 3
		end := start + l
		if end > len(raw) || end < start {
			return nil, ErrShort
		}
		val := raw[start:end]
		i = end
		seen[tag] = true
		var err error
		switch tag {
		case TagRecipientHash:
			err = copy32(&e.RecipientHash, val)
		case TagMsgID:
			err = copy32(&e.MsgID, val)
		case TagBlobRefs:
			err = e.decodeBlobRefs(val)
		case TagSenderPubkey:
			err = copy33(&e.SenderPubkey, val)
		case TagSignature:
			if len(val) != SignatureLen {
				return nil, fmt.Errorf("%w: signature", ErrSize)
			}
			e.Signature = append([]byte(nil), val...)
		case TagTimestamp:
			if len(val) != 8 {
				return nil, fmt.Errorf("%w: timestamp", ErrSize)
			}
			e.Timestamp = int64(binary.BigEndian.Uint64(val))
		case TagReceipt:
			if len(val) != ReceiptLen {
				return nil, fmt.Errorf("%w: receipt", ErrSize)
			}
			r := &PostageReceipt{AmountSats: int64(binary.BigEndian.Uint64(val[:8]))}
			copy(r.Preimage[:], val[8:])
			e.Receipt = r
		case TagPayloadCiphertext:
			if len(val) < NonceLen+16 {
				return nil, fmt.Errorf("%w: ciphertext", ErrSize)
			}
			e.PayloadCiphertext = append([]byte(nil), val...)
		case TagEphemeralPubkey:
			err = copy33(&e.EphemeralPubkey, val)
		case TagSignup:
			if len(val) != 1 || val[0] != 1 {
				return nil, fmt.Errorf("%w: signup must be 0x01", ErrSize)
			}
			e.Signup = true
		}
		if err != nil {
			return nil, err
		}
	}
	for _, req := range []byte{TagRecipientHash, TagMsgID, TagSenderPubkey,
		TagSignature, TagTimestamp, TagPayloadCiphertext, TagEphemeralPubkey} {
		if !seen[req] {
			return nil, fmt.Errorf("%w: 0x%02x", ErrMissing, req)
		}
	}
	return e, nil
}

func (e *Envelope) decodeBlobRefs(val []byte) error {
	if len(val) == 0 {
		return fmt.Errorf("%w: blob_refs empty", ErrSize)
	}
	n := int(val[0])
	if n == 0 || n > MaxBlobRefs || len(val) != 1+32*n {
		return fmt.Errorf("%w: blob_refs count=%d len=%d", ErrSize, n, len(val))
	}
	e.BlobRefs = make([][32]byte, n)
	for j := 0; j < n; j++ {
		copy(e.BlobRefs[j][:], val[1+32*j:])
	}
	return nil
}

func copy32(dst *[32]byte, val []byte) error {
	if len(val) != 32 {
		return fmt.Errorf("%w: want 32 got %d", ErrSize, len(val))
	}
	copy(dst[:], val)
	return nil
}

func copy33(dst *[33]byte, val []byte) error {
	if len(val) != 33 {
		return fmt.Errorf("%w: want 33 got %d", ErrSize, len(val))
	}
	copy(dst[:], val)
	return nil
}
