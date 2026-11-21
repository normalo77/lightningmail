// Package crypto holds the bmail v0.1 primitives (docs/spec.md §5):
// secp256k1 keypairs via btcec (PEM persist), XChaCha20-Poly1305 AEAD,
// BIP340 schnorr envelope signatures, ECIES-light payload encryption.
package crypto

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/lightningmail/lm1/envelope"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	PayloadKeyInfo = "bmail-payload-v1"
	AuthKeyInfo    = "bmail-auth-v1"

	xOnlyPubkeyLen = 32
)

// SEC1 ECPrivateKey (RFC 5915) with the secp256k1 named curve. We hand-encode
// because crypto/x509's EC marshaling only knows NIST curves (its
// namedCurveToOID rejects secp256k1) — verified against Go 1.27.
var sec1OID = asn1.ObjectIdentifier{1, 3, 132, 0, 10} // secp256k1

type sec1PrivateKey struct {
	Version    int
	PrivateKey []byte
	Curve      asn1.ObjectIdentifier `asn1:"explicit,tag:0,optional"`
	Pub        asn1.BitString        `asn1:"explicit,tag:1,optional"`
}

var (
	ErrBadKey   = errors.New("crypto: invalid key material")
	ErrBadSig   = errors.New("crypto: invalid signature")
	ErrBadPEM   = errors.New("crypto: bad key PEM (want EC PRIVATE KEY, secp256k1)")
	ErrOpenAEAD = errors.New("crypto: aead open failed (wrong key or tampered ciphertext)")
)

// GenerateKeyPair returns a fresh secp256k1 mailbox key.
func GenerateKeyPair() (*btcec.PrivateKey, error) {
	return btcec.NewPrivateKey()
}

// PublicBytes serializes the public key as 33B compressed (envelope field 0x04).
func PublicBytes(priv *btcec.PrivateKey) [33]byte {
	var out [33]byte
	copy(out[:], priv.PubKey().SerializeCompressed())
	return out
}

// PrivatePEM encodes the key as SEC1 "EC PRIVATE KEY" PEM.
func PrivatePEM(priv *btcec.PrivateKey) ([]byte, error) {
	d := priv.Key.Bytes()
	k := sec1PrivateKey{
		Version:    1,
		PrivateKey: d[:],
		Curve:      sec1OID,
		Pub:        asn1.BitString{Bytes: priv.PubKey().SerializeCompressed(), BitLength: 33 * 8},
	}
	der, err := asn1.Marshal(k)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

// LoadPrivatePEM parses SEC1 PEM written by PrivatePEM.
func LoadPrivatePEM(data []byte) (*btcec.PrivateKey, error) {
	blk, _ := pem.Decode(data)
	if blk == nil || blk.Type != "EC PRIVATE KEY" {
		return nil, ErrBadPEM
	}
	var k sec1PrivateKey
	if _, err := asn1.Unmarshal(blk.Bytes, &k); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadPEM, err)
	}
	if len(k.Curve) > 0 && !k.Curve.Equal(sec1OID) {
		return nil, fmt.Errorf("%w: curve %v", ErrBadPEM, k.Curve)
	}
	if len(k.PrivateKey) != 32 {
		return nil, fmt.Errorf("%w: bad scalar length %d", ErrBadPEM, len(k.PrivateKey))
	}
	// btcec v2.5.1: PrivKeyFromBytes returns (priv, pub) — nil priv on bad scalar.
	priv, derivedPub := btcec.PrivKeyFromBytes(k.PrivateKey)
	if priv == nil {
		return nil, fmt.Errorf("%w: scalar out of range", ErrBadPEM)
	}
	if len(k.Pub.Bytes) == 33 && derivedPub != nil &&
		!bytes.Equal(k.Pub.Bytes, derivedPub.SerializeCompressed()) {
		return nil, fmt.Errorf("%w: embedded pubkey mismatch", ErrBadPEM)
	}
	return priv, nil
}

// ParsePubKey accepts 33B compressed or 32B x-only.
func ParsePubKey(b []byte) (*btcec.PublicKey, error) {
	if len(b) == xOnlyPubkeyLen {
		pk, err := schnorr.ParsePubKey(b)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrBadKey, err)
		}
		return pk, nil
	}
	pk, err := btcec.ParsePubKey(b)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadKey, err)
	}
	return pk, nil
}

// --- AEAD (XChaCha20-Poly1305) ---

// Seal returns nonce(24) || ciphertext||tag. Random nonce per call.
func Seal(key *[32]byte, plaintext, aad []byte) ([]byte, error) {
	a, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, a.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return a.Seal(nonce, nonce, plaintext, aad), nil
}

func Open(key *[32]byte, sealed, aad []byte) ([]byte, error) {
	a, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, err
	}
	ns := a.NonceSize()
	if len(sealed) < ns+a.Overhead() {
		return nil, ErrOpenAEAD
	}
	pt, err := a.Open(nil, sealed[:ns], sealed[ns:], aad)
	if err != nil {
		return nil, ErrOpenAEAD
	}
	return pt, nil
}

// --- BIP340 schnorr over sha256 digest (envelope tag 0x05) ---

func Sign(priv *btcec.PrivateKey, msg []byte) ([]byte, error) {
	digest := sha256.Sum256(msg)
	sig, err := schnorr.Sign(priv, digest[:])
	if err != nil {
		return nil, err
	}
	return sig.Serialize(), nil
}

func Verify(pub *btcec.PublicKey, msg, sig []byte) error {
	if len(sig) != 64 {
		return ErrBadSig
	}
	digest := sha256.Sum256(msg)
	s, err := schnorr.ParseSignature(sig)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBadSig, err)
	}
	if !s.Verify(digest[:], pub) {
		return ErrBadSig
	}
	return nil
}

// SignEnvelope / VerifyEnvelope bind the mailbox key (tag 0x04) to the
// envelope contents: signature over sha256(SigningBytes()) per spec §3.2.

func SignEnvelope(e *envelope.Envelope, priv *btcec.PrivateKey) ([]byte, error) {
	sb, err := e.SigningBytes()
	if err != nil {
		return nil, err
	}
	return Sign(priv, sb)
}

func VerifyEnvelope(e *envelope.Envelope, senderPubkey, sig []byte) error {
	sb, err := e.SigningBytes()
	if err != nil {
		return err
	}
	pub, err := ParsePubKey(senderPubkey)
	if err != nil {
		return err
	}
	return Verify(pub, sb, sig)
}

// --- ECIES-light payload encryption (envelope tags 0x08/0x09) ---

// sharedKey derives the AEAD key from the x-coordinate of the ECDH point.
func sharedKey(scalar *btcec.ModNScalar, pub *btcec.PublicKey, info string) [32]byte {
	var j btcec.JacobianPoint
	pub.AsJacobian(&j)
	btcec.ScalarMultNonConst(scalar, &j, &j)
	j.ToAffine()
	secret := j.X.Bytes() // 32B x-coordinate
	var key [32]byte
	h := hkdf.New(sha256.New, secret[:], nil, []byte(info))
	if _, err := io.ReadFull(h, key[:]); err != nil {
		panic("crypto: hkdf read: " + err.Error()) // unreachable: 32B < hkdf output
	}
	return key
}

// EncryptForRecipient seals plaintext to the recipient's mailbox pubkey.
// Returns the 33B ephemeral pubkey (tag 0x09) and sealed bytes (tag 0x08).
// aad binds recipient_hash||msg_id (spec §5).
func EncryptForRecipient(recipientPub *btcec.PublicKey, plaintext, aad []byte) (ephPub [33]byte, sealed []byte, err error) {
	eph, err := btcec.NewPrivateKey()
	if err != nil {
		return ephPub, nil, err
	}
	key := sharedKey(&eph.Key, recipientPub, PayloadKeyInfo)
	sealed, err = Seal(&key, plaintext, aad)
	return PublicBytes(eph), sealed, err
}

// DecryptForRecipient opens tag 0x08 with the mailbox private key.
func DecryptForRecipient(priv *btcec.PrivateKey, ephPubBytes, sealed, aad []byte) ([]byte, error) {
	ephPub, err := ParsePubKey(ephPubBytes)
	if err != nil {
		return nil, err
	}
	key := sharedKey(&priv.Key, ephPub, PayloadKeyInfo)
	return Open(&key, sealed, aad)
}

// --- Auth challenge binding (spec §7 /v1/auth) ---

// AuthDigest frames a challenge so an envelope signature can never be reused
// as a login signature (domain separation).
func AuthDigest(challenge []byte) []byte {
	m := hmac.New(sha256.New, []byte(AuthKeyInfo))
	m.Write(challenge)
	return m.Sum(nil)
}
