// Keyfile wraps (M-SEC.1, docs/spec-M-SEC1-lmkey2.md): LMKEY1 (PBKDF2) stays
// readable forever, LMKEY2 (argon2id) is the only write format. Byte-identical
// semantics to client/src/keywrap.ts — proven by desktop/core/testdata/m-sec-golden.json.
package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/pbkdf2"
)

const (
	v1Iter = 310_000

	// Canonical LMKEY2 parameters (m is KiB — same unit as noble's memoryKiB).
	argM     = 65536
	argT     = 3
	argP     = 1
	v2Params = "m=65536,t=3,p=1"

	// Read guard: refuse files asking for more than 1 GiB of argon2 memory.
	argMMax = 1024 * 1024

	minPassphrase = 8
)

var (
	ErrShortPass   = errors.New("crypto: passphrase too short (min 8 chars)")
	ErrKeyFormat   = errors.New("crypto: not a LMKEY1/LMKEY2 key file")
	ErrPRFWrap     = errors.New("crypto: PRF wrap — passkey login required")
	ErrBadPass     = errors.New("crypto: wrong passphrase or corrupted file")
	ErrNotPrivKey  = errors.New("crypto: content is not a private key")
	ErrBadParams   = errors.New("crypto: bad LMKEY2 parameter section")
	ErrUnsupported = errors.New("crypto: unsupported argon2 parameters")

	b64std = base64.StdEncoding
)

// WrapKey encrypts a PEM with the passphrase into LMKEY2 (argon2id + XChaCha20-Poly1305).
func WrapKey(pemStr, passphrase string) (string, error) {
	if len(passphrase) < minPassphrase {
		return "", ErrShortPass
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(passphrase), salt, argT, argM, argP, 32)
	a, err := chacha20poly1305.NewX(key)
	if err != nil {
		return "", err
	}
	ct := a.Seal(nil, nonce, []byte(pemStr), nil)
	return "LMKEY2$" + v2Params + "$" + b64std.EncodeToString(salt) + "$" +
		b64std.EncodeToString(nonce) + "$" + b64std.EncodeToString(ct), nil
}

// UnwrapKey opens LMKEY1 or LMKEY2 with the passphrase; PRF wraps are rejected.
func UnwrapKey(fileText, passphrase string) (string, error) {
	parts := strings.Split(strings.TrimSpace(fileText), "$")
	switch parts[0] {
	case "LMKEY1":
		return unwrapV1(parts, passphrase)
	case "LMKEY2":
		return unwrapV2(parts, passphrase)
	default:
		return "", ErrKeyFormat
	}
}

func unwrapV1(parts []string, passphrase string) (string, error) {
	if len(parts) != 4 {
		return "", ErrKeyFormat
	}
	if parts[1] == "PRF" {
		return "", ErrPRFWrap
	}
	salt, err := b64std.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("%w: salt: %v", ErrKeyFormat, err)
	}
	nonce, err := b64std.DecodeString(parts[2])
	if err != nil {
		return "", fmt.Errorf("%w: nonce: %v", ErrKeyFormat, err)
	}
	ct, err := b64std.DecodeString(parts[3])
	if err != nil {
		return "", fmt.Errorf("%w: ct: %v", ErrKeyFormat, err)
	}
	key := pbkdf2.Key([]byte(passphrase), salt, v1Iter, 32, sha256.New)
	return openAEAD(key, nonce, ct)
}

func unwrapV2(parts []string, passphrase string) (string, error) {
	if len(parts) != 5 {
		return "", ErrKeyFormat
	}
	m, t, p, err := parseArgonParams(parts[1])
	if err != nil {
		return "", err
	}
	salt, err := decodeFixed(parts[2], 16)
	if err != nil {
		return "", fmt.Errorf("%w: salt: %v", ErrKeyFormat, err)
	}
	nonce, err := decodeFixed(parts[3], chacha20poly1305.NonceSizeX)
	if err != nil {
		return "", fmt.Errorf("%w: nonce: %v", ErrKeyFormat, err)
	}
	ct, err := b64std.DecodeString(parts[4])
	if err != nil {
		return "", fmt.Errorf("%w: ct: %v", ErrKeyFormat, err)
	}
	key := argon2.IDKey([]byte(passphrase), salt, t, m, p, 32)
	return openAEAD(key, nonce, ct)
}

var paramPair = regexp.MustCompile(`^[mtp]=\d+$`)

// parseArgonParams accepts exactly m,t,p — unknown keys are an error so nobody
// silently ignores e.g. an unapplied m=1M (spec M-SEC.1).
func parseArgonParams(s string) (m, t uint32, p uint8, err error) {
	seen := map[string]bool{}
	for _, kv := range strings.Split(s, ",") {
		if !paramPair.MatchString(kv) {
			return 0, 0, 0, ErrBadParams
		}
		v, _ := strconv.ParseUint(kv[2:], 10, 32)
		switch kv[0] {
		case 'm':
			m = uint32(v)
		case 't':
			t = uint32(v)
		case 'p':
			p = uint8(v)
		}
		seen[kv[:1]] = true
	}
	if len(seen) != 3 || !seen["m"] || !seen["t"] || !seen["p"] {
		return 0, 0, 0, ErrBadParams
	}
	if m < 8 || m > argMMax || t < 1 || p < 1 || p > 255 {
		return 0, 0, 0, ErrUnsupported
	}
	return m, t, p, nil
}

func decodeFixed(s string, n int) ([]byte, error) {
	b, err := b64std.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != n {
		return nil, fmt.Errorf("%w: want %d bytes, got %d", ErrKeyFormat, n, len(b))
	}
	return b, nil
}

func openAEAD(key, nonce, ct []byte) (string, error) {
	a, err := chacha20poly1305.NewX(key)
	if err != nil {
		return "", err
	}
	pemBytes, err := a.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", ErrBadPass
	}
	text := string(pemBytes)
	if !strings.Contains(text, "PRIVATE KEY") {
		return "", ErrNotPrivKey
	}
	return text, nil
}

// IsWrapped reports whether the file text is a LMKEY1/LMKEY2 wrapped key.
func IsWrapped(text string) bool {
	t := strings.TrimSpace(text)
	return strings.HasPrefix(t, "LMKEY1$") || strings.HasPrefix(t, "LMKEY2$")
}

// LoadKey parses a key file given as bytes: bare SEC1 PEM, or LMKEY1/LMKEY2
// wrapped (passphrase ignored for bare PEM).
func LoadKey(data []byte, passphrase string) (*btcec.PrivateKey, error) {
	text := string(data)
	if IsWrapped(text) {
		pemStr, err := UnwrapKey(text, passphrase)
		if err != nil {
			return nil, err
		}
		data = []byte(pemStr)
		defer clear([]byte(pemStr))
	}
	return LoadPrivatePEM(data)
}
