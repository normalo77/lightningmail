package crypto

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/pbkdf2"
)

// Golden fixtures are written by client/test/m-sec-golden.mts (noble argon2id).
// If these play back byte-exact, noble v2 and x/crypto argon2 are paritätisch —
// units included (m is KiB on both sides). Regenerate: npx tsx
// client/test/m-sec-golden.mts from the repo root.
type goldenFile struct {
	Argon2 struct {
		M    int `json:"m"`
		T    int `json:"t"`
		P    int `json:"p"`
		Unit string
	}
	Unwrap []struct {
		Name       string
		Line       string
		Passphrase string `json:"passphrase"`
		Pem        string `json:"pem"`
	}
	Reject []struct {
		Name       string
		Line       string
		Passphrase string `json:"passphrase"`
	}
}

func loadGolden(t *testing.T) *goldenFile {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	path := filepath.Join(thisFile, "../../../desktop/core/testdata/m-sec-golden.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("golden fixture missing — run: client/node_modules/.bin/tsx client/test/m-sec-golden.mts: %v", err)
	}
	var g goldenFile
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatalf("golden json: %v", err)
	}
	if g.Argon2.M != argM || g.Argon2.T != argT || g.Argon2.P != argP {
		t.Fatalf("fixture costs %v/%v/%v != canonical %v/%v/%v", g.Argon2.M, g.Argon2.T, g.Argon2.P, argM, argT, argP)
	}
	return &g
}

func TestGoldenUnwrap(t *testing.T) {
	g := loadGolden(t)
	if len(g.Unwrap) != 4 {
		t.Fatalf("want 4 unwrap cases, got %d", len(g.Unwrap))
	}
	for _, c := range g.Unwrap {
		t.Run(c.Name, func(t *testing.T) {
			got, err := UnwrapKey(c.Line, c.Passphrase)
			if err != nil {
				t.Fatalf("UnwrapKey: %v", err)
			}
			if got != c.Pem {
				t.Fatal("plaintext PEM mismatch vs noble fixture")
			}
			if _, err := LoadPrivatePEM([]byte(got)); err != nil {
				t.Fatalf("fixture PEM not loadable: %v", err)
			}
		})
	}
}

func TestGoldenReject(t *testing.T) {
	g := loadGolden(t)
	if len(g.Reject) != 3 {
		t.Fatalf("want 3 reject cases, got %d", len(g.Reject))
	}
	for _, c := range g.Reject {
		t.Run(c.Name, func(t *testing.T) {
			if _, err := UnwrapKey(c.Line, c.Passphrase); err == nil {
				t.Fatal("rejected fixture unwrapped cleanly")
			}
		})
	}
}

// Go's own PBKDF2 path must reproduce the noble-written LMKEY1 fixture: derive
// the key directly from the fixture salt and check the AEAD opens it.
func TestV1Pbkdf2Parity(t *testing.T) {
	g := loadGolden(t)
	v1 := ""
	for _, c := range g.Unwrap {
		if strings.HasPrefix(c.Line, "LMKEY1$") {
			v1 = c.Line
			break
		}
	}
	if v1 == "" {
		t.Fatal("no V1 case in golden file")
	}
	parts := strings.Split(v1, "$")
	salt, _ := base64.StdEncoding.DecodeString(parts[1])
	dk := pbkdf2.Key([]byte("sichere-passage-42"), salt, v1Iter, 32, sha256.New)
	nonce, _ := base64.StdEncoding.DecodeString(parts[2])
	ct, _ := base64.StdEncoding.DecodeString(parts[3])
	a, err := chacha20poly1305.NewX(dk)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := a.Open(nil, nonce, ct, nil)
	if err != nil {
		t.Fatal("x/crypto pbkdf2 key does not open noble's LMKEY1 ct — parity broken")
	}
	if !strings.Contains(string(pt), "PRIVATE KEY") {
		t.Fatal("bad plaintext")
	}
}

func TestWrapUnwrapStability(t *testing.T) {
	pem := "-----BEGIN EC PRIVATE KEY-----\nPRIVATE KEY\n-----END EC PRIVATE KEY-----\n"
	w, err := WrapKey(pem, "sichere-passage-42")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(w, "LMKEY2$"+v2Params+"$") {
		t.Fatalf("write path not canonical V2: %q", w[:24])
	}
	if !IsWrapped(w) {
		t.Fatal("IsWrapped(V2) false")
	}
	u, err := UnwrapKey(w, "sichere-passage-42")
	if err != nil {
		t.Fatal(err)
	}
	w2, err := WrapKey(u, "sichere-passage-42")
	if err != nil {
		t.Fatal(err)
	}
	if u2, err := UnwrapKey(w2, "sichere-passage-42"); err != nil || u2 != pem {
		t.Fatalf("re-wrap unstable: %v %q", err, u2)
	}
	if _, err := WrapKey(pem, "kurz123"); err != ErrShortPass {
		t.Fatalf("short passphrase: %v", err)
	}
}

func TestLoadKeyAllFormats(t *testing.T) {
	g := loadGolden(t)
	for _, c := range g.Unwrap {
		priv, err := LoadKey([]byte(c.Line), c.Passphrase)
		if err != nil || priv == nil {
			t.Fatalf("LoadKey(%s): %v", c.Name, err)
		}
	}
	// PRF special case must survive in the V1 format, LMKEY2 has no PRF branch.
	if _, err := UnwrapKey("LMKEY1$PRF$AAAAAAAAAAAAAAAAAAAAAAAAAAAA$AAAA", "whatever12"); err != ErrPRFWrap {
		t.Fatalf("PRF rejection: %v", err)
	}
}
