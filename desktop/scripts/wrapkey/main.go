// wrapkey — B5 helper: wraps a plain SEC1 keyfile into LMKEY2 (argon2id).
//
//	Run:  LMKEY_SRC=plain.key LMKEY_DST=wrapped.lmkey LMKEY_PASS=... \
//	      go run ./scripts/wrapkey
package main

import (
	"log"
	"os"

	"github.com/lightningmail/lm1/crypto"
)

func main() {
	src, dst, pass := os.Getenv("LMKEY_SRC"), os.Getenv("LMKEY_DST"), os.Getenv("LMKEY_PASS")
	if src == "" || dst == "" || pass == "" {
		log.Fatal("LMKEY_SRC, LMKEY_DST and LMKEY_PASS are required")
	}
	pem, err := os.ReadFile(src)
	if err != nil {
		log.Fatal(err)
	}
	wrapped, err := crypto.WrapKey(string(pem), pass)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte(wrapped), 0600); err != nil {
		log.Fatal(err)
	}
	log.Printf("LMKEY2 geschrieben: %s", dst)
}
