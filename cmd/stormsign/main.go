// stormsign signs storm release artifacts with the release key,
// mirroring the EveSynapse scheme (internal/releasesig there):
// the private half is a PEM Ed25519 key in the RELEASE_SIGNING_KEY
// environment variable (a repo Actions secret), a signature is the
// base64 of the raw Ed25519 signature over the file's bytes written
// to <file>.sig, and signing refuses to proceed unless the key's
// public half is listed in the trusted file (release-signing.pub
// at the repo root), so a release can only ever be signed by a key
// this repo has declared trusted.
//
// Usage:
//
//	stormsign sign <file>...    sign each file, writing <file>.sig
//	stormsign verify <file>...  check each <file>.sig against the trusted keys
package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
)

const trustedPath = "release-signing.pub"

func parsePublic(pemData []byte) ([]ed25519.PublicKey, error) {
	var keys []ed25519.PublicKey
	for {
		var block *pem.Block
		block, pemData = pem.Decode(pemData)
		if block == nil {
			break
		}
		if block.Type != "PUBLIC KEY" {
			continue
		}
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		pub, ok := parsed.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("trusted key is not Ed25519")
		}
		keys = append(keys, pub)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no public keys in %s", trustedPath)
	}
	return keys, nil
}

func parsePrivate(pemData []byte) ([]ed25519.PrivateKey, error) {
	var keys []ed25519.PrivateKey
	for {
		var block *pem.Block
		block, pemData = pem.Decode(pemData)
		if block == nil {
			break
		}
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		priv, ok := parsed.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("signing key is not Ed25519")
		}
		keys = append(keys, priv)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no private key in RELEASE_SIGNING_KEY")
	}
	return keys, nil
}

func trusted() ([]ed25519.PublicKey, error) {
	raw, err := os.ReadFile(trustedPath)
	if err != nil {
		return nil, err
	}
	return parsePublic(raw)
}

func sign(files []string) error {
	secret := os.Getenv("RELEASE_SIGNING_KEY")
	if secret == "" {
		return fmt.Errorf("RELEASE_SIGNING_KEY is not set; refusing to sign")
	}
	privs, err := parsePrivate([]byte(secret))
	if err != nil {
		return err
	}
	trust, err := trusted()
	if err != nil {
		return err
	}
	for _, priv := range privs {
		pub := priv.Public().(ed25519.PublicKey)
		found := false
		for _, t := range trust {
			if pub.Equal(t) {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("the signing key is not one this repo trusts; its public half is not in %s. Nothing was signed", trustedPath)
		}
	}
	for _, f := range files {
		msg, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		var lines []string
		for _, priv := range privs {
			lines = append(lines, base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg)))
		}
		if err := os.WriteFile(f+".sig", []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
			return err
		}
		fmt.Printf("signed %s\n", f)
	}
	return nil
}

func verify(files []string) error {
	trust, err := trusted()
	if err != nil {
		return err
	}
	for _, f := range files {
		msg, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		sigFile, err := os.ReadFile(f + ".sig")
		if err != nil {
			return err
		}
		ok := false
		for _, line := range strings.Split(strings.TrimSpace(string(sigFile)), "\n") {
			sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(line))
			if err != nil {
				continue
			}
			for _, pub := range trust {
				if ed25519.Verify(pub, msg, sig) {
					ok = true
				}
			}
		}
		if !ok {
			return fmt.Errorf("%s: no signature verifies against %s", f, trustedPath)
		}
		fmt.Printf("verified %s\n", f)
	}
	return nil
}

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: stormsign sign|verify <file>...")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "sign":
		err = sign(os.Args[2:])
	case "verify":
		err = verify(os.Args[2:])
	default:
		fmt.Fprintln(os.Stderr, "usage: stormsign sign|verify <file>...")
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "stormsign:", err)
		os.Exit(1)
	}
}
