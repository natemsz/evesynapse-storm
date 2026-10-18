package main

// ---------------------------------------------------------------------------
// Build claim: this node's self-reported build, the SHA-256 of
// its own running binary. It rides the seed heartbeat and this
// node's member tuple so a receiving instance can name the
// build on its admin page (the main instance's release library
// does the naming). Self-reported display metadata: nothing
// here verifies it and nothing acts on it, and this node keeps
// no version concept of its own for the purpose — the hash is
// the whole claim.
// ---------------------------------------------------------------------------

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"sync"
)

// buildClaim is the SHA-256 (hex) of the running binary,
// hashed once from the executable file. Empty when the
// executable cannot be read: a node that cannot name its
// build makes no claim.
func buildClaim() string {
	ownBuildOnce.Do(func() {
		ownBuild = hashOwnExecutable()
	})
	return ownBuild
}

var (
	ownBuild     string
	ownBuildOnce sync.Once
)

func hashOwnExecutable() string {
	path, err := os.Executable()
	if err != nil {
		return ""
	}
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}
