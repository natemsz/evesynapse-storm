package main

// ---------------------------------------------------------------------------
// Identity at rest: the node's Ed25519 keypair lives in one file,
// the seed sealed under a key derived from the shared secret (the
// main instance's construction, same salt and label), so a copy
// of the file alone cannot sign as this node. Minted once on
// first boot; the swarm allowlist depends on the key being
// stable, so the file must be backed up with the database.
//
// A seal that stops opening (the secret changed) mints a fresh
// identity, like the main instance: the old key is gone with the
// old secret, and signing on with an unreadable key is
// impossible by construction. The rotation is reported so the
// operator re-allowlists the new key.
// ---------------------------------------------------------------------------

import (
	"encoding/json"
	"fmt"
	"os"
)

// identityFile is the on-disk shape.
type identityFile struct {
	InstanceID string `json:"instance_id"`
	PublicKey  string `json:"public_key"`
	SealedSeed string `json:"sealed_seed"`
}

// loadIdentity reads the node's identity, minting and storing
// one on first boot. rotated reports a fresh mint over an
// unreadable file: the operator must re-allowlist the node.
func loadIdentity(path, secret string) (id *swarmIdentity, rotated bool, err error) {
	raw, ferr := os.ReadFile(path)
	if ferr == nil {
		var rec identityFile
		if jerr := json.Unmarshal(raw, &rec); jerr == nil {
			if id, ok := openSwarmIdentity(rec.InstanceID, rec.PublicKey, rec.SealedSeed, secret); ok {
				return id, false, nil
			}
		}
		rotated = true
	} else if !os.IsNotExist(ferr) {
		return nil, false, fmt.Errorf("warmer: read identity: %w", ferr)
	}
	id, err = mintSwarmIdentity()
	if err != nil {
		return nil, false, err
	}
	sealed, err := sealSwarmSeed(id.private.Seed(), secret)
	if err != nil {
		return nil, false, err
	}
	out, err := json.Marshal(identityFile{InstanceID: id.id, PublicKey: id.publicString(), SealedSeed: sealed})
	if err != nil {
		return nil, false, fmt.Errorf("warmer: encode identity: %w", err)
	}
	if err := os.WriteFile(path, out, 0600); err != nil {
		return nil, false, fmt.Errorf("warmer: store identity: %w", err)
	}
	return id, rotated, nil
}
