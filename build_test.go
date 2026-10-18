package main

// ---------------------------------------------------------------------------
// Build claim tests: the heartbeat this node sends and the
// member list it serves both carry its self-reported build
// claim (the SHA-256 of its own binary) — display metadata
// for the receivers' admin pages, verified and acted on
// nowhere here.
// ---------------------------------------------------------------------------

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

// TestBuildClaimIsOwnHash: the node's claim is the hash of
// the binary the test itself runs as — a well-formed
// SHA-256 hex string.
func TestBuildClaimIsOwnHash(t *testing.T) {
	claim := buildClaim()
	if claim == "" {
		t.Fatal("no claim: the test binary's executable should be readable")
	}
	raw, err := hex.DecodeString(claim)
	if err != nil || len(raw) != 32 {
		t.Fatalf("claim %q is not a SHA-256 hex string", claim)
	}
	if again := buildClaim(); again != claim {
		t.Fatalf("claim changed between calls: %q then %q", claim, again)
	}
}

// TestAnnouncePayloadCarriesBuild: the sealed heartbeat
// payload names the node's build claim beside the address it
// signs.
func TestAnnouncePayloadCarriesBuild(t *testing.T) {
	id, err := mintSwarmIdentity()
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	raw := announcePayload(id, "https://warmer.example.com", time.Now().Unix())
	var payload seedAnnouncePayload
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		t.Fatalf("announce payload is not JSON: %v", err)
	}
	if payload.Build != buildClaim() {
		t.Fatalf("announce claim %q, want the node's own hash %q", payload.Build, buildClaim())
	}
}

// TestMembersCarryBuild: the member list this node serves
// names its own claim; a heartbeat carrying a claim is
// accepted by the register exactly as one without.
func TestMembersCarryBuild(t *testing.T) {
	srv, id := testRig(t)
	members := readMembers(t, srv, id)
	if len(members) == 0 {
		t.Fatal("members list is empty")
	}
	if members[0].InstanceID != id.id {
		t.Fatalf("first member is %q, want the node itself", members[0].InstanceID)
	}
	if members[0].Build != buildClaim() {
		t.Fatalf("served self claim %q, want the node's own hash %q", members[0].Build, buildClaim())
	}

	peer, err := mintSwarmIdentity()
	if err != nil {
		t.Fatalf("mint peer: %v", err)
	}
	if rec := postEntry(srv, announceHeartbeat(t, peer, "https://peer.example")); rec.Code != http.StatusOK {
		t.Fatalf("register heartbeat with a build claim: status %d, want 200", rec.Code)
	}
}
