package main

// ---------------------------------------------------------------------------
// Wire tests: the byte contract with the main instance. The envelope
// vector pins encoding/json's exact output (field order, HTML
// escaping) against a hand-computed string — the same bytes the
// main instance and the seed worker hash. Everything else pins
// the accept/reject behavior both sides rely on.
// ---------------------------------------------------------------------------

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestEnvelopeBytesExact pins the canonical envelope bytes,
// including Go's string escaping (<, >, & and control
// characters). A verifier hashing different bytes rejects
// every entry, so this is the load-bearing assertion.
func TestEnvelopeBytesExact(t *testing.T) {
	doc, err := json.Marshal(swarmEnvelope{
		V: 1, Kind: "market_history", Key: "10000002/34",
		Payload: "a<b>&\"c\"\x01d", FetchedAt: 1760000000, Signer: "id-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"v":1,"kind":"market_history","key":"10000002/34","payload":"a\u003cb\u003e\u0026\"c\"\u0001d","fetched_at":1760000000,"signer":"id-1"}`
	if string(doc) != want {
		t.Errorf("envelope bytes:\n got %s\nwant %s", doc, want)
	}
}

// TestSignVerifyRoundTrip signs one entry and verifies it
// against the public string, the way a peer pins and checks.
func TestSignVerifyRoundTrip(t *testing.T) {
	id, err := mintSwarmIdentity()
	if err != nil {
		t.Fatal(err)
	}
	entry, err := signSwarmEntry(id, id.id, swarmKindTypeName, "34", `{"type_id":34,"name":"Tritanium"}`, time.Unix(1760000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if entry.Signer != id.id || entry.FetchedAt != 1760000000 {
		t.Errorf("signed entry carries %+v", entry)
	}
	if !verifySwarmEntry(entry, id.publicString()) {
		t.Error("fresh signature does not verify")
	}
}

// TestVerifyRejects tampers every covered field and the key:
// any change refuses, with no reason given.
func TestVerifyRejects(t *testing.T) {
	id, err := mintSwarmIdentity()
	if err != nil {
		t.Fatal(err)
	}
	other, err := mintSwarmIdentity()
	if err != nil {
		t.Fatal(err)
	}
	base, err := signSwarmEntry(id, id.id, swarmKindHistory, "10000002/34", `{"region_id":10000002,"type_id":34,"days":[]}`, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	mutate := func(f func(*swarmSignedEntry)) swarmSignedEntry {
		e := base
		f(&e)
		return e
	}
	sig := base.Signature
	rawSig, _ := base64.StdEncoding.DecodeString(sig)
	rawSig[0] ^= 1
	flipped := base64.StdEncoding.EncodeToString(rawSig)
	oversize := strings.Repeat("x", maxSwarmPayloadBytes+1)
	for name, entry := range map[string]swarmSignedEntry{
		"kind":       mutate(func(e *swarmSignedEntry) { e.Kind = "type_name" }),
		"key":        mutate(func(e *swarmSignedEntry) { e.Key = "10000002/35" }),
		"payload":    mutate(func(e *swarmSignedEntry) { e.Payload += " " }),
		"fetched_at": mutate(func(e *swarmSignedEntry) { e.FetchedAt++ }),
		"signer":     mutate(func(e *swarmSignedEntry) { e.Signer = other.id }),
		"signature":  mutate(func(e *swarmSignedEntry) { e.Signature = flipped }),
		"short_sig":  mutate(func(e *swarmSignedEntry) { e.Signature = base64.StdEncoding.EncodeToString(rawSig[:10]) }),
		"empty_kind": mutate(func(e *swarmSignedEntry) { e.Kind = "" }),
		"empty_key":  mutate(func(e *swarmSignedEntry) { e.Key = "" }),
		"oversize":   mutate(func(e *swarmSignedEntry) { e.Payload = oversize }),
	} {
		if verifySwarmEntry(entry, id.publicString()) {
			t.Errorf("%s: tampered entry verifies", name)
		}
	}
	if verifySwarmEntry(base, other.publicString()) {
		t.Error("entry verifies against the wrong key")
	}
	if verifySwarmEntry(base, "not-base64!!") {
		t.Error("entry verifies against a malformed key")
	}
	// Oversized payloads never sign.
	if _, err := signSwarmEntry(id, id.id, swarmKindHistory, "k", oversize, time.Now()); err == nil {
		t.Error("oversized payload signed")
	}
}

// TestSealMembersRoundTrip seals a member list and opens it
// with the same secret; any other secret, or any damage,
// refuses identically.
func TestSealMembersRoundTrip(t *testing.T) {
	const secret = "0123456789abcdef0123456789abcdef"
	raw := []byte(`[{"instance_id":"a","base_url":"https://x.example","public_key":"k"}]`)
	sealed, err := sealSwarmMembers(raw, secret)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(sealed, swarmMembersPrefix) {
		t.Errorf("sealed list has no %q prefix", swarmMembersPrefix)
	}
	opened, err := openSwarmMembers(sealed, secret)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, raw) {
		t.Error("opened list differs")
	}
	for name, probe := range map[string]string{
		"wrong secret": sealed[:len(sealed)-2] + "xx",
		"bad prefix":   "xx:v1:" + sealed[len(swarmMembersPrefix):],
		"bad base64":   swarmMembersPrefix + "!!!",
		"truncated":    sealed[:len(swarmMembersPrefix)+4],
	} {
		if _, err := openSwarmMembers(probe, secret); err == nil {
			t.Errorf("%s: damaged seal opens", name)
		}
	}
	if _, err := openSwarmMembers(sealed, "another-32-character-secret-here!"); err == nil {
		t.Error("seal opens under another secret")
	}
}

// TestIdentityFileRoundTrip mints an identity file and reopens
// it; a changed secret mints fresh instead of reusing an
// unreadable key.
func TestIdentityFileRoundTrip(t *testing.T) {
	const secret = "0123456789abcdef0123456789abcdef"
	path := t.TempDir() + "/identity.json"
	id, rotated, err := loadIdentity(path, secret)
	if err != nil {
		t.Fatal(err)
	}
	if rotated {
		t.Error("first boot reports rotation")
	}
	same, rotated, err := loadIdentity(path, secret)
	if err != nil || rotated {
		t.Fatalf("reopen: %v rotated=%v", err, rotated)
	}
	if same.id != id.id || same.publicString() != id.publicString() {
		t.Error("reopened identity differs")
	}
	fresh, rotated, err := loadIdentity(path, "a-different-32-character-secret!!")
	if err != nil || !rotated {
		t.Fatalf("wrong secret: %v rotated=%v", err, rotated)
	}
	if fresh.id == id.id {
		t.Error("wrong secret reused the identity")
	}
}

// TestSwarmAuthVectors pins the bearer gate.
func TestSwarmAuthVectors(t *testing.T) {
	const secret = "0123456789abcdef0123456789abcdef"
	req := func(header string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/swarm/members", nil)
		if header != "" {
			r.Header.Set("Authorization", header)
		}
		return r
	}
	if !swarmAuth(secret, req("Bearer "+secret)) {
		t.Error("correct bearer refused")
	}
	for name, h := range map[string]string{
		"missing": "",
		"wrong":   "Bearer wrong",
		"scheme":  "Basic " + secret,
		"empty":   "Bearer ",
		"prefix":  "Bearer " + secret + "-suffix",
	} {
		if swarmAuth(secret, req(h)) {
			t.Errorf("%s bearer accepted", name)
		}
	}
	if swarmAuth("", req("Bearer anything")) {
		t.Error("empty secret accepts")
	}
}

// TestValidSwarmBaseURLVectors pins the dial rule: https
// anywhere, http on loopback only.
func TestValidSwarmBaseURLVectors(t *testing.T) {
	ok := []string{
		"https://warmer.example.com",
		"https://warmer.example.com:8443/base",
		"http://127.0.0.1:8079",
		"http://localhost:8079",
		"http://[::1]:8079",
	}
	for _, u := range ok {
		if !validSwarmBaseURL(u) {
			t.Errorf("%s refused", u)
		}
	}
	bad := []string{
		"",
		"not a url",
		"http://warmer.example.com",
		"ftp://warmer.example.com",
		"//warmer.example.com",
		"https://",
	}
	for _, u := range bad {
		if validSwarmBaseURL(u) {
			t.Errorf("%s accepted", u)
		}
	}
}

// TestReadSwarmJSONStrict rejects unknown fields and oversized
// bodies: the wire format is fixed.
func TestReadSwarmJSONStrict(t *testing.T) {
	req := func(body string) *http.Request {
		return httptest.NewRequest(http.MethodPost, "/swarm/pull", strings.NewReader(body))
	}
	var into swarmPullRequest
	if err := readSwarmJSON(req(`{"keys":[]}`), &into); err != nil {
		t.Errorf("valid pull rejected: %v", err)
	}
	if err := readSwarmJSON(req(`{"keys":[],"extra":1}`), &into); err == nil {
		t.Error("unknown field accepted")
	}
	if err := readSwarmJSON(req(`{"keys":[`), &into); err == nil {
		t.Error("truncated body accepted")
	}
	big := httptest.NewRequest(http.MethodPost, "/swarm/pull", strings.NewReader(strings.Repeat("x", maxSwarmBodyBytes+1)))
	if err := readSwarmJSON(big, &into); err == nil {
		t.Error("oversized body accepted")
	}
}

// TestAnnounceEntryShape pins the heartbeat's exact key set:
// the seed worker rejects any other shape.
func TestAnnounceEntryShape(t *testing.T) {
	id, err := mintSwarmIdentity()
	if err != nil {
		t.Fatal(err)
	}
	entry, err := signSwarmEntry(id, id.id, swarmAnnounceKind, id.id, `{"base_url":"https://w.example","public_key":"k"}`, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	var keys map[string]any
	if err := json.Unmarshal(raw, &keys); err != nil {
		t.Fatal(err)
	}
	want := []string{"fetched_at", "key", "kind", "payload", "signature", "signer"}
	if len(keys) != len(want) {
		t.Fatalf("announce has %d keys, want %d: %s", len(keys), len(want), raw)
	}
	for _, k := range want {
		if _, found := keys[k]; !found {
			t.Errorf("announce missing %q: %s", k, raw)
		}
	}
}
