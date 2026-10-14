package main

// ---------------------------------------------------------------------------
// Register tests: the seed directory against the worker's
// contract â€” round-trip heartbeats, exact status codes, expiry,
// re-announce updates, and the full-directory refusal.
// ---------------------------------------------------------------------------

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// issueClock hands each test heartbeat a later issue time than
// the last: two real heartbeats are never issued in the same
// second, and a tuple no newer than the one held is not taken up.
var issueClock = time.Now().Unix()

func nextIssue() int64 {
	issueClock++
	return issueClock
}

// announceHeartbeat signs one heartbeat for the given identity
// and address.
func announceHeartbeat(t *testing.T, id *swarmIdentity, baseURL string) swarmSignedEntry {
	t.Helper()
	entry, err := signSwarmEntry(id, id.id, swarmAnnounceKind, id.id,
		announcePayload(id, baseURL, nextIssue()), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return entry
}

// postRegister posts one body to the register route.
func postRegister(srv *server, auth string, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/swarm/seed/register", strings.NewReader(body))
	if auth != "" {
		r.Header.Set("Authorization", auth)
	}
	rec := httptest.NewRecorder()
	srv.handler().ServeHTTP(rec, r)
	return rec
}

// postEntry posts one announce entry with the shared secret.
func postEntry(srv *server, entry swarmSignedEntry) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(map[string]any{"entry": entry}); err != nil {
		panic(err)
	}
	return postRegister(srv, "Bearer "+testSecret, buf.String())
}

// readMembers fetches the sealed list the way gossip does: open
// with the secret, verify against the serving key.
func readMembers(t *testing.T, srv *server, id *swarmIdentity) []swarmMember {
	t.Helper()
	rec := httptest.NewRecorder()
	srv.handler().ServeHTTP(rec, authed(http.MethodGet, "/swarm/members", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("members: status %d", rec.Code)
	}
	var body struct {
		Entry swarmSignedEntry `json:"entry"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("members: unreadable: %v", err)
	}
	if !verifySwarmEntry(body.Entry, id.publicString()) {
		t.Fatal("members: entry does not verify")
	}
	opened, err := openSwarmMembers(body.Entry.Payload, testSecret)
	if err != nil {
		t.Fatalf("members: seal does not open: %v", err)
	}
	var members []swarmMember
	if err := json.Unmarshal(opened, &members); err != nil {
		t.Fatalf("members: list unreadable: %v", err)
	}
	return members
}

// TestSeedRegisterRoundTrip heartbeats one node and proves it
// lists behind self in the sealed directory.
func TestSeedRegisterRoundTrip(t *testing.T) {
	srv, id := testRig(t)
	node, err := mintSwarmIdentity()
	if err != nil {
		t.Fatal(err)
	}
	rec := postEntry(srv, announceHeartbeat(t, node, "https://node-b.example"))
	if rec.Code != http.StatusOK {
		t.Fatalf("register: status %d", rec.Code)
	}
	var ok struct {
		OK bool `json:"ok"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&ok); err != nil || !ok.OK {
		t.Fatalf("register: body %q", rec.Body.String())
	}
	members := readMembers(t, srv, id)
	if len(members) != 2 {
		t.Fatalf("directory holds %d members, want self + 1", len(members))
	}
	if members[0].InstanceID != id.id {
		t.Errorf("directory first lists %q, want self", members[0].InstanceID)
	}
	if members[1].InstanceID != node.id || members[1].BaseURL != "https://node-b.example" ||
		members[1].PublicKey != node.publicString() {
		t.Errorf("directory peer %+v", members[1])
	}
}

// TestSeedRegisterCodes pins every validation code against the
// worker's: dark without credentials, 403 on a wrong secret,
// 400 on any misshapen announce or failed proof.
func TestSeedRegisterCodes(t *testing.T) {
	srv, _ := testRig(t)
	goodID, err := mintSwarmIdentity()
	if err != nil {
		t.Fatal(err)
	}
	otherID, err := mintSwarmIdentity()
	if err != nil {
		t.Fatal(err)
	}
	good := announceHeartbeat(t, goodID, "https://node.example")
	goodRaw, err := json.Marshal(good)
	if err != nil {
		t.Fatal(err)
	}
	var goodMap map[string]any
	if err := json.Unmarshal(goodRaw, &goodMap); err != nil {
		t.Fatal(err)
	}
	entryBody := func(entry any) string {
		var buf bytes.Buffer
		_ = json.NewEncoder(&buf).Encode(map[string]any{"entry": entry})
		return buf.String()
	}
	big := strings.Repeat("x", maxSwarmBodyBytes+1)
	// Signed by another key while claiming goodID's: proof fails.
	resigned, err := signSwarmEntry(otherID, goodID.id, swarmAnnounceKind, goodID.id,
		announcePayload(goodID, "https://node.example", time.Now().Unix()), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	extraKey := map[string]any{}
	for k, v := range goodMap {
		extraKey[k] = v
	}
	extraKey["zzz"] = 1
	kindSwap := map[string]any{}
	for k, v := range goodMap {
		kindSwap[k] = v
	}
	kindSwap["kind"] = swarmKindHistory
	for name, tc := range map[string]struct {
		auth string
		body string
		want int
	}{
		"no credentials":  {auth: "", body: entryBody(good), want: http.StatusNotFound},
		"wrong secret":    {auth: "Bearer wrong", body: entryBody(good), want: http.StatusForbidden},
		"empty body":      {auth: "Bearer " + testSecret, body: "", want: http.StatusBadRequest},
		"bad json":        {auth: "Bearer " + testSecret, body: "{", want: http.StatusBadRequest},
		"no entry":        {auth: "Bearer " + testSecret, body: `{}`, want: http.StatusBadRequest},
		"extra entry key": {auth: "Bearer " + testSecret, body: entryBody(extraKey), want: http.StatusBadRequest},
		"wrong kind":      {auth: "Bearer " + testSecret, body: entryBody(kindSwap), want: http.StatusBadRequest},
		"bad signature":   {auth: "Bearer " + testSecret, body: entryBody(resigned), want: http.StatusBadRequest},
		"oversized":       {auth: "Bearer " + testSecret, body: big, want: http.StatusBadRequest},
	} {
		if rec := postRegister(srv, tc.auth, tc.body); rec.Code != tc.want {
			t.Errorf("%s: status %d, want %d", name, rec.Code, tc.want)
		}
	}
	// Payload-level refusals: unparsable, non-https, proof mismatch.
	payloadCases := map[string]string{
		"plain string":  "hello",
		"http address":  `{"base_url":"http://node.example","public_key":"k"}`,
		"loopback":      `{"base_url":"http://127.0.0.1:8079","public_key":"k"}`,
		"missing key":   `{"base_url":"https://node.example"}`,
		"foreign proof": announcePayload(otherID, "https://node.example", time.Now().Unix()),
	}
	for name, payload := range payloadCases {
		entry, err := signSwarmEntry(goodID, goodID.id, swarmAnnounceKind, goodID.id, payload, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if rec := postEntry(srv, entry); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", name, rec.Code)
		}
	}
	// Extra top-level keys are tolerated, like the worker.
	var buf bytes.Buffer
	_ = json.NewEncoder(&buf).Encode(map[string]any{"entry": good, "zzz": 1})
	if rec := postRegister(srv, "Bearer "+testSecret, buf.String()); rec.Code != http.StatusOK {
		t.Errorf("extra top-level key: status %d, want 200", rec.Code)
	}
}

// TestSeedDirectoryExpiry lists only fresh heartbeats: a lapsed
// record stays stored until pruned but never serves.
func TestSeedDirectoryExpiry(t *testing.T) {
	srv, id := testRig(t)
	fresh, err := mintSwarmIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if rec := postEntry(srv, announceHeartbeat(t, fresh, "https://fresh.example")); rec.Code != http.StatusOK {
		t.Fatalf("register fresh: status %d", rec.Code)
	}
	store := srv.poller.store
	if err := store.upsertSeedPeer("stale-id", "https://stale.example", strings.Repeat("A", 44), "", 0, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`UPDATE seed_peers SET last_heartbeat = ? WHERE instance_id = 'stale-id'`,
		time.Now().UTC().Add(-seedPeerTTL-time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	members := readMembers(t, srv, id)
	if len(members) != 2 || members[1].InstanceID != fresh.id {
		t.Errorf("directory serves %+v, want self + fresh only", members)
	}
}

// TestSeedRegisterReannounce files an address move over the old
// record: one row, new address.
func TestSeedRegisterReannounce(t *testing.T) {
	srv, id := testRig(t)
	node, err := mintSwarmIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if rec := postEntry(srv, announceHeartbeat(t, node, "https://one.example")); rec.Code != http.StatusOK {
		t.Fatalf("register: status %d", rec.Code)
	}
	if rec := postEntry(srv, announceHeartbeat(t, node, "https://two.example")); rec.Code != http.StatusOK {
		t.Fatalf("re-announce: status %d", rec.Code)
	}
	members := readMembers(t, srv, id)
	if len(members) != 2 || members[1].BaseURL != "https://two.example" {
		t.Errorf("directory after move %+v", members)
	}
}

// TestSeedDirectoryCapacity refuses new heartbeats past a
// thousand listings (the worker's 429), while re-announces from
// listed IDs still refresh.
func TestSeedDirectoryCapacity(t *testing.T) {
	srv, _ := testRig(t)
	store := srv.poller.store
	now := time.Now().UTC()
	for i := 0; i < maxStoredSeedPeers-1; i++ {
		if err := store.upsertSeedPeer(fmt.Sprintf("filler-%d", i), "https://filler.example", strings.Repeat("A", 44), "", 0, now); err != nil {
			t.Fatal(err)
		}
	}
	listed, err := mintSwarmIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if rec := postEntry(srv, announceHeartbeat(t, listed, "https://listed.example")); rec.Code != http.StatusOK {
		t.Fatalf("register 1000th: status %d", rec.Code)
	}
	extra, err := mintSwarmIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if rec := postEntry(srv, announceHeartbeat(t, extra, "https://extra.example")); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("register 1001st: status %d, want 429", rec.Code)
	}
	if rec := postEntry(srv, announceHeartbeat(t, listed, "https://listed.example")); rec.Code != http.StatusOK {
		t.Fatalf("re-announce listed: status %d, want 200", rec.Code)
	}
}

// TestMemberMessageVector pins the bytes a member signs to own
// its address and one signature over them from a fixed key: the
// same vector the main instance pins. If it changes, every
// instance, warmer and seed must change with it.
func TestMemberMessageVector(t *testing.T) {
	if got := string(swarmMemberMessage("id-1", "https://node.example.org", 1760000000)); got != "member\nid-1\nhttps://node.example.org\n1760000000" {
		t.Fatalf("member message %q", got)
	}
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	id := &swarmIdentity{id: "id-1", public: priv.Public().(ed25519.PublicKey), private: priv}
	const wantSig = "RIsOrR2+TRyZ/VEgnPjXfCRbSClfr/gScvRKJj5It5KP7i9NoyAwbSf75pIBIlo+pUIZOr9Kg64XIjnV8hVhAg=="
	if got := signSwarmMember(id, "https://node.example.org", 1760000000); got != wantSig {
		t.Fatalf("url_sig %s, want %s", got, wantSig)
	}
}

// TestMembersCarryOwnersSignatures: the node signs its own tuple
// and relays a registered peer's tuple exactly as it arrived.
func TestMembersCarryOwnersSignatures(t *testing.T) {
	srv, id := testRig(t)
	peer, err := mintSwarmIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if rec := postEntry(srv, announceHeartbeat(t, peer, "https://peer.example")); rec.Code != http.StatusOK {
		t.Fatalf("register: status %d", rec.Code)
	}
	byID := map[string]swarmMember{}
	for _, m := range readMembers(t, srv, id) {
		byID[m.InstanceID] = m
	}
	self, ok := byID[id.id]
	if !ok || !verifySwarmMember(self) {
		t.Fatalf("own tuple %+v carries no valid address signature", self)
	}
	relayed, ok := byID[peer.id]
	if !ok || relayed.BaseURL != "https://peer.example" || relayed.URLSig != signSwarmMember(peer, "https://peer.example", relayed.IssuedAt) || relayed.IssuedAt == 0 || !verifySwarmMember(relayed) {
		t.Fatalf("relayed tuple %+v was not passed on as registered", relayed)
	}
}

// TestSeedRegisterNeedsAddressSignature: a heartbeat whose
// payload lacks the sender's signature over its address, or
// carries one made for another address, is refused.
func TestSeedRegisterNeedsAddressSignature(t *testing.T) {
	srv, _ := testRig(t)
	peer, err := mintSwarmIdentity()
	if err != nil {
		t.Fatal(err)
	}
	for name, sig := range map[string]string{
		"no signature":             "",
		"signed for another place": signSwarmMember(peer, "https://elsewhere.example", 1760000000),
		"signed for another time":  signSwarmMember(peer, "https://peer.example", 1750000000),
	} {
		raw, err := json.Marshal(seedAnnouncePayload{BaseURL: "https://peer.example", PublicKey: peer.publicString(), URLSig: sig, IssuedAt: 1760000000})
		if err != nil {
			t.Fatal(err)
		}
		entry, err := signSwarmEntry(peer, peer.id, swarmAnnounceKind, peer.id, string(raw), time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if rec := postEntry(srv, entry); rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: status %d, want 400", name, rec.Code)
		}
	}
}

// TestSeedRegisterKeepsFirstKey: while an ID is listed, a
// heartbeat for it under another key is a conflict and changes
// nothing; the owner can still move its own address.
func TestSeedRegisterKeepsFirstKey(t *testing.T) {
	srv, id := testRig(t)
	peer, err := mintSwarmIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if rec := postEntry(srv, announceHeartbeat(t, peer, "https://peer.example")); rec.Code != http.StatusOK {
		t.Fatalf("register: status %d", rec.Code)
	}
	impostor, err := mintSwarmIdentity()
	if err != nil {
		t.Fatal(err)
	}
	impostor.id = peer.id
	if rec := postEntry(srv, announceHeartbeat(t, impostor, "https://impostor.example")); rec.Code != http.StatusConflict {
		t.Fatalf("impostor heartbeat: status %d, want 409", rec.Code)
	}
	if rec := postEntry(srv, announceHeartbeat(t, peer, "https://moved.example")); rec.Code != http.StatusOK {
		t.Fatalf("owner re-announce: status %d", rec.Code)
	}
	for _, m := range readMembers(t, srv, id) {
		if m.InstanceID == peer.id && (m.PublicKey != peer.publicString() || m.BaseURL != "https://moved.example") {
			t.Fatalf("listing after the conflict: %+v", m)
		}
	}
}

// TestSeedRegisterKeepsNewestTuple: a heartbeat the owner really
// signed, but issued earlier than the tuple held, refreshes the
// listing without moving the address back.
func TestSeedRegisterKeepsNewestTuple(t *testing.T) {
	srv, id := testRig(t)
	peer, err := mintSwarmIdentity()
	if err != nil {
		t.Fatal(err)
	}
	beat := func(url string, issued int64) swarmSignedEntry {
		t.Helper()
		entry, err := signSwarmEntry(peer, peer.id, swarmAnnounceKind, peer.id, announcePayload(peer, url, issued), time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return entry
	}
	for _, step := range []struct {
		url    string
		issued int64
		want   string
	}{
		{"https://first.example", 1760000100, "https://first.example"},
		{"https://replayed.example", 1760000050, "https://first.example"},
		{"https://second.example", 1760000200, "https://second.example"},
	} {
		if rec := postEntry(srv, beat(step.url, step.issued)); rec.Code != http.StatusOK {
			t.Fatalf("heartbeat for %s: status %d", step.url, rec.Code)
		}
		for _, m := range readMembers(t, srv, id) {
			if m.InstanceID == peer.id && m.BaseURL != step.want {
				t.Fatalf("after a tuple for %s issued at %d the listing is %s, want %s", step.url, step.issued, m.BaseURL, step.want)
			}
		}
	}
}
