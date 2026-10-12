package main

// ---------------------------------------------------------------------------
// Register tests: the seed directory against the worker's
// contract â€” round-trip heartbeats, exact status codes, expiry,
// re-announce updates, and the full-directory refusal.
// ---------------------------------------------------------------------------

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// announceHeartbeat signs one heartbeat for the given identity
// and address.
func announceHeartbeat(t *testing.T, id *swarmIdentity, baseURL string) swarmSignedEntry {
	t.Helper()
	entry, err := signSwarmEntry(id, id.id, swarmAnnounceKind, id.id,
		announcePayload(baseURL, id.publicString()), time.Now())
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
		announcePayload("https://node.example", goodID.publicString()), time.Now())
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
		"foreign proof": announcePayload("https://node.example", otherID.publicString()),
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
	if err := store.upsertSeedPeer("stale-id", "https://stale.example", strings.Repeat("A", 44), time.Now().UTC()); err != nil {
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
		if err := store.upsertSeedPeer(fmt.Sprintf("filler-%d", i), "https://filler.example", strings.Repeat("A", 44), now); err != nil {
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
