package main

// ---------------------------------------------------------------------------
// Server tests: the pull and members endpoints against a warmed
// store, asserting the exact shapes the main instance strictly
// decodes — response key sets, signature validity, freshness
// gating, and the silent-skip rule.
// ---------------------------------------------------------------------------

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testSecret = "0123456789abcdef0123456789abcdef"

// testRig builds a server over a store warmed with one history
// pair, one type name and one corporation record.
func testRig(t *testing.T) (*server, *swarmIdentity) {
	t.Helper()
	st, err := openStore(t.TempDir() + "/warm.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.close() })
	now := time.Now().UTC()
	if err := st.replaceHistory(10000002, 34, []historyDay{
		{date: "2026-10-09", average: 5.5, highest: 6.0, lowest: 5.0, volume: 100, orderCount: 10},
		{date: "2026-10-10", average: 5.7, highest: 6.2, lowest: 5.1, volume: 120, orderCount: 12},
	}, now); err != nil {
		t.Fatal(err)
	}
	if err := st.upsertTypeName(34, "Tritanium", now); err != nil {
		t.Fatal(err)
	}
	if err := st.upsertOrgRecord(swarmKindCorporation, 98000001, `{"name":"Stored Corp"}`, now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	id, err := mintSwarmIdentity()
	if err != nil {
		t.Fatal(err)
	}
	cfg := config{secret: testSecret, publicBaseURL: "https://warmer.example.com"}
	esi := newESIClientWithBase("http://example.invalid", "test@example.com")
	return newServer(cfg, newPoller(cfg, esi, st, id), id), id
}

// authed builds a request carrying the shared bearer.
func authed(method, path string, body io.Reader) *http.Request {
	r := httptest.NewRequest(method, path, body)
	r.Header.Set("Authorization", "Bearer "+testSecret)
	return r
}

// TestMembersServesSealedSelf fetches the member list the way
// the main instance's gossip does: open the seal with the
// secret, find the signer, verify the signature.
func TestMembersServesSealedSelf(t *testing.T) {
	srv, id := testRig(t)
	rec := httptest.NewRecorder()
	srv.handler().ServeHTTP(rec, authed(http.MethodGet, "/swarm/members", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("members: status %d", rec.Code)
	}
	var body struct {
		Entry swarmSignedEntry `json:"entry"`
	}
	dec := json.NewDecoder(rec.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		t.Fatalf("members: unreadable: %v", err)
	}
	entry := body.Entry
	if entry.Kind != swarmKindMembers || entry.Signer != id.id || entry.Key != id.id {
		t.Errorf("members: entry %+v", entry)
	}
	opened, err := openSwarmMembers(entry.Payload, testSecret)
	if err != nil {
		t.Fatalf("members: seal does not open: %v", err)
	}
	var members []swarmMember
	mdec := json.NewDecoder(bytes.NewReader(opened))
	mdec.DisallowUnknownFields()
	if err := mdec.Decode(&members); err != nil {
		t.Fatalf("members: list unreadable: %v", err)
	}
	var self *swarmMember
	for i := range members {
		if members[i].InstanceID == entry.Signer {
			self = &members[i]
		}
	}
	if self == nil {
		t.Fatalf("members: signer not listed: %s", opened)
	}
	if self.PublicKey != id.publicString() || self.BaseURL != "https://warmer.example.com" {
		t.Errorf("members: self record %+v", self)
	}
	if !verifySwarmEntry(entry, self.PublicKey) {
		t.Error("members: entry does not verify against the listed key")
	}
}

// TestMembersDark refuses anonymous and wrong-bearer fetches,
// and answers nothing off-route.
func TestMembersDark(t *testing.T) {
	srv, _ := testRig(t)
	for name, r := range map[string]*http.Request{
		"no bearer":    httptest.NewRequest(http.MethodGet, "/swarm/members", nil),
		"wrong bearer": authed(http.MethodGet, "/swarm/members", nil),
	} {
		if name == "wrong bearer" {
			r.Header.Set("Authorization", "Bearer wrong")
		}
		rec := httptest.NewRecorder()
		srv.handler().ServeHTTP(rec, r)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s: status %d, want 403", name, rec.Code)
		}
	}
	for _, path := range []string{"/", "/swarm", "/swarm/pull/extra", "/healthz"} {
		rec := httptest.NewRecorder()
		srv.handler().ServeHTTP(rec, authed(http.MethodGet, path, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %s: status %d, want 404", path, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	srv.handler().ServeHTTP(rec, authed(http.MethodGet, "/swarm/pull", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("GET /swarm/pull: status %d, want 404", rec.Code)
	}
}

// TestPullServesHeldKeys pulls the warmed keys plus unknown and
// malformed ones: held keys come back signed, everything else
// is skipped silently.
func TestPullServesHeldKeys(t *testing.T) {
	srv, id := testRig(t)
	keys := []swarmPullKey{
		{Kind: swarmKindHistory, Key: "10000002/34"},
		{Kind: swarmKindTypeName, Key: "34"},
		{Kind: swarmKindCorporation, Key: "98000001"},
		{Kind: swarmKindHistory, Key: "10000002/35"}, // not held
		{Kind: "market_orders", Key: "10000002/34"},  // no such kind
		{Kind: swarmKindTypeName, Key: ""},           // empty key
		{Kind: swarmKindTypeName, Key: strings.Repeat("9", 129)},
	}
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(swarmPullRequest{Keys: keys}); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	srv.handler().ServeHTTP(rec, authed(http.MethodPost, "/swarm/pull", &buf))
	if rec.Code != http.StatusOK {
		t.Fatalf("pull: status %d", rec.Code)
	}
	var body struct {
		Entries []swarmSignedEntry `json:"entries"`
	}
	dec := json.NewDecoder(rec.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		t.Fatalf("pull: unreadable: %v", err)
	}
	if len(body.Entries) != 3 {
		t.Fatalf("pull: %d entries, want 3", len(body.Entries))
	}
	byKind := map[string]swarmSignedEntry{}
	for _, e := range body.Entries {
		byKind[e.Kind+"/"+e.Key] = e
		if e.Signer != id.id {
			t.Errorf("pull: entry signed by %q", e.Signer)
		}
		if !verifySwarmEntry(e, id.publicString()) {
			t.Errorf("pull: %s %s does not verify", e.Kind, e.Key)
		}
	}
	hist := byKind["market_history/10000002/34"]
	var hp swarmHistoryPayload
	if err := json.Unmarshal([]byte(hist.Payload), &hp); err != nil {
		t.Fatalf("pull: history payload unreadable: %v", err)
	}
	if hp.RegionID != 10000002 || hp.TypeID != 34 || len(hp.Days) != 2 {
		t.Errorf("pull: history payload %+v", hp)
	}
	if hp.Days[0].Date != "2026-10-10" {
		t.Errorf("pull: history days not newest first: %+v", hp.Days)
	}
	named := byKind["type_name/34"]
	var np swarmTypeNamePayload
	if err := json.Unmarshal([]byte(named.Payload), &np); err != nil || np.Name != "Tritanium" {
		t.Errorf("pull: type name payload %q: %v", named.Payload, err)
	}
	org := byKind["corporation_record/98000001"]
	var op swarmOrgPayload
	if err := json.Unmarshal([]byte(org.Payload), &op); err != nil || op.Payload != `{"name":"Stored Corp"}` {
		t.Errorf("pull: org payload %q: %v", org.Payload, err)
	}
}

// TestPullShapeAndBounds pins the response envelope (exactly
// "entries", never null) and the request bounds.
func TestPullShapeAndBounds(t *testing.T) {
	srv, _ := testRig(t)
	post := func(body string) *httptest.ResponseRecorder {
		r := authed(http.MethodPost, "/swarm/pull", strings.NewReader(body))
		rec := httptest.NewRecorder()
		srv.handler().ServeHTTP(rec, r)
		return rec
	}
	empty := post(`{"keys":[]}`)
	if empty.Code != http.StatusOK {
		t.Fatalf("empty pull: status %d", empty.Code)
	}
	if strings.TrimSpace(empty.Body.String()) != `{"entries":[]}` {
		t.Errorf("empty pull body %q, want %q", empty.Body.String(), `{"entries":[]}`)
	}
	var many strings.Builder
	many.WriteString(`{"keys":[`)
	for i := 0; i < maxSwarmPullKeys+1; i++ {
		if i > 0 {
			many.WriteString(",")
		}
		many.WriteString(`{"kind":"type_name","key":"34"}`)
	}
	many.WriteString(`]}`)
	if rec := post(many.String()); rec.Code != http.StatusBadRequest {
		t.Errorf("%d keys: status %d, want 400", maxSwarmPullKeys+1, rec.Code)
	}
	if rec := post(`{"keys":[],"unknown":true}`); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown field: status %d, want 400", rec.Code)
	}
	r := authed(http.MethodPost, "/swarm/pull", strings.NewReader(`{"keys":[]}`))
	r.Header.Set("Authorization", "Bearer wrong")
	rec := httptest.NewRecorder()
	srv.handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Errorf("wrong bearer: status %d, want 403", rec.Code)
	}
}

// TestPullServesOnlyFreshHistory holds a stale pair back: the
// response never moves stale rows sideways.
func TestPullServesOnlyFreshHistory(t *testing.T) {
	srv, _ := testRig(t)
	var buf bytes.Buffer
	_ = json.NewEncoder(&buf).Encode(swarmPullRequest{Keys: []swarmPullKey{
		{Kind: swarmKindHistory, Key: "10000002/34"},
	}})
	// Age the pair past the gate by rewriting its fetch time.
	st := srv.poller.store
	old := time.Now().UTC().Add(-historyRefetchGate - time.Hour)
	if _, err := st.db.Exec(`UPDATE history_state SET fetched_at = ? WHERE region_id = 10000002 AND type_id = 34`, old.Unix()); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	srv.handler().ServeHTTP(rec, authed(http.MethodPost, "/swarm/pull", &buf))
	if rec.Code != http.StatusOK {
		t.Fatalf("pull: status %d", rec.Code)
	}
	if strings.TrimSpace(rec.Body.String()) != `{"entries":[]}` {
		t.Errorf("stale pair served: %s", rec.Body.String())
	}
}
