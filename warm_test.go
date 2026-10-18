package main

// ---------------------------------------------------------------------------
// Swarm-first warming tests: the /swarm/warms announcement the
// main instance strictly decodes, demand queued by pull misses,
// and the poll pass that drains it so the next pull serves.
// ---------------------------------------------------------------------------

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"
)

// pull posts one pull through the handler and returns the
// entries served.
func pull(t *testing.T, srv *server, keys ...swarmPullKey) []swarmSignedEntry {
	t.Helper()
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
	return body.Entries
}

// TestWarmsAnnouncesCoverage pins the coverage announcement: dark
// to a missing or wrong secret, and exactly {"kinds": [the five
// fetchable kinds]} with it — never structure_name.
func TestWarmsAnnouncesCoverage(t *testing.T) {
	srv, _ := testRig(t)
	anon := httptest.NewRequest(http.MethodGet, "/swarm/warms", nil)
	wrong := authed(http.MethodGet, "/swarm/warms", nil)
	wrong.Header.Set("Authorization", "Bearer wrong")
	for name, r := range map[string]*http.Request{"no bearer": anon, "wrong bearer": wrong} {
		rec := httptest.NewRecorder()
		srv.handler().ServeHTTP(rec, r)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s: status %d, want 403", name, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	srv.handler().ServeHTTP(rec, authed(http.MethodGet, "/swarm/warms", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("warms: status %d", rec.Code)
	}
	var body struct {
		Kinds []string `json:"kinds"`
	}
	dec := json.NewDecoder(rec.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		t.Fatalf("warms: unreadable under strict decoding: %v", err)
	}
	want := []string{swarmKindHistory, swarmKindTypeName, swarmKindCorporation, swarmKindAlliance, swarmKindPublicContract}
	if !slices.Equal(body.Kinds, want) {
		t.Errorf("warms: kinds %v, want %v", body.Kinds, want)
	}
	if slices.Contains(body.Kinds, swarmKindStructure) {
		t.Error("warms: promises structure names it cannot fetch")
	}
}

// TestPullMissRecordsDemand proves a covered miss queues exactly
// one demand row (a repeat refreshes it), a hit queues nothing,
// and an uncovered or junk key never queues.
func TestPullMissRecordsDemand(t *testing.T) {
	srv, _ := testRig(t)
	st := srv.poller.store
	miss := swarmPullKey{Kind: swarmKindHistory, Key: "10000002/35"}
	if got := pull(t, srv, miss, swarmPullKey{Kind: swarmKindTypeName, Key: "34"}); len(got) != 1 {
		t.Fatalf("pull: %d entries, want only the held name", len(got))
	}
	if n, err := st.countDemand(); err != nil || n != 1 {
		t.Fatalf("demand rows %d (%v), want 1", n, err)
	}
	first, ok, err := st.getDemand(miss.Kind, miss.Key)
	if err != nil || !ok {
		t.Fatalf("miss not queued: %v", err)
	}
	// Age the row, then ask again: the same row refreshes.
	aged := time.Now().UTC().Add(-time.Hour).Unix()
	if _, err := st.db.Exec(`UPDATE swarm_demand SET first_asked = ?, last_asked = ?`, aged, aged); err != nil {
		t.Fatal(err)
	}
	if got := pull(t, srv, miss); len(got) != 0 {
		t.Fatalf("repeat miss served %d entries", len(got))
	}
	if n, err := st.countDemand(); err != nil || n != 1 {
		t.Fatalf("repeat pull: demand rows %d (%v), want 1", n, err)
	}
	again, _, _ := st.getDemand(miss.Kind, miss.Key)
	if again.firstAsked.Unix() != aged {
		t.Errorf("repeat pull moved first_asked: %s", again.firstAsked)
	}
	if again.lastAsked.Unix() <= aged || again.lastAsked.Before(first.lastAsked) {
		t.Errorf("repeat pull did not refresh last_asked: %s", again.lastAsked)
	}
	// A structure name is never promised, so its miss is not
	// demand; neither is a key that names nothing.
	pull(t, srv,
		swarmPullKey{Kind: swarmKindStructure, Key: "1000000000001"},
		swarmPullKey{Kind: swarmKindHistory, Key: "bogus"},
		swarmPullKey{Kind: swarmKindTypeName, Key: "-5"},
	)
	if n, _ := st.countDemand(); n != 1 {
		t.Errorf("uncovered or junk misses queued: %d rows, want 1", n)
	}
	if _, ok, _ := st.getDemand(swarmKindStructure, "1000000000001"); ok {
		t.Error("structure_name miss recorded as demand")
	}
}

// TestPollDrainsDemand pulls keys no routine warming would ever
// fetch (a type with no orders anywhere), runs one pass, and
// proves the next pull serves them and the queue is empty.
func TestPollDrainsDemand(t *testing.T) {
	esiSrv, f := newFakeESI(t)
	p, st := testPoller(t, esiSrv)
	srv := newServer(p.cfg, p, p.id)
	keys := []swarmPullKey{
		{Kind: swarmKindHistory, Key: "10000002/99"},
		{Kind: swarmKindTypeName, Key: "99"},
	}
	if got := pull(t, srv, keys...); len(got) != 0 {
		t.Fatalf("cold pull served %d entries", len(got))
	}
	if n, _ := st.countDemand(); n != 2 {
		t.Fatalf("demand rows %d, want 2", n)
	}
	if f.total.Load() != 0 {
		t.Fatal("a pull miss spent ESI calls; demand must wait for the poll loop")
	}
	if hold := p.tick(context.Background(), time.Now().UTC()); hold != 0 {
		t.Fatalf("tick held %s", hold)
	}
	if n, _ := st.countDemand(); n != 0 {
		t.Errorf("demand rows after the pass: %d, want 0", n)
	}
	got := pull(t, srv, keys...)
	if len(got) != 2 {
		t.Fatalf("pull after the pass: %d entries, want 2", len(got))
	}
	for _, e := range got {
		if !verifySwarmEntry(e, p.id.publicString()) {
			t.Errorf("%s %s does not verify", e.Kind, e.Key)
		}
	}
	if name, held, _ := st.getTypeName(99); !held || name != "Type 99" {
		t.Errorf("demanded name stored as %q (held %v)", name, held)
	}
}

// TestDemandBackoffAndAging proves a dead key costs one call and
// then waits out its backoff instead of hot-looping, a non-type
// ID never lands as a type name, and a day of nobody asking drops
// a key unfetched.
func TestDemandBackoffAndAging(t *testing.T) {
	esiSrv, f := newFakeESI(t)
	p, st := testPoller(t, esiSrv)
	ctx := context.Background()
	now := time.Now().UTC()
	for _, id := range []string{"999999", "90000001"} {
		if err := st.noteDemand(swarmKindTypeName, id, now); err != nil {
			t.Fatal(err)
		}
	}
	if hold := p.tick(ctx, now); hold != 0 {
		t.Fatalf("tick held %s", hold)
	}
	names := f.count("/universe/names/")
	for _, id := range []string{"999999", "90000001"} {
		d, ok, err := st.getDemand(swarmKindTypeName, id)
		if err != nil || !ok {
			t.Fatalf("failed key %s left the queue: %v", id, err)
		}
		if !d.retryAt.After(now) {
			t.Errorf("failed key %s not backed off: retry at %s", id, d.retryAt)
		}
	}
	if _, held, _ := st.getTypeName(90000001); held {
		t.Error("a character name was stored as a type name")
	}
	if hold := p.tick(ctx, now.Add(time.Minute)); hold != 0 {
		t.Fatalf("second tick held %s", hold)
	}
	if after := f.count("/universe/names/"); after != names {
		t.Errorf("backed-off keys refetched: %d more calls", after-names)
	}
	// Past the backoff the key is tried once more.
	if hold := p.tick(ctx, now.Add(demandRetryBackoff+time.Minute)); hold != 0 {
		t.Fatalf("third tick held %s", hold)
	}
	if after := f.count("/universe/names/"); after != names+2 {
		t.Errorf("after the backoff: %d more calls, want 2", after-names)
	}
	// A day after the last ask, the keys age out unfetched.
	before := f.total.Load()
	if hold := p.tick(ctx, now.Add(demandTTL+time.Minute)); hold != 0 {
		t.Fatalf("aging tick held %s", hold)
	}
	if n, _ := st.countDemand(); n != 0 {
		t.Errorf("stale demand kept: %d rows", n)
	}
	if after := f.count("/universe/names/"); after != names+2 {
		t.Errorf("aged keys fetched: %d more calls (%d total ESI calls)", after-names-2, f.total.Load()-before)
	}
}

// TestDemandLimitedKeepsKeyDue proves ESI's stop signal ends the
// drain with its hold and does not count against the key.
func TestDemandLimitedKeepsKeyDue(t *testing.T) {
	esiSrv, f := newFakeESI(t)
	p, st := testPoller(t, esiSrv)
	now := time.Now().UTC()
	if err := st.noteDemand(swarmKindAlliance, "99000001", now); err != nil {
		t.Fatal(err)
	}
	f.limited = true
	if hold := p.tick(context.Background(), now); hold != 2*time.Minute {
		t.Errorf("limited drain hold %s, want 2m", hold)
	}
	if n := f.total.Load(); n != 1 {
		t.Errorf("limited pass spent %d calls, want 1", n)
	}
	d, ok, _ := st.getDemand(swarmKindAlliance, "99000001")
	if !ok || d.retryAt.After(now) {
		t.Errorf("limited key backed off or dropped: queued %v, retry at %s", ok, d.retryAt)
	}
	f.limited = false
	if hold := p.tick(context.Background(), now); hold != 0 {
		t.Fatalf("tick held %s", hold)
	}
	if _, ok, _ := st.getDemand(swarmKindAlliance, "99000001"); ok {
		t.Error("alliance demand not drained once ESI recovered")
	}
	if _, _, _, held, _ := st.getOrgRecord(swarmKindAlliance, 99000001); !held {
		t.Error("drained alliance record not stored")
	}
}
