package main

// ---------------------------------------------------------------------------
// Poll tests: the loop against a fake ESI — warming, cache
// respect across ticks and restarts, the 420 stop signal, the
// error-budget hold, and single-flighted on-demand records.
// ---------------------------------------------------------------------------

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeESI is a scripted ESI: fixed books, history, names and org
// records across all five hub regions, with request counts per
// path so tests prove what was (not) fetched.
type fakeESI struct {
	t       *testing.T
	mu      sync.Mutex
	calls   map[string]int64
	total   atomic.Int64
	ua      string
	limited bool
}

func newFakeESI(t *testing.T) (*httptest.Server, *fakeESI) {
	f := &fakeESI{t: t, calls: map[string]int64{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/", f.handle)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, f
}

func (f *fakeESI) count(path string) int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[path]
}

func (f *fakeESI) handle(w http.ResponseWriter, r *http.Request) {
	f.total.Add(1)
	f.mu.Lock()
	f.calls[r.URL.Path]++
	f.mu.Unlock()
	f.ua = r.Header.Get("User-Agent")
	if r.URL.Query().Get("datasource") != "tranquility" {
		http.Error(w, "datasource required", http.StatusBadRequest)
		return
	}
	future := time.Now().UTC().Add(2 * time.Hour).Format(http.TimeFormat)
	if f.limited {
		w.Header().Set("Retry-After", "120")
		http.Error(w, "calm down", 420)
		return
	}
	switch {
	case strings.HasSuffix(r.URL.Path, "/orders/"):
		// /markets/{region}/orders/
		region := strings.Split(strings.Trim(r.URL.Path, "/"), "/")[1]
		typeID := map[string]int64{
			"10000002": 34, "10000043": 35, "10000032": 36, "10000030": 37, "10000042": 38,
		}[region]
		if typeID == 0 {
			http.NotFound(w, r)
			return
		}
		page := r.URL.Query().Get("page")
		orders := []esiMarketOrder{{
			OrderID: 1000 + typeID, TypeID: typeID, LocationID: 60003760,
			Price: 5.5, VolumeTotal: 100, VolumeRemain: 40,
			Range: "station", Issued: "2026-10-10T00:00:00Z", Duration: 90,
		}}
		if region == "10000002" && page != "2" {
			w.Header().Set("X-Pages", "2")
		}
		if region == "10000002" && page == "2" {
			orders[0].OrderID = 2000
		}
		w.Header().Set("Expires", future)
		_ = json.NewEncoder(w).Encode(orders)
	case strings.HasSuffix(r.URL.Path, "/history/"):
		if r.URL.Query().Get("type_id") == "999999" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Expires", future)
		_ = json.NewEncoder(w).Encode([]esiHistoryDay{
			{Date: "2026-10-09", Average: 5.5, Highest: 6.0, Lowest: 5.0, Volume: 100, OrderCount: 10},
			{Date: "2026-10-10", Average: 5.7, Highest: 6.2, Lowest: 5.1, Volume: 120, OrderCount: 12},
		})
	case r.URL.Path == "/universe/names/" && r.Method == http.MethodPost:
		var req struct {
			IDs []int64 `json:"ids"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		var out []esiName
		for _, id := range req.IDs {
			switch id {
			case 999999:
				// ESI refuses a batch naming any ID it cannot resolve.
				http.NotFound(w, r)
				return
			case 90000001:
				out = append(out, esiName{ID: id, Name: "Some Pilot", Category: "character"})
			default:
				out = append(out, esiName{ID: id, Name: fmt.Sprintf("Type %d", id), Category: "inventory_type"})
			}
		}
		w.Header().Set("Expires", future)
		_ = json.NewEncoder(w).Encode(out)
	case strings.HasPrefix(r.URL.Path, "/corporations/"):
		if strings.Trim(r.URL.Path, "/") == "corporations/999" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Expires", future)
		_, _ = w.Write([]byte(`{"name":"Fake Corp","ticker":"FAKE"}`))
	case strings.HasPrefix(r.URL.Path, "/alliances/"):
		w.Header().Set("Expires", future)
		_, _ = w.Write([]byte(`{"name":"Fake Alliance","ticker":"FAL"}`))
	default:
		http.NotFound(w, r)
	}
}

// testPoller builds a poller against the fake ESI and a temp DB.
func testPoller(t *testing.T, srv *httptest.Server) (*poller, *store) {
	t.Helper()
	st, err := openStore(t.TempDir() + "/warm.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.close() })
	id, err := mintSwarmIdentity()
	if err != nil {
		t.Fatal(err)
	}
	cfg := config{secret: testSecret, pollInterval: time.Minute}
	return newPoller(cfg, newESIClientWithBase(srv.URL, "test@example.com"), st, id), st
}

// TestPollTickWarmsAllHubs runs one pass and proves every hub
// region's book, history and names landed in SQLite.
func TestPollTickWarmsAllHubs(t *testing.T) {
	srv, f := newFakeESI(t)
	p, st := testPoller(t, srv)
	if hold := p.tick(context.Background(), time.Now().UTC()); hold != 0 {
		t.Fatalf("tick held %s", hold)
	}
	for region, typ := range map[int64]int64{10000002: 34, 10000043: 35, 10000032: 36, 10000030: 37, 10000042: 38} {
		types, err := st.orderTypes(region)
		if err != nil {
			t.Fatal(err)
		}
		if len(types) == 0 || types[0] != typ {
			t.Errorf("region %d: types %v, want [%d]", region, types, typ)
		}
		last, err := st.historyFetchedAt(region, typ)
		if err != nil || last.IsZero() {
			t.Errorf("region %d type %d: no history fetch recorded", region, typ)
		}
		rows, err := st.listHistory(region, typ, maxSwarmHistoryDays)
		if err != nil || len(rows) != 2 {
			t.Errorf("region %d type %d: %d history rows", region, typ, len(rows))
		}
		name, held, err := st.getTypeName(typ)
		if err != nil || !held || name != fmt.Sprintf("Type %d", typ) {
			t.Errorf("type %d: name %q held=%v", typ, name, held)
		}
	}
	if !strings.HasPrefix(f.ua, "EveSynapse-Warmer/") || !strings.Contains(f.ua, "test@example.com") {
		t.Errorf("User-Agent %q carries no product or contact", f.ua)
	}
}

// TestPollTickRespectsCache runs two passes: the second spends
// zero ESI calls, because every Expires still holds.
func TestPollTickRespectsCache(t *testing.T) {
	srv, f := newFakeESI(t)
	p, _ := testPoller(t, srv)
	ctx := context.Background()
	if hold := p.tick(ctx, time.Now().UTC()); hold != 0 {
		t.Fatalf("first tick held %s", hold)
	}
	before := f.total.Load()
	if before == 0 {
		t.Fatal("first tick fetched nothing")
	}
	if hold := p.tick(ctx, time.Now().UTC()); hold != 0 {
		t.Fatalf("second tick held %s", hold)
	}
	if after := f.total.Load(); after != before {
		t.Errorf("second tick spent %d ESI calls against fresh caches", after-before)
	}
}

// TestRestartResumesWarm reopens the database file and proves
// the new process fetches nothing while the ledger holds.
func TestRestartResumesWarm(t *testing.T) {
	srv, f := newFakeESI(t)
	dir := t.TempDir()
	st, err := openStore(dir + "/warm.db")
	if err != nil {
		t.Fatal(err)
	}
	id, err := mintSwarmIdentity()
	if err != nil {
		t.Fatal(err)
	}
	cfg := config{secret: testSecret, pollInterval: time.Minute}
	p := newPoller(cfg, newESIClientWithBase(srv.URL, "test@example.com"), st, id)
	if hold := p.tick(context.Background(), time.Now().UTC()); hold != 0 {
		t.Fatalf("tick held %s", hold)
	}
	calls := f.total.Load()
	st.close()
	// A restart: a new handle on the same file.
	st2, err := openStore(dir + "/warm.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st2.close()
	p2 := newPoller(cfg, newESIClientWithBase(srv.URL, "test@example.com"), st2, id)
	if hold := p2.tick(context.Background(), time.Now().UTC()); hold != 0 {
		t.Fatalf("restart tick held %s", hold)
	}
	if after := f.total.Load(); after != calls {
		t.Errorf("restart refetched %d calls against a warm store", after-calls)
	}
	// And the warmed data still serves.
	payload, _, ok := p2.serveKey(context.Background(), swarmKindHistory, "10000002/34", time.Now().UTC())
	if !ok || !strings.Contains(payload, "2026-10-10") {
		t.Errorf("restarted node serves %v: %q", ok, payload)
	}
}

// TestLimitedStopsPass proves a 420 ends the pass with the
// Retry-After hold, spending no further calls.
func TestLimitedStopsPass(t *testing.T) {
	srv, f := newFakeESI(t)
	f.limited = true
	p, _ := testPoller(t, srv)
	hold := p.tick(context.Background(), time.Now().UTC())
	if hold != 2*time.Minute {
		t.Errorf("420 hold %s, want 2m", hold)
	}
	if n := f.total.Load(); n != 1 {
		t.Errorf("limited pass spent %d calls, want 1", n)
	}
}

// TestParseHelpers pins the header parsing the etiquette runs on.
func TestParseHelpers(t *testing.T) {
	if d, ok := parseRetryAfter("120"); !ok || d != 2*time.Minute {
		t.Errorf("Retry-After seconds: %s %v", d, ok)
	}
	future := time.Now().UTC().Add(time.Hour).Format(http.TimeFormat)
	if d, ok := parseRetryAfter(future); !ok || d <= 0 {
		t.Errorf("Retry-After date: %s %v", d, ok)
	}
	if _, ok := parseRetryAfter("junk"); ok {
		t.Error("junk Retry-After parses")
	}
	h := http.Header{"Expires": []string{future}}
	exp := parseExpires(h, time.Now().UTC())
	if time.Until(exp) < 50*time.Minute {
		t.Errorf("Expires parsed as %s", exp)
	}
	before := time.Now().UTC()
	if exp := parseExpires(http.Header{}, before); exp.Sub(before) != esiFallbackCache {
		t.Errorf("missing Expires fallback %s", exp.Sub(before))
	}
}

// TestServeOrgOnDemandSingleflight hammers one unheld record
// from eight goroutines: one ESI call, eight served payloads.
func TestServeOrgOnDemandSingleflight(t *testing.T) {
	srv, f := newFakeESI(t)
	p, _ := testPoller(t, srv)
	ctx := context.Background()
	var wg sync.WaitGroup
	results := make([]string, 8)
	okAll := make([]bool, 8)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			payload, _, ok := p.serveKey(ctx, swarmKindCorporation, "98000001", time.Now().UTC())
			results[i], okAll[i] = payload, ok
		}(i)
	}
	wg.Wait()
	for i, ok := range okAll {
		if !ok || !strings.Contains(results[i], "Fake Corp") {
			t.Errorf("pull %d: ok=%v payload=%q", i, ok, results[i])
		}
	}
	if n := f.count("/corporations/98000001/"); n != 1 {
		t.Errorf("eight concurrent pulls spent %d ESI calls", n)
	}
	// A repeat pull serves from SQLite: no new call.
	if _, _, ok := p.serveKey(ctx, swarmKindCorporation, "98000001", time.Now().UTC()); !ok {
		t.Error("repeat pull misses")
	}
	if n := f.count("/corporations/98000001/"); n != 1 {
		t.Errorf("repeat pull refetched: %d calls", n)
	}
}

// TestOrgNegative suppresses refetch of a missing record: one
// 404, then silence for the TTL.
func TestOrgNegative(t *testing.T) {
	srv, f := newFakeESI(t)
	p, _ := testPoller(t, srv)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, _, ok := p.serveKey(ctx, swarmKindCorporation, "999", time.Now().UTC()); ok {
			t.Fatal("missing record served")
		}
	}
	if n := f.count("/corporations/999/"); n != 1 {
		t.Errorf("missing record cost %d ESI calls", n)
	}
}

// TestServeKindMatrix pins what the node serves without ESI and
// what it never serves: structures need a token this node
// holds none of.
func TestServeKindMatrix(t *testing.T) {
	srv, _ := newFakeESI(t)
	p, _ := testPoller(t, srv)
	ctx := context.Background()
	now := time.Now().UTC()
	if _, _, ok := p.serveKey(ctx, swarmKindStructure, "1000000000001", now); ok {
		t.Error("structure name served without a token source")
	}
	if _, _, ok := p.serveKey(ctx, "market_orders", "10000002/34", now); ok {
		t.Error("unlisted kind served")
	}
	if _, _, ok := p.serveKey(ctx, swarmKindHistory, "bogus", now); ok {
		t.Error("malformed key served")
	}
}

// TestWarmerContactsOnlyESIAndSeed proves the node is a source,
// never a puller: one full tick plus serving held keys contacts
// exactly two endpoints — ESI for polling, and the seed's
// register route for the heartbeat. No peer is ever dialed,
// because no peer address ever enters the node.
func TestWarmerContactsOnlyESIAndSeed(t *testing.T) {
	esiSrv, f := newFakeESI(t)
	var seedMu sync.Mutex
	var seedHits []string
	seedSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seedMu.Lock()
		seedHits = append(seedHits, r.Method+" "+r.URL.Path)
		seedMu.Unlock()
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(seedSrv.Close)
	st, err := openStore(t.TempDir() + "/warm.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.close() })
	id, err := mintSwarmIdentity()
	if err != nil {
		t.Fatal(err)
	}
	cfg := config{
		secret: testSecret, pollInterval: time.Minute,
		seedURL: seedSrv.URL, publicBaseURL: "https://warmer.example.com",
	}
	p := newPoller(cfg, newESIClientWithBase(esiSrv.URL, "test@example.com"), st, id)
	if hold := p.tick(context.Background(), time.Now().UTC()); hold != 0 {
		t.Fatalf("tick held %s", hold)
	}
	if n := f.total.Load(); n == 0 {
		t.Fatal("tick polled nothing")
	}
	// Serving held keys spends no call anywhere.
	before := f.total.Load()
	ctx := context.Background()
	now := time.Now().UTC()
	if _, _, ok := p.serveKey(ctx, swarmKindHistory, "10000002/34", now); !ok {
		t.Error("warmed history does not serve")
	}
	if _, _, ok := p.serveKey(ctx, swarmKindTypeName, "34", now); !ok {
		t.Error("warmed type name does not serve")
	}
	if after := f.total.Load(); after != before {
		t.Errorf("serving held keys spent %d outbound calls", after-before)
	}
	seedMu.Lock()
	hits := append([]string(nil), seedHits...)
	seedMu.Unlock()
	if len(hits) != 1 || hits[0] != "POST /swarm/seed/register" {
		t.Errorf("seed contacts %v, want exactly one heartbeat", hits)
	}
}
