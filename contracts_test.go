package main

// ---------------------------------------------------------------------------
// Contracts tests: the public_contract swarm kind end to end —
// the golden payload shape the main instance strictly decodes,
// the store round-trip (a header refresh never un-stores its
// items), serve gating (stored and live only), and the sweep
// against a fake ESI: listings become pending headers, the
// bounded items drain settles stored / private / gone, and
// demand waits for unknown IDs while fetching known pending
// ones.
// ---------------------------------------------------------------------------

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func int64Ptr(v int64) *int64 { return &v }

// TestContractPayloadGolden pins the contract payload's field
// names and order byte-for-byte. The main instance strictly
// decodes this shape; drift must fail here, not in production.
func TestContractPayloadGolden(t *testing.T) {
	payload := swarmContractPayload{
		ContractID: 123, RegionID: 10000002, Type: "item_exchange",
		IssuerID: 111, IssuerCorporationID: 222, ForCorporation: false,
		Title: "Test", Price: 1000, Buyout: 0, Reward: 0, Collateral: 0, Volume: 12.5,
		StartLocationID: 60003760, EndLocationID: 0,
		DateIssued: 1760000000, DateExpired: 1760600000, DaysToComplete: 0,
		Items: []swarmContractItem{
			{RecordID: 1, TypeID: 34, ItemID: nil, Quantity: 10, IsIncluded: true, IsBlueprintCopy: false, Runs: nil, MaterialEfficiency: nil, TimeEfficiency: nil},
			{RecordID: 2, TypeID: 35, ItemID: int64Ptr(999), Quantity: 1, IsIncluded: false, IsBlueprintCopy: true, Runs: int64Ptr(3), MaterialEfficiency: int64Ptr(10), TimeEfficiency: int64Ptr(20)},
		},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"contract_id":123,"region_id":10000002,"type":"item_exchange","issuer_id":111,"issuer_corporation_id":222,"for_corporation":false,"title":"Test","price":1000,"buyout":0,"reward":0,"collateral":0,"volume":12.5,"start_location_id":60003760,"end_location_id":0,"date_issued":1760000000,"date_expired":1760600000,"days_to_complete":0,"items":[{"record_id":1,"type_id":34,"item_id":null,"quantity":10,"is_included":true,"is_blueprint_copy":false,"runs":null,"material_efficiency":null,"time_efficiency":null},{"record_id":2,"type_id":35,"item_id":999,"quantity":1,"is_included":false,"is_blueprint_copy":true,"runs":3,"material_efficiency":10,"time_efficiency":20}]}`
	if string(raw) != want {
		t.Errorf("contract payload:\n got %s\nwant %s", raw, want)
	}
	if !validSwarmKind(swarmKindPublicContract) {
		t.Error("public_contract is not a valid swarm kind")
	}
}

func testContractHeader(contractID int64, issued, expired time.Time) contractRow {
	return contractRow{
		contractID: contractID, regionID: 10000002, contractType: "item_exchange",
		issuerID: 90000001, issuerCorporationID: 98000001, forCorporation: false,
		title: "Bundle", price: 123.5, buyout: 0, reward: 0, collateral: 0, volume: 42,
		startLocationID: 60003760, endLocationID: 0,
		dateIssued: issued.Unix(), dateExpired: expired.Unix(), daysToComplete: 0,
	}
}

// TestContractStoreRoundTrip proves a header upsert refreshes
// facts without ever touching the settled items state, items
// store and read back with their NULLs as nil pointers, and
// expiry pruning drops headers together with their items.
func TestContractStoreRoundTrip(t *testing.T) {
	st, err := openStore(t.TempDir() + "/warm.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.close() })
	now := time.Now().UTC()
	issued := now.Add(-time.Hour)
	expired := now.Add(7 * 24 * time.Hour)
	header := testContractHeader(1001, issued, expired)
	if err := st.upsertContractHeader(header, now); err != nil {
		t.Fatal(err)
	}
	got, ok, err := st.getContract(1001)
	if err != nil || !ok {
		t.Fatalf("getContract: ok=%v err=%v", ok, err)
	}
	if got.itemsState != contractItemsPending || got.price != 123.5 || got.regionID != 10000002 || got.dateIssued != issued.Unix() {
		t.Errorf("stored header %+v", got)
	}
	if got.items == nil || len(got.items) != 0 {
		t.Errorf("fresh header items %v, want empty non-nil", got.items)
	}
	pending, err := st.listContractsPendingItems(10)
	if err != nil || len(pending) != 1 || pending[0].contractID != 1001 {
		t.Errorf("pending list %v (%v), want [1001]", pending, err)
	}
	items := []swarmContractItem{
		{RecordID: 5001, TypeID: 34, ItemID: int64Ptr(123456), Quantity: 100, IsIncluded: true},
		{RecordID: 5002, TypeID: 35, ItemID: nil, Quantity: 5, IsIncluded: true, IsBlueprintCopy: true, Runs: int64Ptr(10), MaterialEfficiency: int64Ptr(5), TimeEfficiency: int64Ptr(8)},
	}
	fetchedAt := now.Add(time.Minute)
	if err := st.putContractItems(1001, items, fetchedAt); err != nil {
		t.Fatal(err)
	}
	got, ok, err = st.getContract(1001)
	if err != nil || !ok {
		t.Fatalf("getContract after items: ok=%v err=%v", ok, err)
	}
	if got.itemsState != contractItemsStored || got.itemsFetchedAt.Unix() != fetchedAt.Unix() {
		t.Errorf("after items: state %q fetched_at %s", got.itemsState, got.itemsFetchedAt)
	}
	if len(got.items) != 2 {
		t.Fatalf("items %d, want 2", len(got.items))
	}
	if got.items[0].ItemID == nil || *got.items[0].ItemID != 123456 || got.items[0].Runs != nil {
		t.Errorf("item 0 %+v", got.items[0])
	}
	if got.items[1].ItemID != nil || got.items[1].Runs == nil || *got.items[1].Runs != 10 || got.items[1].MaterialEfficiency == nil || *got.items[1].MaterialEfficiency != 5 {
		t.Errorf("item 1 %+v", got.items[1])
	}
	// A listing refresh changes facts and seen_at only.
	refresh := header
	refresh.price = 999
	refresh.title = "Bundle v2"
	if err := st.upsertContractHeader(refresh, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	got, _, _ = st.getContract(1001)
	if got.price != 999 || got.title != "Bundle v2" {
		t.Errorf("refresh did not land: %+v", got)
	}
	if got.itemsState != contractItemsStored || got.itemsFetchedAt.Unix() != fetchedAt.Unix() || len(got.items) != 2 {
		t.Errorf("refresh disturbed the items: state %q fetched_at %s items %d", got.itemsState, got.itemsFetchedAt, len(got.items))
	}
	if pending, _ := st.listContractsPendingItems(10); len(pending) != 0 {
		t.Errorf("stored contract listed pending: %v", pending)
	}
	// Pruning an expired contract drops its items with it,
	// and leaves a live contract alone.
	dead := testContractHeader(1002, now.Add(-48*time.Hour), now.Add(-time.Hour))
	if err := st.upsertContractHeader(dead, now); err != nil {
		t.Fatal(err)
	}
	if err := st.putContractItems(1002, []swarmContractItem{{RecordID: 6001, TypeID: 34, Quantity: 1, IsIncluded: true}}, now); err != nil {
		t.Fatal(err)
	}
	if err := st.pruneExpiredContracts(now); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := st.getContract(1002); ok {
		t.Error("expired contract survived pruning")
	}
	var itemCount int
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM contract_items WHERE contract_id = 1002`).Scan(&itemCount); err != nil || itemCount != 0 {
		t.Errorf("expired contract items %d (%v), want 0", itemCount, err)
	}
	if _, ok, _ := st.getContract(1001); !ok {
		t.Error("live contract pruned")
	}
}

// TestServeContractGating proves serveKey serves a stored,
// live contract whole (with the items fetch time as the
// entry's fetch time) and misses pending, private, gone and
// expired contracts alike.
func TestServeContractGating(t *testing.T) {
	esiSrv, _ := newFakeESI(t)
	p, st := testPoller(t, esiSrv)
	now := time.Now().UTC()
	issued := now.Add(-time.Hour)
	live := now.Add(7 * 24 * time.Hour)
	mk := func(id int64, expires time.Time) contractRow {
		h := testContractHeader(id, issued, expires)
		if err := st.upsertContractHeader(h, now); err != nil {
			t.Fatal(err)
		}
		return h
	}
	mk(2001, live)
	if err := st.putContractItems(2001, []swarmContractItem{{RecordID: 7001, TypeID: 34, Quantity: 3, IsIncluded: true}}, now); err != nil {
		t.Fatal(err)
	}
	mk(2002, live) // stays pending
	mk(2003, live)
	if err := st.setContractItemsState(2003, contractItemsPrivate); err != nil {
		t.Fatal(err)
	}
	mk(2004, live)
	if err := st.setContractItemsState(2004, contractItemsGone); err != nil {
		t.Fatal(err)
	}
	mk(2005, now.Add(-time.Minute)) // stored but expired
	if err := st.putContractItems(2005, []swarmContractItem{{RecordID: 7005, TypeID: 34, Quantity: 1, IsIncluded: true}}, now); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	payload, fetchedAt, ok := p.serveKey(ctx, swarmKindPublicContract, "2001", now)
	if !ok {
		t.Fatal("stored live contract does not serve")
	}
	if fetchedAt.Unix() != now.Unix() {
		t.Errorf("served fetchedAt %s, want the items fetch time %s", fetchedAt, now)
	}
	var decoded swarmContractPayload
	if err := json.Unmarshal([]byte(payload), &decoded); err != nil {
		t.Fatalf("served payload unreadable: %v", err)
	}
	if decoded.ContractID != 2001 || decoded.RegionID != 10000002 || len(decoded.Items) != 1 || decoded.Items[0].RecordID != 7001 || decoded.DateExpired != live.Unix() {
		t.Errorf("served payload %+v", decoded)
	}
	for _, id := range []string{"2002", "2003", "2004", "2005", "2999", "bogus"} {
		if _, _, ok := p.serveKey(ctx, swarmKindPublicContract, id, now); ok {
			t.Errorf("contract %s served, want a miss", id)
		}
	}
}

// fakeContractsESI is a scripted contracts ESI: one hub
// region lists three contracts (a plain exchange, a courier,
// and one that vanishes before its items fetch), every other
// region lists none, and the items endpoint answers per
// contract — 200 for 1001 and 2001, 400 for 1002 (courier
// cargo), 404 for 1003 (gone).
type fakeContractsESI struct {
	mu    sync.Mutex
	calls map[string]int
	now   time.Time
}

func newFakeContractsESI(t *testing.T) (*httptest.Server, *fakeContractsESI) {
	t.Helper()
	f := &fakeContractsESI{calls: map[string]int{}, now: time.Now().UTC()}
	srv := httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(srv.Close)
	return srv, f
}

func (f *fakeContractsESI) count(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[path]
}

func (f *fakeContractsESI) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.calls[r.URL.Path]++
	f.mu.Unlock()
	future := time.Now().UTC().Add(2 * time.Hour).Format(http.TimeFormat)
	rfc := func(d time.Duration) string { return f.now.Add(d).UTC().Format(time.RFC3339) }
	switch {
	case strings.HasPrefix(r.URL.Path, "/contracts/public/items/"):
		id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/contracts/public/items/"), "/")
		switch id {
		case "1002":
			http.Error(w, "courier cargo is private", http.StatusBadRequest)
			return
		case "1003":
			http.NotFound(w, r)
			return
		case "1001":
			w.Header().Set("Expires", future)
			_ = json.NewEncoder(w).Encode([]esiPublicContractItem{
				{RecordID: 5001, TypeID: 34, ItemID: int64Ptr(123456), Quantity: 100, IsIncluded: true},
				{RecordID: 5002, TypeID: 35, Quantity: 5, IsIncluded: true, IsBlueprintCopy: true, Runs: int64Ptr(10), MaterialEfficiency: int64Ptr(5), TimeEfficiency: int64Ptr(8)},
			})
			return
		case "2001":
			w.Header().Set("Expires", future)
			_ = json.NewEncoder(w).Encode([]esiPublicContractItem{
				{RecordID: 7001, TypeID: 34, Quantity: 3, IsIncluded: true},
			})
			return
		default:
			http.NotFound(w, r)
			return
		}
	case strings.HasPrefix(r.URL.Path, "/contracts/public/"):
		w.Header().Set("Expires", future)
		if r.URL.Path != "/contracts/public/10000002/" {
			_ = json.NewEncoder(w).Encode([]esiPublicContract{})
			return
		}
		_ = json.NewEncoder(w).Encode([]esiPublicContract{
			{ContractID: 1001, IssuerID: 90000001, IssuerCorporationID: 98000001, Type: "item_exchange", Title: "Bundle", Price: 123.5, Volume: 42, StartLocationID: 60003760, DateIssued: rfc(-time.Hour), DateExpired: rfc(7 * 24 * time.Hour)},
			{ContractID: 1002, IssuerID: 90000001, IssuerCorporationID: 98000001, Type: "courier", Title: "Haul", Reward: 1000000, Collateral: 5000000, Volume: 1000, StartLocationID: 60003760, EndLocationID: 60003761, DateIssued: rfc(-2 * time.Hour), DateExpired: rfc(7 * 24 * time.Hour), DaysToComplete: 3},
			{ContractID: 1003, IssuerID: 90000001, IssuerCorporationID: 98000001, Type: "auction", Title: "Vanishing", Buyout: 999, Price: 10, Volume: 1, StartLocationID: 60003760, DateIssued: rfc(-3 * time.Hour), DateExpired: rfc(7 * 24 * time.Hour)},
			{ContractID: 1004, IssuerID: 90000001, IssuerCorporationID: 98000001, Type: "item_exchange", Title: "Broken dates", DateIssued: "not-a-date", DateExpired: rfc(7 * 24 * time.Hour)},
		})
		return
	default:
		http.NotFound(w, r)
	}
}

// TestContractSweepAndItemsDrain runs the two sweep halves in
// order: listings land as pending headers (a row with
// unparseable dates is skipped), the listing ledger then
// holds, and the items drain settles each header — stored
// with its list, private on a 400, gone on a 404.
func TestContractSweepAndItemsDrain(t *testing.T) {
	srv, f := newFakeContractsESI(t)
	p, st := testPoller(t, srv)
	ctx := context.Background()
	now := f.now
	if hold, done := p.pollContracts(ctx, now); done {
		t.Fatalf("pollContracts held %s", hold)
	}
	for _, id := range []int64{1001, 1002, 1003} {
		c, ok, err := st.getContract(id)
		if err != nil || !ok {
			t.Fatalf("contract %d not swept: ok=%v err=%v", id, ok, err)
		}
		if c.itemsState != contractItemsPending {
			t.Errorf("contract %d state %q, want pending after the listing sweep", id, c.itemsState)
		}
	}
	if _, ok, _ := st.getContract(1004); ok {
		t.Error("contract with unparseable dates was stored")
	}
	pending, err := st.listContractsPendingItems(10)
	if err != nil || len(pending) != 3 || pending[0].contractID != 1001 || pending[2].contractID != 1003 {
		t.Errorf("pending order %v (%v), want newest first [1001 1002 1003]", pending, err)
	}
	// The ledger holds: a second sweep at the same time
	// spends no listing calls.
	before := f.count("/contracts/public/10000002/")
	if hold, done := p.pollContracts(ctx, now); done {
		t.Fatalf("second pollContracts held %s", hold)
	}
	if after := f.count("/contracts/public/10000002/"); after != before {
		t.Errorf("fresh listing refetched: %d more calls", after-before)
	}
	if hold, done := p.pollContractItems(ctx, now); done {
		t.Fatalf("pollContractItems held %s", hold)
	}
	stored, _, _ := st.getContract(1001)
	if stored.itemsState != contractItemsStored || len(stored.items) != 2 {
		t.Errorf("contract 1001 state %q items %d, want stored with 2", stored.itemsState, len(stored.items))
	}
	if stored.items[1].ItemID != nil || stored.items[1].Runs == nil || *stored.items[1].Runs != 10 {
		t.Errorf("contract 1001 item 1 %+v: absent item_id must stay nil", stored.items[1])
	}
	if c, _, _ := st.getContract(1002); c.itemsState != contractItemsPrivate {
		t.Errorf("courier contract state %q, want private on a 400", c.itemsState)
	}
	if c, _, _ := st.getContract(1003); c.itemsState != contractItemsGone {
		t.Errorf("vanished contract state %q, want gone on a 404", c.itemsState)
	}
	if _, _, ok := p.serveKey(ctx, swarmKindPublicContract, "1001", now); !ok {
		t.Error("swept and stored contract does not serve")
	}
	if _, _, ok := p.serveKey(ctx, swarmKindPublicContract, "1002", now); ok {
		t.Error("private contract serves")
	}
	// Demand coverage: the kind queues, junk keys do not.
	if !demandable(swarmKindPublicContract, "1001") {
		t.Error("public_contract demand refused for a valid ID")
	}
	if demandable(swarmKindPublicContract, "bogus") {
		t.Error("public_contract demand accepted for a junk key")
	}
}

// TestContractDemandWaitsForUnknownAndFetchesPending proves
// the demand case: an unknown contract cannot be fetched (its
// header comes from the regional sweep), so demand waits out
// the standard backoff; a known pending header fetches its
// items through the drain's own fetcher and is done.
func TestContractDemandWaitsForUnknownAndFetchesPending(t *testing.T) {
	srv, _ := newFakeContractsESI(t)
	p, st := testPoller(t, srv)
	ctx := context.Background()
	now := time.Now().UTC()
	done, retryAt, hold, stop := p.fetchDemand(ctx, swarmKindPublicContract, "999999", now)
	if done || stop || hold != 0 {
		t.Errorf("unknown contract demand: done=%v stop=%v hold=%s, want a plain wait", done, stop, hold)
	}
	if !retryAt.Equal(now.Add(demandRetryBackoff)) {
		t.Errorf("unknown contract retryAt %s, want %s", retryAt, now.Add(demandRetryBackoff))
	}
	header := testContractHeader(2001, now.Add(-time.Hour), now.Add(7*24*time.Hour))
	if err := st.upsertContractHeader(header, now); err != nil {
		t.Fatal(err)
	}
	done, _, hold, stop = p.fetchDemand(ctx, swarmKindPublicContract, "2001", now)
	if !done || stop || hold != 0 {
		t.Errorf("pending contract demand: done=%v stop=%v hold=%s, want done", done, stop, hold)
	}
	c, ok, _ := st.getContract(2001)
	if !ok || c.itemsState != contractItemsStored || len(c.items) != 1 {
		t.Errorf("demanded contract state %q items %d, want stored with 1", c.itemsState, len(c.items))
	}
	// Already held fresh: done again, with no further fetch.
	done, _, _, _ = p.fetchDemand(ctx, swarmKindPublicContract, "2001", now)
	if !done {
		t.Error("held-fresh contract demand not done")
	}
}
