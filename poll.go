package main

// ---------------------------------------------------------------------------
// The poll loop: what the node fetches from ESI, and what it serves
// to the swarm. Five hub regions, in a loop, cache-driven:
//
//   - order books per region, refreshed when their Expires lapses
//     (the book itself is not a swarm kind yet — it feeds the
//     type universe below, and is persisted for the day an
//     orders kind exists);
//   - market history for every (region, type) pair with orders,
//     refreshed past the 20-hour gate, a bounded backlog per tick
//     so a cold start ramps over hours, not minutes;
//   - type names for every seen type, once (they are immutable);
//   - corporation/alliance records on demand: no public endpoint
//     enumerates the ones the swarm wants, so the first pull for
//     an unheld record fetches it (single-flighted), then it is
//     served from SQLite until its Expires lapses;
//   - public contracts per hub region: listing headers swept
//     when their Expires lapses, then each contract's item list
//     fetched once (bounded per tick), because the listing
//     alone appraises nothing;
//   - swarm demand first of all: covered keys peers pulled and
//     this node missed (warm.go), so the next pull serves them.
//
// Structure names are never fetched: that endpoint needs a
// token, and this node holds none by design.
//
// The loop serves only what it holds fresh — the same rule the
// main instance serves by — so the swarm never launders stale
// rows into fresh ones.
// ---------------------------------------------------------------------------

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// hubRegions is the fixed set of warmed trade regions. IDs and
// names verified against GET /universe/regions/{id}/, matching
// the main instance's market page.
var hubRegions = []struct {
	id   int64
	name string
}{
	{10000002, "The Forge"},
	{10000043, "Domain"},
	{10000032, "Sinq Laison"},
	{10000030, "Heimatar"},
	{10000042, "Metropolis"},
}

// historyRefetchGate mirrors the main instance: the minimum age
// of a successful history fetch before the pair is fetched
// again.
const historyRefetchGate = 20 * time.Hour

// Per-tick bounds: a cold start drains the backlog gradually,
// and one tick never spends an unbounded burst of ESI calls.
const (
	maxHistoryPerTick = 100
	maxNamesPerTick   = 5000
	namesBatchSize    = 1000
	// maxContractItemsPerTick bounds the contract-items drain
	// per tick: each pending contract costs one ESI call, and
	// a fresh region sweep can queue thousands of headers at
	// once — the drain ramps like the history backlog does,
	// newest contracts first.
	maxContractItemsPerTick = 50
)

// orgNegativeTTL is how long a missing (404) corporation or
// alliance record suppresses refetch: a deleted record must not
// cost an ESI call on every pull.
const orgNegativeTTL = time.Hour

// heartbeatInterval is how often the node re-announces to the
// seed: well inside the seed's 48-hour directory TTL.
const heartbeatInterval = 12 * time.Hour

// esiMarketOrder is one row of GET /markets/{region}/orders/.
type esiMarketOrder struct {
	OrderID      int64   `json:"order_id"`
	TypeID       int64   `json:"type_id"`
	LocationID   int64   `json:"location_id"`
	SystemID     int64   `json:"system_id"`
	IsBuyOrder   bool    `json:"is_buy_order"`
	Price        float64 `json:"price"`
	VolumeTotal  int64   `json:"volume_total"`
	VolumeRemain int64   `json:"volume_remain"`
	Range        string  `json:"range"`
	Issued       string  `json:"issued"`
	Duration     int     `json:"duration"`
}

// esiHistoryDay is one row of GET /markets/{region}/history/.
type esiHistoryDay struct {
	Date       string  `json:"date"`
	Average    float64 `json:"average"`
	Highest    float64 `json:"highest"`
	Lowest     float64 `json:"lowest"`
	Volume     int64   `json:"volume"`
	OrderCount int64   `json:"order_count"`
}

// esiName is one answer of POST /universe/names/. The endpoint
// resolves any EVE ID, so only an inventory_type answer is a
// type name.
type esiName struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	Category string `json:"category"`
}

// esiPublicContract is one row of
// GET /contracts/public/{region}/, mirrored field-for-field
// from the main instance's ESI shape. Dates arrive as RFC3339
// strings and are parsed to unix seconds at sweep time; the
// region is not in the row — it is the endpoint's argument.
type esiPublicContract struct {
	ContractID          int64   `json:"contract_id"`
	IssuerID            int64   `json:"issuer_id"`
	IssuerCorporationID int64   `json:"issuer_corporation_id"`
	Type                string  `json:"type"`
	Title               string  `json:"title"`
	ForCorporation      bool    `json:"for_corporation"`
	Price               float64 `json:"price"`
	Reward              float64 `json:"reward"`
	Buyout              float64 `json:"buyout"`
	Collateral          float64 `json:"collateral"`
	Volume              float64 `json:"volume"`
	StartLocationID     int64   `json:"start_location_id"`
	EndLocationID       int64   `json:"end_location_id"`
	DateIssued          string  `json:"date_issued"`
	DateExpired         string  `json:"date_expired"`
	DaysToComplete      int64   `json:"days_to_complete"`
}

// esiPublicContractItem is one row of
// GET /contracts/public/items/{contract}/. ItemID is a
// pointer because the field is absent for a stack with no
// singleton item (a decoded 0 means the same); the blueprint
// fields exist only on copies.
type esiPublicContractItem struct {
	RecordID           int64  `json:"record_id"`
	TypeID             int64  `json:"type_id"`
	ItemID             *int64 `json:"item_id"`
	Quantity           int64  `json:"quantity"`
	IsIncluded         bool   `json:"is_included"`
	IsBlueprintCopy    bool   `json:"is_blueprint_copy"`
	Runs               *int64 `json:"runs"`
	MaterialEfficiency *int64 `json:"material_efficiency"`
	TimeEfficiency     *int64 `json:"time_efficiency"`
}

// poller fetches ESI into the store and serves swarm keys.
type poller struct {
	cfg   config
	esi   *esiClient
	store *store
	id    *swarmIdentity

	flightsMu sync.Mutex
	flights   map[string]*flight
}

// flight is one in-progress on-demand fetch; concurrent pulls
// for the same record join it instead of doubling the ESI call.
type flight struct {
	done      chan struct{}
	payload   string
	fetchedAt time.Time
	expiresAt time.Time
	ok        bool
	hold      time.Duration
}

// newPoller builds the poll loop.
func newPoller(cfg config, esi *esiClient, store *store, id *swarmIdentity) *poller {
	return &poller{cfg: cfg, esi: esi, store: store, id: id, flights: map[string]*flight{}}
}

// tick runs one poll pass. It returns how long the loop must
// hold before the next pass: nonzero when ESI signaled a limit
// (or the shared budget runs low) — the pass ended early, and
// hammering on would only burn budget.
func (p *poller) tick(ctx context.Context, now time.Time) time.Duration {
	if hold := p.esi.budgetHold(now); hold > 0 {
		return hold
	}
	// Expired contracts prune once per tick, up front, so the
	// prune runs even when a later pass ends the tick early on
	// ESI's stop signal.
	_ = p.store.pruneExpiredContracts(now)
	p.heartbeatDue(ctx, now)
	if hold, done := p.pollDemand(ctx, now); done {
		return hold
	}
	for _, region := range hubRegions {
		if hold, done := p.pollOrders(ctx, region.id, now); done {
			return hold
		}
	}
	if hold, done := p.pollHistory(ctx, now); done {
		return hold
	}
	if hold, done := p.pollContracts(ctx, now); done {
		return hold
	}
	if hold, done := p.pollContractItems(ctx, now); done {
		return hold
	}
	if hold, done := p.pollNames(ctx); done {
		return hold
	}
	return 0
}

// limited converts an ESI error into a loop hold: a stop signal
// holds until ESI says, anything else ends the pass with no
// hold (the dataset failed, not the loop).
func limited(err error) (time.Duration, bool) {
	var lim *errLimited
	if errors.As(err, &lim) {
		return lim.retryAfter, true
	}
	return 0, false
}

// pollOrders sweeps one region's order book when its Expires
// lapsed. True when the pass ended (with a hold when ESI
// signaled one).
func (p *poller) pollOrders(ctx context.Context, regionID int64, now time.Time) (time.Duration, bool) {
	key := fmt.Sprintf("orders/%d", regionID)
	fresh, err := p.store.cacheFresh(key, now)
	if err != nil {
		return 0, false
	}
	if fresh {
		return 0, false
	}
	bodies, expires, err := p.esi.getPages(ctx, fmt.Sprintf("/markets/%d/orders/", regionID))
	if err != nil {
		if hold, stop := limited(err); stop {
			return hold, true
		}
		return 0, false
	}
	var rows []orderRow
	for _, body := range bodies {
		var orders []esiMarketOrder
		if err := json.Unmarshal(body, &orders); err != nil {
			return 0, false
		}
		for _, o := range orders {
			if o.OrderID <= 0 || o.TypeID <= 0 {
				continue
			}
			rows = append(rows, orderRow{
				regionID: regionID, orderID: o.OrderID, typeID: o.TypeID,
				locationID: o.LocationID, systemID: o.SystemID, isBuy: o.IsBuyOrder,
				price: o.Price, volumeTotal: o.VolumeTotal, volumeRemain: o.VolumeRemain,
				ordRange: o.Range, issued: o.Issued, duration: int64(o.Duration), fetchedAt: now,
			})
		}
	}
	if err := p.store.replaceRegionOrders(regionID, rows); err != nil {
		return 0, false
	}
	// The sweep is due again when its Expires lapses; the
	// ledger records it so a restart resumes warm.
	if err := p.store.noteCache(key, expires); err != nil {
		return 0, false
	}
	return 0, false
}

// pollHistory refreshes due history pairs, bounded per tick.
// True when the pass ended early.
func (p *poller) pollHistory(ctx context.Context, now time.Time) (time.Duration, bool) {
	type pair struct{ region, typ int64 }
	var due []pair
	for _, region := range hubRegions {
		types, err := p.store.orderTypes(region.id)
		if err != nil {
			return 0, false
		}
		for _, typ := range types {
			last, err := p.store.historyFetchedAt(region.id, typ)
			if err != nil {
				return 0, false
			}
			if !last.IsZero() && now.Sub(last) < historyRefetchGate {
				continue
			}
			if fresh, err := p.store.cacheFresh(fmt.Sprintf("history/%d/%d", region.id, typ), now); err != nil {
				return 0, false
			} else if fresh {
				continue
			}
			if fresh, err := p.store.cacheFresh(fmt.Sprintf("neg:history/%d/%d", region.id, typ), now); err != nil {
				return 0, false
			} else if fresh {
				continue
			}
			due = append(due, pair{region.id, typ})
			if len(due) >= maxHistoryPerTick {
				break
			}
		}
		if len(due) >= maxHistoryPerTick {
			break
		}
	}
	for _, pr := range due {
		if hold, stop := p.fetchHistory(ctx, pr.region, pr.typ, now); stop {
			return hold, true
		}
	}
	return 0, false
}

// fetchHistory fetches one pair's history. True when the pass
// ended early (with a hold when ESI signaled one).
func (p *poller) fetchHistory(ctx context.Context, regionID, typeID int64, now time.Time) (time.Duration, bool) {
	key := fmt.Sprintf("history/%d/%d", regionID, typeID)
	body, expires, err := p.esi.get(ctx, fmt.Sprintf("/markets/%d/history/?type_id=%d", regionID, typeID))
	if err != nil {
		if hold, stop := limited(err); stop {
			return hold, true
		}
		if isNotFound(err) {
			// No history for this pair (a type with
			// orders but no daily aggregates yet):
			// back off a day rather than refetching
			// nothing every tick.
			_ = p.store.noteCache("neg:"+key, now.Add(24*time.Hour))
		}
		return 0, false
	}
	var days []esiHistoryDay
	if err := json.Unmarshal(body, &days); err != nil {
		return 0, false
	}
	var rows []historyDay
	for _, d := range days {
		if d.Date == "" || d.Average < 0 || d.Highest < 0 || d.Lowest < 0 || d.Volume < 0 || d.OrderCount < 0 {
			continue
		}
		rows = append(rows, historyDay{date: d.Date, average: d.Average, highest: d.Highest, lowest: d.Lowest, volume: d.Volume, orderCount: d.OrderCount})
	}
	if len(rows) == 0 {
		_ = p.store.noteCache("neg:"+key, now.Add(24*time.Hour))
		return 0, false
	}
	if err := p.store.replaceHistory(regionID, typeID, rows, now); err != nil {
		return 0, false
	}
	_ = p.store.noteCache(key, expires)
	return 0, false
}

// pollContracts sweeps public contract listings for every hub
// region whose Expires ledger has lapsed, storing headers only:
// the item lists drain separately (pollContractItems), bounded
// per tick, so a region's first sweep does not turn into tens
// of thousands of items calls in one pass. True when the pass
// ended early on ESI's stop signal.
func (p *poller) pollContracts(ctx context.Context, now time.Time) (time.Duration, bool) {
	for _, region := range hubRegions {
		key := fmt.Sprintf("contracts/%d", region.id)
		fresh, err := p.store.cacheFresh(key, now)
		if err != nil {
			continue
		}
		if fresh {
			continue
		}
		bodies, expires, err := p.esi.getPages(ctx, fmt.Sprintf("/contracts/public/%d/", region.id))
		if err != nil {
			if hold, stop := limited(err); stop {
				return hold, true
			}
			continue
		}
		for _, body := range bodies {
			var contracts []esiPublicContract
			if err := json.Unmarshal(body, &contracts); err != nil {
				continue
			}
			for _, c := range contracts {
				if c.ContractID <= 0 {
					continue
				}
				issued, err := time.Parse(time.RFC3339, c.DateIssued)
				if err != nil {
					continue
				}
				expired, err := time.Parse(time.RFC3339, c.DateExpired)
				if err != nil {
					continue
				}
				header := contractRow{
					contractID: c.ContractID, regionID: region.id, contractType: c.Type,
					issuerID: c.IssuerID, issuerCorporationID: c.IssuerCorporationID, forCorporation: c.ForCorporation,
					title: c.Title, price: c.Price, buyout: c.Buyout, reward: c.Reward, collateral: c.Collateral,
					volume: c.Volume, startLocationID: c.StartLocationID, endLocationID: c.EndLocationID,
					dateIssued: issued.UTC().Unix(), dateExpired: expired.UTC().Unix(), daysToComplete: c.DaysToComplete,
				}
				if err := p.store.upsertContractHeader(header, now); err != nil {
					return 0, false
				}
			}
		}
		// The sweep is due again when its Expires lapses; the
		// ledger records it so a restart resumes warm, exactly
		// as the order-book sweep does.
		if err := p.store.noteCache(key, expires); err != nil {
			return 0, false
		}
	}
	return 0, false
}

// pollContractItems drains pending contract item lists, bounded
// per tick, newest contracts first. True when the pass ended
// early on ESI's stop signal.
func (p *poller) pollContractItems(ctx context.Context, now time.Time) (time.Duration, bool) {
	pending, err := p.store.listContractsPendingItems(maxContractItemsPerTick)
	if err != nil {
		return 0, false
	}
	for _, c := range pending {
		if hold, stop := p.fetchContractItems(ctx, c.contractID, now); stop {
			return hold, true
		}
	}
	return 0, false
}

// fetchContractItems performs one contract's single items
// fetch — the fetcher the per-tick drain and swarm demand
// share, so a demanded contract and a routinely drained one
// settle identically. Success stores the list; a 400 settles
// 'private' (courier cargo is private by design, not a
// failure to retry); a 404 settles 'gone' (the contract ended
// between the listing sweep and this fetch); any other error
// leaves the header 'pending' for the next pass. There is no
// attempt counter in v1: a contract whose items endpoint
// keeps failing transiently is retried once per drain pass,
// bounded by maxContractItemsPerTick, and expires out of the
// queue when the contract itself expires. Stop-signal errors
// end the pass like everywhere else.
func (p *poller) fetchContractItems(ctx context.Context, contractID int64, now time.Time) (time.Duration, bool) {
	body, _, err := p.esi.get(ctx, fmt.Sprintf("/contracts/public/items/%d/", contractID))
	if err != nil {
		if hold, stop := limited(err); stop {
			return hold, true
		}
		if isStatus(err, http.StatusBadRequest) {
			_ = p.store.setContractItemsState(contractID, contractItemsPrivate)
			return 0, false
		}
		if isNotFound(err) {
			_ = p.store.setContractItemsState(contractID, contractItemsGone)
			return 0, false
		}
		return 0, false
	}
	var rows []esiPublicContractItem
	if err := json.Unmarshal(body, &rows); err != nil {
		return 0, false
	}
	items := make([]swarmContractItem, 0, len(rows))
	for _, row := range rows {
		if row.RecordID <= 0 || row.TypeID <= 0 {
			continue
		}
		item := swarmContractItem{
			RecordID: row.RecordID, TypeID: row.TypeID, Quantity: row.Quantity,
			IsIncluded: row.IsIncluded, IsBlueprintCopy: row.IsBlueprintCopy,
			Runs: row.Runs, MaterialEfficiency: row.MaterialEfficiency, TimeEfficiency: row.TimeEfficiency,
		}
		// ESI omits item_id for a stack with no singleton
		// item; a decoded pointer to 0 means the same, and
		// the wire carries both as nil.
		if row.ItemID != nil && *row.ItemID != 0 {
			v := *row.ItemID
			item.ItemID = &v
		}
		items = append(items, item)
	}
	if len(items) > maxSwarmContractItems {
		items = items[:maxSwarmContractItems]
	}
	if err := p.store.putContractItems(contractID, items, now); err != nil {
		return 0, false
	}
	return 0, false
}

// isStatus reports whether err is an ESI statusError with the
// given status — the 400 sibling of isNotFound, for endpoints
// where a 400 is an answer (courier cargo), not a failure.
func isStatus(err error, status int) bool {
	var se *statusError
	return errors.As(err, &se) && se.status == status
}

// pollNames resolves unseen type names, batched a thousand to
// the call. True when the pass ended early.
func (p *poller) pollNames(ctx context.Context) (time.Duration, bool) {
	var unseen []int64
	seen := map[int64]bool{}
	for _, region := range hubRegions {
		types, err := p.store.orderTypes(region.id)
		if err != nil {
			return 0, false
		}
		for _, typ := range types {
			if seen[typ] {
				continue
			}
			seen[typ] = true
			_, held, err := p.store.getTypeName(typ)
			if err != nil {
				return 0, false
			}
			if !held {
				unseen = append(unseen, typ)
				if len(unseen) >= maxNamesPerTick {
					break
				}
			}
		}
		if len(unseen) >= maxNamesPerTick {
			break
		}
	}
	now := time.Now().UTC()
	for start := 0; start < len(unseen); start += namesBatchSize {
		end := start + namesBatchSize
		if end > len(unseen) {
			end = len(unseen)
		}
		if hold, stop := p.fetchNames(ctx, unseen[start:end], now); stop {
			return hold, true
		}
	}
	return 0, false
}

// fetchNames resolves one batch of type IDs. True when the pass
// ended early.
func (p *poller) fetchNames(ctx context.Context, ids []int64, now time.Time) (time.Duration, bool) {
	body, _, err := p.esi.postJSON(ctx, "/universe/names/", map[string]any{"ids": ids})
	if err != nil {
		if hold, stop := limited(err); stop {
			return hold, true
		}
		return 0, false
	}
	var names []esiName
	if err := json.Unmarshal(body, &names); err != nil {
		return 0, false
	}
	for _, n := range names {
		if n.ID <= 0 || n.Name == "" || len(n.Name) > 256 || n.Category != "inventory_type" {
			continue
		}
		if err := p.store.upsertTypeName(n.ID, n.Name, now); err != nil {
			return 0, false
		}
	}
	return 0, false
}

// heartbeatDue announces to the seed when the last heartbeat is
// older than the interval (or never sent). Silence is not an
// error: discovery retries next pass.
func (p *poller) heartbeatDue(ctx context.Context, now time.Time) {
	if p.cfg.seedURL == "" || p.cfg.publicBaseURL == "" {
		log.Printf("warmer: heartbeat skipped: seedURL=%q publicBaseURL=%q", p.cfg.seedURL, p.cfg.publicBaseURL)
		return
	}
	if raw, err := p.store.getMeta("last_heartbeat"); err == nil && raw != "" {
		if at, err := time.Parse(time.RFC3339, raw); err == nil && now.Sub(at) < heartbeatInterval {
			return
		}
	}
	entry, err := signSwarmEntry(p.id, p.id.id, swarmAnnounceKind, p.id.id, announcePayload(p.id, p.cfg.publicBaseURL, now.Unix()), now)
	if err != nil {
		log.Printf("warmer: heartbeat sign failed: %v", err)
		return
	}
	if err := sendSeedAnnounce(ctx, p.cfg.secret, p.cfg.seedURL, entry); err != nil {
		log.Printf("warmer: heartbeat send failed: %v", err)
		return
	}
	log.Printf("warmer: heartbeat sent to %s", p.cfg.seedURL)
	_ = p.store.putMeta("last_heartbeat", now.UTC().Format(time.RFC3339))
}

// announcePayload seals the heartbeat's member tuple: the
// address, the key, and the node's signature over the address.
// Build rides along as the node's self-reported claim (the
// SHA-256 of its own binary): display metadata for receivers,
// never a claim about anything but itself.
func announcePayload(id *swarmIdentity, baseURL string, issuedAt int64) string {
	raw, err := json.Marshal(seedAnnouncePayload{BaseURL: baseURL, PublicKey: id.publicString(), URLSig: signSwarmMember(id, baseURL, issuedAt), IssuedAt: issuedAt, Build: buildClaim()})
	if err != nil {
		return ""
	}
	return string(raw)
}

// serveKey reads one shared key for a peer pull. It serves only
// rows the poll loop holds fresh — history inside the refetch
// gate, any held type name, records inside their Expires (or
// fetched live on first demand), contracts stored whole and
// unexpired. Anything else is a miss.
func (p *poller) serveKey(ctx context.Context, kind, key string, now time.Time) (payload string, fetchedAt time.Time, ok bool) {
	switch kind {
	case swarmKindHistory:
		return p.serveHistory(key, now)
	case swarmKindTypeName:
		return p.serveTypeName(key)
	case swarmKindCorporation:
		return p.serveOrg(ctx, "corporation", key, now)
	case swarmKindAlliance:
		return p.serveOrg(ctx, "alliance", key, now)
	case swarmKindPublicContract:
		return p.serveContract(key, now)
	default:
		return "", time.Time{}, false
	}
}

// serveContract serves one public contract whole — header
// plus its item list — and only whole: a contract whose items
// were never stored (still pending, courier-private, or gone)
// appraises nothing, so it is a miss, and an expired contract
// is a miss even before the prune drops it. The entry's
// fetchedAt is the items fetch time: that is when the payload
// became complete, not when the listing header was swept.
func (p *poller) serveContract(key string, now time.Time) (string, time.Time, bool) {
	contractID, ok := parseSwarmID(key)
	if !ok {
		return "", time.Time{}, false
	}
	c, held, err := p.store.getContract(contractID)
	if err != nil || !held {
		return "", time.Time{}, false
	}
	if c.itemsState != contractItemsStored || c.dateExpired <= now.Unix() {
		return "", time.Time{}, false
	}
	if len(c.items) > maxSwarmContractItems {
		return "", time.Time{}, false
	}
	items := c.items
	if items == nil {
		items = []swarmContractItem{}
	}
	out := swarmContractPayload{
		ContractID: c.contractID, RegionID: c.regionID, Type: c.contractType,
		IssuerID: c.issuerID, IssuerCorporationID: c.issuerCorporationID, ForCorporation: c.forCorporation,
		Title: c.title, Price: c.price, Buyout: c.buyout, Reward: c.reward, Collateral: c.collateral,
		Volume: c.volume, StartLocationID: c.startLocationID, EndLocationID: c.endLocationID,
		DateIssued: c.dateIssued, DateExpired: c.dateExpired, DaysToComplete: c.daysToComplete,
		Items: items,
	}
	raw, err := json.Marshal(out)
	if err != nil {
		return "", time.Time{}, false
	}
	return string(raw), c.itemsFetchedAt, true
}

// serveHistory serves one region/type pair's day rows, newest
// first, bounded — the wire shape the main instance stages.
func (p *poller) serveHistory(key string, now time.Time) (string, time.Time, bool) {
	regionID, typeID, ok := parseHistoryKey(key)
	if !ok {
		return "", time.Time{}, false
	}
	last, err := p.store.historyFetchedAt(regionID, typeID)
	if err != nil || last.IsZero() || now.Sub(last) >= historyRefetchGate {
		return "", time.Time{}, false
	}
	rows, err := p.store.listHistory(regionID, typeID, maxSwarmHistoryDays)
	if err != nil || len(rows) == 0 {
		return "", time.Time{}, false
	}
	out := swarmHistoryPayload{RegionID: regionID, TypeID: typeID}
	for _, row := range rows {
		out.Days = append(out.Days, swarmHistoryDay{
			Date: row.date, Average: row.average, Highest: row.highest,
			Lowest: row.lowest, Volume: row.volume, OrderCount: row.orderCount,
		})
	}
	raw, err := json.Marshal(out)
	if err != nil {
		return "", time.Time{}, false
	}
	return string(raw), last, true
}

// parseHistoryKey reads a "region/type" history key.
func parseHistoryKey(key string) (regionID, typeID int64, ok bool) {
	parts := strings.Split(key, "/")
	if len(parts) != 2 {
		return 0, 0, false
	}
	if regionID, ok = parseSwarmID(parts[0]); !ok {
		return 0, 0, false
	}
	if typeID, ok = parseSwarmID(parts[1]); !ok {
		return 0, 0, false
	}
	return regionID, typeID, true
}

// serveTypeName serves one held type name. Names carry no stored
// timestamp (they are effectively immutable); the receivers
// apply names only where they hold none.
func (p *poller) serveTypeName(key string) (string, time.Time, bool) {
	typeID, ok := parseSwarmID(key)
	if !ok {
		return "", time.Time{}, false
	}
	name, held, err := p.store.getTypeName(typeID)
	if err != nil || !held || name == "" {
		return "", time.Time{}, false
	}
	raw, err := json.Marshal(swarmTypeNamePayload{TypeID: typeID, Name: name})
	if err != nil {
		return "", time.Time{}, false
	}
	return string(raw), time.Now().UTC(), true
}

// serveOrg serves one corporation/alliance record: held and
// inside its Expires serves from SQLite; otherwise the record
// is fetched live (single-flighted across concurrent pulls),
// stored, and served. A failed fetch is a miss — the swarm
// never moves stale data sideways.
func (p *poller) serveOrg(ctx context.Context, kind, key string, now time.Time) (string, time.Time, bool) {
	id, ok := parseSwarmID(key)
	if !ok {
		return "", time.Time{}, false
	}
	wireKind := swarmKindCorporation
	endpoint := "corporations"
	if kind == "alliance" {
		wireKind = swarmKindAlliance
		endpoint = "alliances"
	}
	if payload, fetched, expires, held, err := p.store.getOrgRecord(wireKind, id); err == nil && held && now.Before(expires) {
		raw, err := json.Marshal(swarmOrgPayload{ID: id, Payload: payload})
		if err != nil {
			return "", time.Time{}, false
		}
		return string(raw), fetched, true
	}
	payload, fetched, ok, _ := p.fetchOrg(ctx, wireKind, endpoint, id, now)
	if !ok {
		return "", time.Time{}, false
	}
	raw, err := json.Marshal(swarmOrgPayload{ID: id, Payload: payload})
	if err != nil {
		return "", time.Time{}, false
	}
	return string(raw), fetched, true
}

// fetchOrg fetches one record live, joining an in-progress fetch
// for the same record instead of doubling the ESI call. hold is
// nonzero when ESI signaled a limit — a pull ignores it, the
// poll loop ends its pass on it.
func (p *poller) fetchOrg(ctx context.Context, wireKind, endpoint string, id int64, now time.Time) (payload string, fetchedAt time.Time, ok bool, hold time.Duration) {
	flightKey := wireKind + "/" + itoa(id)
	p.flightsMu.Lock()
	if f, dupe := p.flights[flightKey]; dupe {
		p.flightsMu.Unlock()
		select {
		case <-ctx.Done():
			return "", time.Time{}, false, 0
		case <-f.done:
			return f.payload, f.fetchedAt, f.ok, f.hold
		}
	}
	f := &flight{done: make(chan struct{})}
	p.flights[flightKey] = f
	p.flightsMu.Unlock()
	f.payload, f.fetchedAt, f.expiresAt, f.ok, f.hold = p.loadOrg(ctx, wireKind, endpoint, id, now)
	close(f.done)
	p.flightsMu.Lock()
	delete(p.flights, flightKey)
	p.flightsMu.Unlock()
	return f.payload, f.fetchedAt, f.ok, f.hold
}

// loadOrg performs one record fetch: a fresh negative marker or
// a live record suppresses the call; a 404 records the negative
// marker; the stored payload is ESI's body verbatim. hold is
// ESI's stop signal, when it sent one.
func (p *poller) loadOrg(ctx context.Context, wireKind, endpoint string, id int64, now time.Time) (string, time.Time, time.Time, bool, time.Duration) {
	negKey := "neg:" + wireKind + "/" + itoa(id)
	if fresh, err := p.store.cacheFresh(negKey, now); err == nil && fresh {
		return "", time.Time{}, time.Time{}, false, 0
	}
	body, expires, err := p.esi.get(ctx, fmt.Sprintf("/%s/%d/", endpoint, id))
	if err != nil {
		if isNotFound(err) {
			_ = p.store.noteCache(negKey, now.Add(orgNegativeTTL))
		}
		hold, _ := limited(err)
		return "", time.Time{}, time.Time{}, false, hold
	}
	payload := string(body)
	var probe any
	if err := json.Unmarshal(body, &probe); err != nil {
		return "", time.Time{}, time.Time{}, false, 0
	}
	if len(payload) > maxSwarmPayloadBytes {
		return "", time.Time{}, time.Time{}, false, 0
	}
	if err := p.store.upsertOrgRecord(wireKind, id, payload, now, expires); err != nil {
		return "", time.Time{}, time.Time{}, false, 0
	}
	return payload, now, expires, true, 0
}

// isNotFound reports a 404: the record does not exist, which is
// an answer, not a failure.
func isNotFound(err error) bool {
	var se *statusError
	return errors.As(err, &se) && se.status == http.StatusNotFound
}

// itoa formats an ID without importing strconv at every site.
func itoa(id int64) string {
	return fmt.Sprintf("%d", id)
}
