package main

// ---------------------------------------------------------------------------
// Persistence: one SQLite file holding every warmed dataset plus the
// ESI cache ledger. A restart reopens the file warm — nothing is
// refetched while its Expires (or the history gate) still holds,
// so a cold restart never means a 30-minute gap.
//
// One *sql.DB with a single open connection serializes all access:
// the poll loop, the pull handler and on-demand fetches share the
// handle without any locking discipline of their own.
// ---------------------------------------------------------------------------

import (
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// schemaVersion is stored in meta; a mismatch refuses to open
// rather than read a layout this binary does not understand.
const schemaVersion = "1"

// warmerSchema is the whole layout.
const warmerSchema = `
CREATE TABLE IF NOT EXISTS meta(
	k TEXT PRIMARY KEY,
	v TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS esi_cache(
	cache_key  TEXT PRIMARY KEY,
	expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS region_orders(
	region_id     INTEGER NOT NULL,
	order_id      INTEGER NOT NULL,
	type_id       INTEGER NOT NULL,
	location_id   INTEGER NOT NULL,
	system_id     INTEGER NOT NULL,
	is_buy        INTEGER NOT NULL,
	price         REAL NOT NULL,
	volume_total  INTEGER NOT NULL,
	volume_remain INTEGER NOT NULL,
	ord_range     TEXT NOT NULL,
	issued        TEXT NOT NULL,
	duration      INTEGER NOT NULL,
	fetched_at    INTEGER NOT NULL,
	PRIMARY KEY(region_id, order_id)
);
CREATE INDEX IF NOT EXISTS idx_region_orders_type ON region_orders(region_id, type_id);
CREATE TABLE IF NOT EXISTS history(
	region_id   INTEGER NOT NULL,
	type_id     INTEGER NOT NULL,
	date        TEXT NOT NULL,
	average     REAL NOT NULL,
	highest     REAL NOT NULL,
	lowest      REAL NOT NULL,
	volume      INTEGER NOT NULL,
	order_count INTEGER NOT NULL,
	PRIMARY KEY(region_id, type_id, date)
);
CREATE TABLE IF NOT EXISTS history_state(
	region_id  INTEGER NOT NULL,
	type_id    INTEGER NOT NULL,
	fetched_at INTEGER NOT NULL,
	PRIMARY KEY(region_id, type_id)
);
CREATE TABLE IF NOT EXISTS type_names(
	type_id    INTEGER PRIMARY KEY,
	name       TEXT NOT NULL,
	fetched_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS org_records(
	kind       TEXT NOT NULL,
	id         INTEGER NOT NULL,
	payload    TEXT NOT NULL,
	fetched_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL,
	PRIMARY KEY(kind, id)
);
CREATE TABLE IF NOT EXISTS seed_peers(
	instance_id    TEXT PRIMARY KEY,
	base_url       TEXT NOT NULL,
	public_key     TEXT NOT NULL,
	last_heartbeat INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_seed_peers_heartbeat ON seed_peers(last_heartbeat);
CREATE TABLE IF NOT EXISTS swarm_demand(
	kind        TEXT NOT NULL,
	swarm_key   TEXT NOT NULL,
	first_asked INTEGER NOT NULL,
	last_asked  INTEGER NOT NULL,
	retry_at    INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY(kind, swarm_key)
);
CREATE INDEX IF NOT EXISTS idx_swarm_demand_asked ON swarm_demand(last_asked);
CREATE TABLE IF NOT EXISTS contracts(
	contract_id           INTEGER PRIMARY KEY,
	region_id             INTEGER NOT NULL,
	type                  TEXT NOT NULL,
	issuer_id             INTEGER NOT NULL,
	issuer_corporation_id INTEGER NOT NULL,
	for_corporation       INTEGER NOT NULL,
	title                 TEXT NOT NULL,
	price                 REAL NOT NULL,
	buyout                REAL NOT NULL,
	reward                REAL NOT NULL,
	collateral            REAL NOT NULL,
	volume                REAL NOT NULL,
	start_location_id     INTEGER NOT NULL,
	end_location_id       INTEGER NOT NULL,
	date_issued           INTEGER NOT NULL,
	date_expired          INTEGER NOT NULL,
	days_to_complete      INTEGER NOT NULL,
	items_state           TEXT NOT NULL,
	items_fetched_at      INTEGER NOT NULL DEFAULT 0,
	seen_at               INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_contracts_region ON contracts(region_id);
CREATE INDEX IF NOT EXISTS idx_contracts_items_state ON contracts(items_state, date_issued DESC);
CREATE TABLE IF NOT EXISTS contract_items(
	record_id           INTEGER PRIMARY KEY,
	contract_id         INTEGER NOT NULL,
	type_id             INTEGER NOT NULL,
	item_id             INTEGER,
	quantity            INTEGER NOT NULL,
	is_included         INTEGER NOT NULL,
	is_blueprint_copy   INTEGER NOT NULL,
	runs                INTEGER,
	material_efficiency INTEGER,
	time_efficiency     INTEGER
);
CREATE INDEX IF NOT EXISTS idx_contract_items_contract ON contract_items(contract_id);
`

// Seed directory bounds, mirroring the Cloudflare seed worker:
// heartbeats live 48 hours, a thousand records store, five
// hundred serve.
const (
	seedPeerTTL        = 48 * time.Hour
	maxStoredSeedPeers = 1000
	maxServedSeedPeers = 500
)

// store is the SQLite handle.
type store struct {
	db *sql.DB
}

// openStore opens (creating) the database file, applies the
// pragmas and the schema, and checks the version.
func openStore(path string) (*store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("warmer: open db: %w", err)
	}
	db.SetMaxOpenConns(1)
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA busy_timeout=5000",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA foreign_keys=ON",
	} {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("warmer: db pragma: %w", err)
		}
	}
	for _, stmt := range strings.Split(warmerSchema, ";") {
		if strings.TrimSpace(stmt) == "" {
			continue
		}
		if _, err := db.Exec(stmt); err != nil {
			db.Close()
			return nil, fmt.Errorf("warmer: db schema: %w", err)
		}
	}
	// seed_peers gained url_sig and url_issued_at after the first release. SQLite
	// has no ADD COLUMN IF NOT EXISTS: a database that already
	// has the column answers "duplicate column name", which is
	// the success case.
	for _, stmt := range []string{
		`ALTER TABLE seed_peers ADD COLUMN url_sig TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE seed_peers ADD COLUMN url_issued_at INTEGER NOT NULL DEFAULT 0`,
	} {
		if _, err := db.Exec(stmt); err != nil && !strings.Contains(err.Error(), "duplicate column name") {
			db.Close()
			return nil, fmt.Errorf("warmer: db schema: %w", err)
		}
	}
	s := &store{db: db}
	ver, err := s.getMeta("schema_version")
	if err != nil {
		db.Close()
		return nil, err
	}
	if ver == "" {
		if err := s.putMeta("schema_version", schemaVersion); err != nil {
			db.Close()
			return nil, err
		}
	} else if ver != schemaVersion {
		db.Close()
		return nil, fmt.Errorf("warmer: db schema is version %s, this binary reads %s", ver, schemaVersion)
	}
	return s, nil
}

// close releases the database.
func (s *store) close() error {
	return s.db.Close()
}

// getMeta reads one meta value ("", nil when unset).
func (s *store) getMeta(key string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT v FROM meta WHERE k = ?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("warmer: read meta: %w", err)
	}
	return v, nil
}

// bumpMeta increments one integer counter held in meta,
// treating an unset key as zero. The store's single connection
// serializes the read-modify-write, so concurrent handlers
// cannot lose an increment between the read and the write.
func (s *store) bumpMeta(key string) error {
	cur, err := s.getMeta(key)
	if err != nil {
		return err
	}
	var n int64
	if cur != "" {
		if parsed, err := strconv.ParseInt(cur, 10, 64); err == nil {
			n = parsed
		}
	}
	return s.putMeta(key, strconv.FormatInt(n+1, 10))
}

// putMeta writes one meta value.
func (s *store) putMeta(key, value string) error {
	if _, err := s.db.Exec(`INSERT INTO meta(k, v) VALUES(?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v`, key, value); err != nil {
		return fmt.Errorf("warmer: write meta: %w", err)
	}
	return nil
}

// cacheExpiresAt reports when one ESI cache entry lapses (the
// zero time when nothing is recorded).
func (s *store) cacheExpiresAt(key string) (time.Time, error) {
	var unix int64
	err := s.db.QueryRow(`SELECT expires_at FROM esi_cache WHERE cache_key = ?`, key).Scan(&unix)
	if err == sql.ErrNoRows {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("warmer: read cache ledger: %w", err)
	}
	return time.Unix(unix, 0).UTC(), nil
}

// cacheFresh reports whether one ESI cache entry is still fresh.
func (s *store) cacheFresh(key string, now time.Time) (bool, error) {
	exp, err := s.cacheExpiresAt(key)
	if err != nil {
		return false, err
	}
	return !exp.IsZero() && now.Before(exp), nil
}

// noteCache records one ESI Expires for a cache key.
func (s *store) noteCache(key string, expiresAt time.Time) error {
	if _, err := s.db.Exec(`INSERT INTO esi_cache(cache_key, expires_at) VALUES(?, ?) ON CONFLICT(cache_key) DO UPDATE SET expires_at = excluded.expires_at`,
		key, expiresAt.UTC().Unix()); err != nil {
		return fmt.Errorf("warmer: write cache ledger: %w", err)
	}
	return nil
}

// clearCache drops one ledger entry (a failed fetch must not
// poison the ledger into skipping the retry).
func (s *store) clearCache(key string) error {
	if _, err := s.db.Exec(`DELETE FROM esi_cache WHERE cache_key = ?`, key); err != nil {
		return fmt.Errorf("warmer: clear cache ledger: %w", err)
	}
	return nil
}

// orderRow is one stored market order.
type orderRow struct {
	regionID     int64
	orderID      int64
	typeID       int64
	locationID   int64
	systemID     int64
	isBuy        bool
	price        float64
	volumeTotal  int64
	volumeRemain int64
	ordRange     string
	issued       string
	duration     int64
	fetchedAt    time.Time
}

// replaceRegionOrders swaps one region's whole order book for a
// fresh sweep, transactionally: readers never see half a book.
func (s *store) replaceRegionOrders(regionID int64, rows []orderRow) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("warmer: orders transaction: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM region_orders WHERE region_id = ?`, regionID); err != nil {
		return fmt.Errorf("warmer: clear orders: %w", err)
	}
	for _, o := range rows {
		isBuy := 0
		if o.isBuy {
			isBuy = 1
		}
		if _, err := tx.Exec(`INSERT INTO region_orders(region_id, order_id, type_id, location_id, system_id, is_buy, price, volume_total, volume_remain, ord_range, issued, duration, fetched_at)
			VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			regionID, o.orderID, o.typeID, o.locationID, o.systemID, isBuy, o.price,
			o.volumeTotal, o.volumeRemain, o.ordRange, o.issued, o.duration, o.fetchedAt.UTC().Unix()); err != nil {
			return fmt.Errorf("warmer: store order: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("warmer: commit orders: %w", err)
	}
	return nil
}

// orderTypes lists the distinct type IDs with orders in a region.
func (s *store) orderTypes(regionID int64) ([]int64, error) {
	rows, err := s.db.Query(`SELECT DISTINCT type_id FROM region_orders WHERE region_id = ? ORDER BY type_id`, regionID)
	if err != nil {
		return nil, fmt.Errorf("warmer: list order types: %w", err)
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("warmer: list order types: %w", err)
		}
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("warmer: list order types: %w", err)
	}
	return out, nil
}

// historyDay is one stored daily aggregate.
type historyDay struct {
	date       string
	average    float64
	highest    float64
	lowest     float64
	volume     int64
	orderCount int64
}

// replaceHistory swaps one pair's day rows for a fresh fetch,
// transactionally, and settles the pair's fetch time.
func (s *store) replaceHistory(regionID, typeID int64, days []historyDay, fetchedAt time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("warmer: history transaction: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM history WHERE region_id = ? AND type_id = ?`, regionID, typeID); err != nil {
		return fmt.Errorf("warmer: clear history: %w", err)
	}
	for _, d := range days {
		if _, err := tx.Exec(`INSERT INTO history(region_id, type_id, date, average, highest, lowest, volume, order_count)
			VALUES(?, ?, ?, ?, ?, ?, ?, ?)`,
			regionID, typeID, d.date, d.average, d.highest, d.lowest, d.volume, d.orderCount); err != nil {
			return fmt.Errorf("warmer: store history: %w", err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO history_state(region_id, type_id, fetched_at) VALUES(?, ?, ?)
		ON CONFLICT(region_id, type_id) DO UPDATE SET fetched_at = excluded.fetched_at`,
		regionID, typeID, fetchedAt.UTC().Unix()); err != nil {
		return fmt.Errorf("warmer: settle history state: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("warmer: commit history: %w", err)
	}
	return nil
}

// historyFetchedAt reports when one pair was last fetched (zero
// when never).
func (s *store) historyFetchedAt(regionID, typeID int64) (time.Time, error) {
	var unix int64
	err := s.db.QueryRow(`SELECT fetched_at FROM history_state WHERE region_id = ? AND type_id = ?`, regionID, typeID).Scan(&unix)
	if err == sql.ErrNoRows {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("warmer: read history state: %w", err)
	}
	return time.Unix(unix, 0).UTC(), nil
}

// listHistory reads one pair's day rows, newest first, bounded.
func (s *store) listHistory(regionID, typeID int64, limit int) ([]historyDay, error) {
	rows, err := s.db.Query(`SELECT date, average, highest, lowest, volume, order_count FROM history
		WHERE region_id = ? AND type_id = ? ORDER BY date DESC LIMIT ?`, regionID, typeID, limit)
	if err != nil {
		return nil, fmt.Errorf("warmer: read history: %w", err)
	}
	defer rows.Close()
	var out []historyDay
	for rows.Next() {
		var d historyDay
		if err := rows.Scan(&d.date, &d.average, &d.highest, &d.lowest, &d.volume, &d.orderCount); err != nil {
			return nil, fmt.Errorf("warmer: read history: %w", err)
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("warmer: read history: %w", err)
	}
	return out, nil
}

// upsertTypeName stores one resolved type name. Names are
// effectively immutable: once held, never refetched.
func (s *store) upsertTypeName(typeID int64, name string, fetchedAt time.Time) error {
	if _, err := s.db.Exec(`INSERT INTO type_names(type_id, name, fetched_at) VALUES(?, ?, ?)
		ON CONFLICT(type_id) DO UPDATE SET name = excluded.name, fetched_at = excluded.fetched_at`,
		typeID, name, fetchedAt.UTC().Unix()); err != nil {
		return fmt.Errorf("warmer: store type name: %w", err)
	}
	return nil
}

// getTypeName reads one held name ("", false when unknown).
func (s *store) getTypeName(typeID int64) (string, bool, error) {
	var name string
	err := s.db.QueryRow(`SELECT name FROM type_names WHERE type_id = ?`, typeID).Scan(&name)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("warmer: read type name: %w", err)
	}
	return name, true, nil
}

// missingTypeNames reports which IDs have no held name, bounded.
func (s *store) missingTypeNames(ids []int64, limit int) ([]int64, error) {
	var out []int64
	for _, id := range ids {
		if len(out) >= limit {
			break
		}
		_, held, err := s.getTypeName(id)
		if err != nil {
			return nil, err
		}
		if !held {
			out = append(out, id)
		}
	}
	return out, nil
}

// upsertOrgRecord stores one corporation/alliance record payload
// verbatim, with its ESI Expires.
func (s *store) upsertOrgRecord(kind string, id int64, payload string, fetchedAt, expiresAt time.Time) error {
	if _, err := s.db.Exec(`INSERT INTO org_records(kind, id, payload, fetched_at, expires_at) VALUES(?, ?, ?, ?, ?)
		ON CONFLICT(kind, id) DO UPDATE SET payload = excluded.payload, fetched_at = excluded.fetched_at, expires_at = excluded.expires_at`,
		kind, id, payload, fetchedAt.UTC().Unix(), expiresAt.UTC().Unix()); err != nil {
		return fmt.Errorf("warmer: store org record: %w", err)
	}
	return nil
}

// getOrgRecord reads one held record (ok false when unknown).
func (s *store) getOrgRecord(kind string, id int64) (payload string, fetchedAt, expiresAt time.Time, ok bool, err error) {
	var fetchedUnix, expiresUnix int64
	err = s.db.QueryRow(`SELECT payload, fetched_at, expires_at FROM org_records WHERE kind = ? AND id = ?`, kind, id).Scan(&payload, &fetchedUnix, &expiresUnix)
	if err == sql.ErrNoRows {
		return "", time.Time{}, time.Time{}, false, nil
	}
	if err != nil {
		return "", time.Time{}, time.Time{}, false, fmt.Errorf("warmer: read org record: %w", err)
	}
	return payload, time.Unix(fetchedUnix, 0).UTC(), time.Unix(expiresUnix, 0).UTC(), true, nil
}

// seedPeer is one heartbeat the directory holds.
type seedPeer struct {
	instanceID    string
	baseURL       string
	publicKey     string
	urlSig        string
	issuedAt      int64
	lastHeartbeat time.Time
}

// upsertSeedPeer files one heartbeat: a re-announce refreshes
// the 48-hour listing, and replaces the address, its signature
// and issue time only when the tuple was issued later than the
// one held (an older tuple, however valid, never moves an
// address back). The key is written once: a listed ID keeps the
// key it registered with (the handler refuses a different one
// before this is reached).
func (s *store) upsertSeedPeer(instanceID, baseURL, publicKey, urlSig string, issuedAt int64, now time.Time) error {
	if _, err := s.db.Exec(`INSERT INTO seed_peers(instance_id, base_url, public_key, url_sig, url_issued_at, last_heartbeat) VALUES(?, ?, ?, ?, ?, ?)
		ON CONFLICT(instance_id) DO UPDATE SET
			base_url = CASE WHEN excluded.url_issued_at > seed_peers.url_issued_at THEN excluded.base_url ELSE seed_peers.base_url END,
			url_sig = CASE WHEN excluded.url_issued_at > seed_peers.url_issued_at THEN excluded.url_sig ELSE seed_peers.url_sig END,
			url_issued_at = MAX(excluded.url_issued_at, seed_peers.url_issued_at),
			last_heartbeat = excluded.last_heartbeat
		WHERE seed_peers.public_key = excluded.public_key`,
		instanceID, baseURL, publicKey, urlSig, issuedAt, now.UTC().Unix()); err != nil {
		return fmt.Errorf("warmer: file heartbeat: %w", err)
	}
	return nil
}

// countSeedPeers reports the directory size.
func (s *store) countSeedPeers() (int, error) {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM seed_peers`).Scan(&n); err != nil {
		return 0, fmt.Errorf("warmer: count directory: %w", err)
	}
	return n, nil
}

// seedPeerKey returns the key a listed ID registered with.
func (s *store) seedPeerKey(instanceID string) (key string, listed bool, err error) {
	err = s.db.QueryRow(`SELECT public_key FROM seed_peers WHERE instance_id = ?`, instanceID).Scan(&key)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("warmer: check directory: %w", err)
	}
	return key, true, nil
}

// hasSeedPeer reports whether one ID is already listed.
func (s *store) hasSeedPeer(instanceID string) (bool, error) {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM seed_peers WHERE instance_id = ?`, instanceID).Scan(&n); err != nil {
		return false, fmt.Errorf("warmer: check directory: %w", err)
	}
	return n > 0, nil
}

// listSeedPeers reads the fresh listings, freshest heartbeat
// first, bounded — the worker's order and cap.
func (s *store) listSeedPeers(now time.Time, limit int) ([]seedPeer, error) {
	// A listing with no address signature (filed before tuples
	// were signed) has nothing that may be relayed.
	rows, err := s.db.Query(`SELECT instance_id, base_url, public_key, url_sig, url_issued_at, last_heartbeat FROM seed_peers
		WHERE last_heartbeat > ? AND url_sig != '' ORDER BY last_heartbeat DESC LIMIT ?`, now.Add(-seedPeerTTL).UTC().Unix(), limit)
	if err != nil {
		return nil, fmt.Errorf("warmer: read directory: %w", err)
	}
	defer rows.Close()
	var out []seedPeer
	for rows.Next() {
		var p seedPeer
		var unix int64
		if err := rows.Scan(&p.instanceID, &p.baseURL, &p.publicKey, &p.urlSig, &p.issuedAt, &unix); err != nil {
			return nil, fmt.Errorf("warmer: read directory: %w", err)
		}
		p.lastHeartbeat = time.Unix(unix, 0).UTC()
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("warmer: read directory: %w", err)
	}
	return out, nil
}

// pruneSeedPeers drops listings whose heartbeat lapsed.
func (s *store) pruneSeedPeers(now time.Time) error {
	if _, err := s.db.Exec(`DELETE FROM seed_peers WHERE last_heartbeat <= ?`, now.Add(-seedPeerTTL).UTC().Unix()); err != nil {
		return fmt.Errorf("warmer: prune directory: %w", err)
	}
	return nil
}

// Demand bounds: a key nobody has asked for in a day is dropped
// unfetched — silently, it is not a failure against anyone — and
// the queue never holds more than this many keys.
const (
	demandTTL     = 24 * time.Hour
	maxDemandRows = 10000
)

// demandRow is one covered key a peer pulled and this node
// missed.
type demandRow struct {
	kind       string
	key        string
	firstAsked time.Time
	lastAsked  time.Time
	retryAt    time.Time
}

// noteDemand records one missed pull: a new key queues, a key
// already queued only refreshes its last-asked time (its backoff
// stands). A full queue drops new keys.
func (s *store) noteDemand(kind, key string, now time.Time) error {
	res, err := s.db.Exec(`UPDATE swarm_demand SET last_asked = ? WHERE kind = ? AND swarm_key = ?`, now.UTC().Unix(), kind, key)
	if err != nil {
		return fmt.Errorf("warmer: refresh demand: %w", err)
	}
	if n, err := res.RowsAffected(); err == nil && n > 0 {
		return nil
	}
	if _, err := s.db.Exec(`INSERT INTO swarm_demand(kind, swarm_key, first_asked, last_asked, retry_at)
		SELECT ?, ?, ?, ?, 0 WHERE (SELECT COUNT(*) FROM swarm_demand) < ?
		ON CONFLICT(kind, swarm_key) DO UPDATE SET last_asked = excluded.last_asked`,
		kind, key, now.UTC().Unix(), now.UTC().Unix(), maxDemandRows); err != nil {
		return fmt.Errorf("warmer: record demand: %w", err)
	}
	return nil
}

// scanDemand reads one demand row from a query result.
func scanDemand(scan func(dest ...any) error) (demandRow, error) {
	var d demandRow
	var first, last, retry int64
	if err := scan(&d.kind, &d.key, &first, &last, &retry); err != nil {
		return demandRow{}, err
	}
	d.firstAsked = time.Unix(first, 0).UTC()
	d.lastAsked = time.Unix(last, 0).UTC()
	d.retryAt = time.Unix(retry, 0).UTC()
	return d, nil
}

// dueDemand lists the queued keys whose backoff has lapsed,
// oldest demand first, bounded.
func (s *store) dueDemand(now time.Time, limit int) ([]demandRow, error) {
	rows, err := s.db.Query(`SELECT kind, swarm_key, first_asked, last_asked, retry_at FROM swarm_demand
		WHERE retry_at <= ? ORDER BY first_asked, kind, swarm_key LIMIT ?`, now.UTC().Unix(), limit)
	if err != nil {
		return nil, fmt.Errorf("warmer: read demand: %w", err)
	}
	defer rows.Close()
	var out []demandRow
	for rows.Next() {
		d, err := scanDemand(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("warmer: read demand: %w", err)
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("warmer: read demand: %w", err)
	}
	return out, nil
}

// getDemand reads one queued key (ok false when not queued).
func (s *store) getDemand(kind, key string) (demandRow, bool, error) {
	d, err := scanDemand(s.db.QueryRow(`SELECT kind, swarm_key, first_asked, last_asked, retry_at FROM swarm_demand
		WHERE kind = ? AND swarm_key = ?`, kind, key).Scan)
	if errors.Is(err, sql.ErrNoRows) {
		return demandRow{}, false, nil
	}
	if err != nil {
		return demandRow{}, false, fmt.Errorf("warmer: read demand: %w", err)
	}
	return d, true, nil
}

// countDemand reports the queue size.
func (s *store) countDemand() (int, error) {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM swarm_demand`).Scan(&n); err != nil {
		return 0, fmt.Errorf("warmer: count demand: %w", err)
	}
	return n, nil
}

// deferDemand holds one queued key back until retryAt.
func (s *store) deferDemand(kind, key string, retryAt time.Time) error {
	if _, err := s.db.Exec(`UPDATE swarm_demand SET retry_at = ? WHERE kind = ? AND swarm_key = ?`, retryAt.UTC().Unix(), kind, key); err != nil {
		return fmt.Errorf("warmer: defer demand: %w", err)
	}
	return nil
}

// deleteDemand drops one queued key: fetched, or already held.
func (s *store) deleteDemand(kind, key string) error {
	if _, err := s.db.Exec(`DELETE FROM swarm_demand WHERE kind = ? AND swarm_key = ?`, kind, key); err != nil {
		return fmt.Errorf("warmer: drop demand: %w", err)
	}
	return nil
}

// pruneDemand drops keys nobody has asked for within the TTL.
func (s *store) pruneDemand(now time.Time) error {
	if _, err := s.db.Exec(`DELETE FROM swarm_demand WHERE last_asked <= ?`, now.Add(-demandTTL).UTC().Unix()); err != nil {
		return fmt.Errorf("warmer: prune demand: %w", err)
	}
	return nil
}

// Contract items states: a header is swept first and its item
// list fetched once, ever, afterwards. 'pending' awaits that
// fetch; 'stored' holds the list; 'private' is ESI's 400 for
// courier cargo (private by design, not a failure); 'gone' is
// its 404 (the contract ended between the listing sweep and
// the items fetch). Only 'stored' ever serves.
const (
	contractItemsPending = "pending"
	contractItemsStored  = "stored"
	contractItemsPrivate = "private"
	contractItemsGone    = "gone"
)

// contractRow is one stored contract header plus, when read
// through getContract, its item list. Date fields are unix
// seconds, matching the wire payload exactly.
type contractRow struct {
	contractID          int64
	regionID            int64
	contractType        string
	issuerID            int64
	issuerCorporationID int64
	forCorporation      bool
	title               string
	price               float64
	buyout              float64
	reward              float64
	collateral          float64
	volume              float64
	startLocationID     int64
	endLocationID       int64
	dateIssued          int64
	dateExpired         int64
	daysToComplete      int64
	itemsState          string
	itemsFetchedAt      time.Time
	seenAt              time.Time
	items               []swarmContractItem
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// nullableInt flattens an optional ID/statistic for storage:
// nil stays SQL NULL, never a fabricated zero.
func nullableInt(v *int64) any {
	if v == nil {
		return nil
	}
	return *v
}

// ptrFromNull rebuilds an optional value from a stored
// column: SQL NULL comes back as a nil pointer.
func ptrFromNull(v sql.NullInt64) *int64 {
	if !v.Valid {
		return nil
	}
	out := v.Int64
	return &out
}

func scanContractHeader(scan func(dest ...any) error) (contractRow, error) {
	var c contractRow
	var forCorp int
	var itemsFetchedUnix, seenUnix int64
	if err := scan(&c.contractID, &c.regionID, &c.contractType, &c.issuerID, &c.issuerCorporationID, &forCorp,
		&c.title, &c.price, &c.buyout, &c.reward, &c.collateral, &c.volume,
		&c.startLocationID, &c.endLocationID, &c.dateIssued, &c.dateExpired, &c.daysToComplete,
		&c.itemsState, &itemsFetchedUnix, &seenUnix); err != nil {
		return contractRow{}, err
	}
	c.forCorporation = forCorp != 0
	if itemsFetchedUnix != 0 {
		c.itemsFetchedAt = time.Unix(itemsFetchedUnix, 0).UTC()
	}
	if seenUnix != 0 {
		c.seenAt = time.Unix(seenUnix, 0).UTC()
	}
	return c, nil
}

const contractHeaderColumns = `contract_id, region_id, type, issuer_id, issuer_corporation_id, for_corporation, title, price, buyout, reward, collateral, volume, start_location_id, end_location_id, date_issued, date_expired, days_to_complete, items_state, items_fetched_at, seen_at`

// upsertContractHeader stores one swept contract header,
// refreshing its facts and seen_at on conflict. It NEVER
// touches items_state or items_fetched_at on conflict: a
// contract's item list is fetched once, ever, and a listing
// refresh that reset the state would refetch (or worse,
// un-store) a list already held. A brand-new header starts
// 'pending' — the items drain picks it up from there.
func (s *store) upsertContractHeader(c contractRow, seenAt time.Time) error {
	if _, err := s.db.Exec(`INSERT INTO contracts(`+contractHeaderColumns+`)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', 0, ?)
		ON CONFLICT(contract_id) DO UPDATE SET
			region_id = excluded.region_id, type = excluded.type,
			issuer_id = excluded.issuer_id, issuer_corporation_id = excluded.issuer_corporation_id,
			for_corporation = excluded.for_corporation, title = excluded.title,
			price = excluded.price, buyout = excluded.buyout, reward = excluded.reward,
			collateral = excluded.collateral, volume = excluded.volume,
			start_location_id = excluded.start_location_id, end_location_id = excluded.end_location_id,
			date_issued = excluded.date_issued, date_expired = excluded.date_expired,
			days_to_complete = excluded.days_to_complete, seen_at = excluded.seen_at`,
		c.contractID, c.regionID, c.contractType, c.issuerID, c.issuerCorporationID, boolToInt(c.forCorporation),
		c.title, c.price, c.buyout, c.reward, c.collateral, c.volume,
		c.startLocationID, c.endLocationID, c.dateIssued, c.dateExpired, c.daysToComplete,
		seenAt.UTC().Unix()); err != nil {
		return fmt.Errorf("warmer: store contract header: %w", err)
	}
	return nil
}

// listContractsPendingItems lists headers still awaiting their
// one items fetch, newest first — a fresh contract is the one
// a pull is most likely to be waiting on.
func (s *store) listContractsPendingItems(limit int) ([]contractRow, error) {
	rows, err := s.db.Query(`SELECT `+contractHeaderColumns+` FROM contracts
		WHERE items_state = 'pending' ORDER BY date_issued DESC, contract_id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("warmer: list pending contracts: %w", err)
	}
	defer rows.Close()
	var out []contractRow
	for rows.Next() {
		c, err := scanContractHeader(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("warmer: list pending contracts: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("warmer: list pending contracts: %w", err)
	}
	return out, nil
}

// putContractItems stores one contract's item list in a
// single transaction and settles the header as 'stored' with
// its fetch time. Rows insert-or-ignore per record_id, like
// the main instance: a record already held is the same record,
// never a duplicate and never a reason to fail the list.
func (s *store) putContractItems(contractID int64, items []swarmContractItem, fetchedAt time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("warmer: contract items transaction: %w", err)
	}
	defer tx.Rollback()
	for _, it := range items {
		if _, err := tx.Exec(`INSERT OR IGNORE INTO contract_items(record_id, contract_id, type_id, item_id, quantity, is_included, is_blueprint_copy, runs, material_efficiency, time_efficiency)
			VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			it.RecordID, contractID, it.TypeID, nullableInt(it.ItemID), it.Quantity, boolToInt(it.IsIncluded), boolToInt(it.IsBlueprintCopy),
			nullableInt(it.Runs), nullableInt(it.MaterialEfficiency), nullableInt(it.TimeEfficiency)); err != nil {
			return fmt.Errorf("warmer: store contract item: %w", err)
		}
	}
	if _, err := tx.Exec(`UPDATE contracts SET items_state = 'stored', items_fetched_at = ? WHERE contract_id = ?`,
		fetchedAt.UTC().Unix(), contractID); err != nil {
		return fmt.Errorf("warmer: settle contract items: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("warmer: commit contract items: %w", err)
	}
	return nil
}

// setContractItemsState moves one header to a terminal items
// state ('private' or 'gone') without touching its fetch time:
// no list was ever fetched for it.
func (s *store) setContractItemsState(contractID int64, state string) error {
	if _, err := s.db.Exec(`UPDATE contracts SET items_state = ? WHERE contract_id = ?`, state, contractID); err != nil {
		return fmt.Errorf("warmer: set contract items state: %w", err)
	}
	return nil
}

// getContract reads one contract header plus its item list
// (ok false when the contract is unknown). NULL item columns
// come back as nil pointers, exactly as the wire payload
// carries them. The item list is an empty slice, never nil,
// for a held contract, so a stored contract with no lines
// still marshals "items":[].
func (s *store) getContract(contractID int64) (contractRow, bool, error) {
	c, err := scanContractHeader(s.db.QueryRow(`SELECT `+contractHeaderColumns+` FROM contracts WHERE contract_id = ?`, contractID).Scan)
	if errors.Is(err, sql.ErrNoRows) {
		return contractRow{}, false, nil
	}
	if err != nil {
		return contractRow{}, false, fmt.Errorf("warmer: read contract: %w", err)
	}
	c.items = []swarmContractItem{}
	rows, err := s.db.Query(`SELECT record_id, type_id, item_id, quantity, is_included, is_blueprint_copy, runs, material_efficiency, time_efficiency
		FROM contract_items WHERE contract_id = ? ORDER BY record_id`, contractID)
	if err != nil {
		return contractRow{}, false, fmt.Errorf("warmer: read contract items: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var it swarmContractItem
		var included, bpc int
		var itemID, runs, me, te sql.NullInt64
		if err := rows.Scan(&it.RecordID, &it.TypeID, &itemID, &it.Quantity, &included, &bpc, &runs, &me, &te); err != nil {
			return contractRow{}, false, fmt.Errorf("warmer: read contract items: %w", err)
		}
		it.ItemID = ptrFromNull(itemID)
		it.Runs = ptrFromNull(runs)
		it.MaterialEfficiency = ptrFromNull(me)
		it.TimeEfficiency = ptrFromNull(te)
		it.IsIncluded = included != 0
		it.IsBlueprintCopy = bpc != 0
		c.items = append(c.items, it)
	}
	if err := rows.Err(); err != nil {
		return contractRow{}, false, fmt.Errorf("warmer: read contract items: %w", err)
	}
	return c, true, nil
}

// pruneExpiredContracts drops contracts whose expiry has
// passed, together with their items: an expired contract can
// never serve again, and keeping its lines would only grow
// the store with dead appraisals.
func (s *store) pruneExpiredContracts(now time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("warmer: prune contracts transaction: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM contract_items WHERE contract_id IN (SELECT contract_id FROM contracts WHERE date_expired <= ?)`, now.UTC().Unix()); err != nil {
		return fmt.Errorf("warmer: prune contract items: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM contracts WHERE date_expired <= ?`, now.UTC().Unix()); err != nil {
		return fmt.Errorf("warmer: prune contracts: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("warmer: commit prune contracts: %w", err)
	}
	return nil
}
