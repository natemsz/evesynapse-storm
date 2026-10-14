package main

// ---------------------------------------------------------------------------
// Swarm-first warming, the dedicated-node side of the main
// instance's swarm_warm.go. A main leaves a covered miss to the
// swarm for a grace period before spending its own ESI budget,
// so this node:
//
//   - announces what it covers on GET /swarm/warms — the kinds it
//     can FETCH on demand, not merely the kinds it serves;
//   - treats a pull as the demand: a covered key it misses is
//     queued (kind, key, first/last asked), deduplicated, and
//     aged out unfetched after a day of nobody asking;
//   - drains the queue at the top of every poll pass, through the
//     same fetchers and the same per-pass discipline as routine
//     warming, so a later pull serves the key through the
//     unchanged trust pipeline. Nothing is pushed.
//
// structure_name is served when held but never covered: resolving
// one needs a character with docking access, and this node holds
// no character tokens. A promise it cannot keep would cost every
// asker the grace period for nothing.
// ---------------------------------------------------------------------------

import (
	"context"
	"fmt"
	"time"
)

// warmKinds is this node's coverage, in the order /swarm/warms
// lists it.
var warmKinds = []string{swarmKindHistory, swarmKindTypeName, swarmKindCorporation, swarmKindAlliance}

// Drain bounds: at most this many demanded keys per pass (the
// history backlog's own bound), and a failed key waits this long
// before it costs another call.
const (
	maxDemandPerTick   = 100
	demandRetryBackoff = time.Hour
)

// coversKind reports whether this node fetches kind on demand.
func coversKind(kind string) bool {
	for _, k := range warmKinds {
		if k == kind {
			return true
		}
	}
	return false
}

// demandable reports whether a missed pull may queue: a covered
// kind and a key that names its entity. Junk keys never queue —
// they could never be fetched.
func demandable(kind, key string) bool {
	switch kind {
	case swarmKindHistory:
		_, _, ok := parseHistoryKey(key)
		return ok
	case swarmKindTypeName, swarmKindCorporation, swarmKindAlliance:
		_, ok := parseSwarmID(key)
		return ok
	default:
		return false
	}
}

// pollDemand drains the due demand queue, oldest first, bounded
// per pass. A fetched (or already held) key leaves the queue; a
// failed one backs off. True when the pass ended early on ESI's
// stop signal — the key in hand stays due.
func (p *poller) pollDemand(ctx context.Context, now time.Time) (time.Duration, bool) {
	_ = p.store.pruneDemand(now)
	due, err := p.store.dueDemand(now, maxDemandPerTick)
	if err != nil {
		return 0, false
	}
	for _, d := range due {
		done, retryAt, hold, stop := p.fetchDemand(ctx, d.kind, d.key, now)
		switch {
		case stop:
			return hold, true
		case done:
			_ = p.store.deleteDemand(d.kind, d.key)
		default:
			if !retryAt.After(now) {
				retryAt = now.Add(demandRetryBackoff)
			}
			_ = p.store.deferDemand(d.kind, d.key, retryAt)
		}
	}
	return 0, false
}

// fetchDemand fetches one demanded key through its kind's
// fetcher and stores it as routine warming does. done when the
// key is now held fresh; otherwise retryAt says when to try
// again (zero for the default backoff). stop carries ESI's stop
// signal.
func (p *poller) fetchDemand(ctx context.Context, kind, key string, now time.Time) (done bool, retryAt time.Time, hold time.Duration, stop bool) {
	switch kind {
	case swarmKindHistory:
		regionID, typeID, ok := parseHistoryKey(key)
		if !ok {
			return false, time.Time{}, 0, false
		}
		if p.historyHeld(regionID, typeID, now) {
			return true, time.Time{}, 0, false
		}
		// Never fetch against a fresh Expires (or a fresh
		// "no history here" marker): wait it out instead.
		for _, ledger := range []string{fmt.Sprintf("history/%d/%d", regionID, typeID), fmt.Sprintf("neg:history/%d/%d", regionID, typeID)} {
			if exp, err := p.store.cacheExpiresAt(ledger); err == nil && now.Before(exp) {
				return false, exp, 0, false
			}
		}
		if hold, stop := p.fetchHistory(ctx, regionID, typeID, now); stop {
			return false, time.Time{}, hold, true
		}
		return p.historyHeld(regionID, typeID, now), time.Time{}, 0, false
	case swarmKindTypeName:
		typeID, ok := parseSwarmID(key)
		if !ok {
			return false, time.Time{}, 0, false
		}
		if _, held, err := p.store.getTypeName(typeID); err == nil && held {
			return true, time.Time{}, 0, false
		}
		// One ID to the call: ESI refuses a whole batch over
		// one bad ID, and a demanded ID is unvetted.
		if hold, stop := p.fetchNames(ctx, []int64{typeID}, now); stop {
			return false, time.Time{}, hold, true
		}
		_, held, err := p.store.getTypeName(typeID)
		return err == nil && held, time.Time{}, 0, false
	case swarmKindCorporation, swarmKindAlliance:
		id, ok := parseSwarmID(key)
		if !ok {
			return false, time.Time{}, 0, false
		}
		endpoint := "corporations"
		if kind == swarmKindAlliance {
			endpoint = "alliances"
		}
		if _, _, expires, held, err := p.store.getOrgRecord(kind, id); err == nil && held && now.Before(expires) {
			return true, time.Time{}, 0, false
		}
		_, _, ok, hold := p.fetchOrg(ctx, kind, endpoint, id, now)
		if hold > 0 {
			return false, time.Time{}, hold, true
		}
		return ok, time.Time{}, 0, false
	default:
		return false, time.Time{}, 0, false
	}
}

// historyHeld reports whether a pair is held inside the refetch
// gate — exactly when serveHistory would serve it.
func (p *poller) historyHeld(regionID, typeID int64, now time.Time) bool {
	last, err := p.store.historyFetchedAt(regionID, typeID)
	return err == nil && !last.IsZero() && now.Sub(last) < historyRefetchGate
}
