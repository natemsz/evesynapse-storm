package main

// ---------------------------------------------------------------------------
// The swarm HTTP API: how the main instance talks to this node.
// Four endpoints, all gated (the bearer secret, or a directory-
// verified pull signature on /swarm/pull), all dark (404) to
// anything else:
//
//   GET  /swarm/members       — this node plus its seed directory
//   GET  /swarm/warms         — the kinds this node fetches on demand
//   POST /swarm/pull          — signed public-data entries for wanted keys
//   POST /swarm/seed/register — file one heartbeat in the directory
//
// Pulls serve what callers ask for from what the poll loop holds
// fresh, and nothing else. Unknown kinds and keys it does not
// hold are skipped silently, so the response never says what is
// missing — only what is shared. A miss on a covered kind is
// also demand: the key queues for the poll loop (warm.go), and a
// later pull serves it. Registration mirrors the
// Cloudflare seed worker field for field (codes included), so
// any instance that announces to the worker announces here.
// Behavior otherwise mirrors the main instance's swarm_api.go:
// 403 on a wrong secret, 400 on an unreadable body, entries
// signed at serve time over the row's own fetch time.
// ---------------------------------------------------------------------------

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// server serves the swarm API from the warmed store.
type server struct {
	cfg    config
	poller *poller
	id     *swarmIdentity
}

// newServer builds the handler dependencies.
func newServer(cfg config, poller *poller, id *swarmIdentity) *server {
	return &server{cfg: cfg, poller: poller, id: id}
}

// handler routes the four swarm endpoints. Anything else is
// dark: 404, the way a disabled instance answers.
func (s *server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/swarm/members":
			s.handleMembers(w, r)
		case r.Method == http.MethodGet && r.URL.Path == "/swarm/warms":
			s.handleWarms(w, r)
		case r.Method == http.MethodPost && r.URL.Path == "/swarm/pull":
			s.handlePull(w, r)
		case r.Method == http.MethodPost && r.URL.Path == "/swarm/seed/register":
			s.handleSeedRegister(w, r)
		default:
			http.NotFound(w, r)
		}
	})
	return mux
}

// handleMembers serves this node's sealed membership list:
// the node itself first, then its seed directory, freshest
// heartbeat first — the worker's shape and order. The main
// instance pins the serving key on first contact from this
// list, and learns every listed instance through gossip.
func (s *server) handleMembers(w http.ResponseWriter, r *http.Request) {
	if !swarmAuth(s.cfg.secret, r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	now := time.Now().UTC()
	store := s.poller.store
	_ = store.pruneSeedPeers(now)
	peers, err := store.listSeedPeers(now, maxServedSeedPeers)
	if err != nil {
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	// This node signs its own tuple and nobody else's: every
	// listed peer's tuple goes out exactly as it registered.
	members := []swarmMember{{
		InstanceID: s.id.id, BaseURL: s.cfg.publicBaseURL,
		PublicKey: s.id.publicString(),
		URLSig:    signSwarmMember(s.id, s.cfg.publicBaseURL, now.Unix()),
		IssuedAt:  now.Unix(),
	}}
	for _, p := range peers {
		members = append(members, swarmMember{
			InstanceID: p.instanceID, BaseURL: p.baseURL, PublicKey: p.publicKey, URLSig: p.urlSig, IssuedAt: p.issuedAt,
		})
	}
	raw, err := json.Marshal(members)
	if err != nil {
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	// Sealed under the shared secret before signing: possession
	// of the secret decides who may fetch; the seal decides who
	// may read.
	sealed, err := sealSwarmMembers(raw, s.cfg.secret)
	if err != nil {
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	entry, err := signSwarmEntry(s.id, s.id.id, swarmKindMembers, s.id.id, sealed, time.Now())
	if err != nil {
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	writeSwarmJSON(w, map[string]any{"entry": entry})
}

// handleWarms announces this node's coverage: {"kinds": [...]}
// and nothing else — the main instance decodes it strictly.
// Unconditional: a dedicated node always covers its kinds.
func (s *server) handleWarms(w http.ResponseWriter, r *http.Request) {
	if !swarmAuth(s.cfg.secret, r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	writeSwarmJSON(w, map[string]any{"kinds": warmKinds})
}

// pullAuthWindow is how far a signed pull's timestamp may
// drift from the server clock, in either direction. Five
// minutes covers ordinary clock skew between two instances
// while keeping a captured signature's replay window short.
const pullAuthWindow = 5 * time.Minute

// signedPullValid reports whether the request's three signed-
// pull headers prove the claimed instance: the instance must
// be listed in the seed directory, the timestamp must sit
// inside pullAuthWindow of now, and the signature must verify
// under the directory key over the message built from the
// exact received body bytes. Any failure is simply false —
// the caller falls back to the bearer, and a failed signature
// is never anything more than an auth failure.
func (s *server) signedPullValid(instanceID, timestampRaw, signature string, body []byte, now time.Time) bool {
	ts, err := strconv.ParseInt(strings.TrimSpace(timestampRaw), 10, 64)
	if err != nil {
		return false
	}
	diff := now.Unix() - ts
	if diff < 0 {
		diff = -diff
	}
	if diff > int64(pullAuthWindow/time.Second) {
		return false
	}
	key, listed, err := s.poller.store.seedPeerKey(instanceID)
	if err != nil || !listed {
		return false
	}
	return verifySwarmPull(key, instanceID, ts, body, signature)
}

// handlePull serves the signed entries for the requested keys
// this node holds fresh, and queues each covered miss as demand.
//
// Auth is dual-path while pullers migrate to signed requests.
// A request carrying all three X-Swarm-* headers is checked
// against the seed directory first: a listed instance, a fresh
// timestamp, and a signature over the exact body bytes serve
// without the shared secret ever crossing the wire. Absent or
// invalid signed headers fall back to the legacy bearer check
// unchanged — a peer that has not upgraded yet still pulls, and
// a bad signature alone never locks anyone out. Neither path
// passing is 403, exactly as before. Every served pull counts
// once, under the path that authorized it, in meta
// (pull_auth_signed / pull_auth_legacy): the counters are how
// an operator sees the migration actually happen, and when the
// legacy count reaches zero the bearer could be retired.
// 403s and unreadable bodies count nothing — they served
// nothing.
func (s *server) handlePull(w http.ResponseWriter, r *http.Request) {
	// The body is read once, up front and size-capped the way
	// handleSeedRegister reads its body: the signed path hashes
	// the exact bytes received, so verification and decoding
	// must both run over this one copy, never a re-read.
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxSwarmBodyBytes+1))
	_ = r.Body.Close()
	if err != nil || len(raw) > maxSwarmBodyBytes {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	now := time.Now().UTC()
	authKind := ""
	instanceID := r.Header.Get("X-Swarm-Instance")
	timestampRaw := r.Header.Get("X-Swarm-Timestamp")
	signature := r.Header.Get("X-Swarm-Signature")
	if instanceID != "" && timestampRaw != "" && signature != "" {
		if s.signedPullValid(instanceID, timestampRaw, signature, raw, now) {
			authKind = "signed"
		} else {
			// Logged once for visibility — a peer whose
			// clock or key drifted is otherwise invisible,
			// silently riding the bearer — and nothing
			// more: the bearer decides below.
			log.Printf("warmer: pull: signed auth failed for instance %q, falling back to bearer", instanceID)
		}
	}
	if authKind == "" {
		if !swarmAuth(s.cfg.secret, r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		authKind = "legacy"
	}
	var req swarmPullRequest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if len(req.Keys) > maxSwarmPullKeys {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	entries := []swarmSignedEntry{}
	for _, k := range req.Keys {
		if !validPullKey(k.Kind, k.Key) {
			continue
		}
		payload, fetchedAt, ok := s.poller.serveKey(ctx, k.Kind, k.Key, now)
		if !ok {
			// The miss still answers nothing; it only queues.
			if demandable(k.Kind, k.Key) {
				_ = s.poller.store.noteDemand(k.Kind, k.Key, now)
			}
			continue
		}
		entry, err := signSwarmEntry(s.id, s.id.id, k.Kind, k.Key, payload, fetchedAt)
		if err != nil {
			continue
		}
		entries = append(entries, entry)
	}
	// One count per served pull, under the path that
	// authorized it — not per key, and never for a 403 or a
	// body that never decoded.
	if authKind == "signed" {
		_ = s.poller.store.bumpMeta("pull_auth_signed")
	} else {
		_ = s.poller.store.bumpMeta("pull_auth_legacy")
	}
	writeSwarmJSON(w, map[string]any{"entries": entries})
}

// handleSeedRegister files one heartbeat in the seed directory.
// Validation and status codes mirror the Cloudflare seed worker
// exactly: anonymous callers stay dark (404), a wrong secret is
// 403, an unreadable or misshapen announce is 400, and a full
// directory answers 429. The signature verifies against the
// CLAIMED key — self-signed, the same trust-on-first-use as mesh
// gossip — the address must be https, like the worker demands,
// and the payload must carry the sender's signature over that
// address (url_sig). A heartbeat for a listed ID under another
// key is 409.
func (s *server) handleSeedRegister(w http.ResponseWriter, r *http.Request) {
	if _, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); !ok {
		http.NotFound(w, r)
		return
	}
	if !swarmAuth(s.cfg.secret, r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	// The outer body tolerates extra keys, exactly like the
	// worker; the entry itself must carry precisely the six
	// announce keys, enforced by strict decoding below.
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxSwarmBodyBytes+1))
	_ = r.Body.Close()
	if err != nil || len(raw) > maxSwarmBodyBytes {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var outer struct {
		Entry json.RawMessage `json:"entry"`
	}
	if err := json.Unmarshal(raw, &outer); err != nil || len(outer.Entry) == 0 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var entry swarmSignedEntry
	dec := json.NewDecoder(bytes.NewReader(outer.Entry))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&entry); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if entry.Kind != swarmAnnounceKind || entry.Key == "" || entry.Key != entry.Signer ||
		entry.Payload == "" || entry.Signature == "" || len(entry.Payload) > maxSwarmPayloadBytes {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var detail seedAnnouncePayload
	if err := json.Unmarshal([]byte(entry.Payload), &detail); err != nil ||
		detail.BaseURL == "" || detail.PublicKey == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !isHTTPSURL(detail.BaseURL) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !verifySwarmEntry(entry, detail.PublicKey) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	// The member tuple itself: the sender's signature over its
	// ID and address, under the same key. It is what gets stored
	// and relayed, so it is checked before it is kept.
	if !verifySwarmMember(swarmMember{InstanceID: entry.Signer, BaseURL: detail.BaseURL, PublicKey: detail.PublicKey, URLSig: detail.URLSig, IssuedAt: detail.IssuedAt}) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	now := time.Now().UTC()
	store := s.poller.store
	_ = store.pruneSeedPeers(now)
	heldKey, listed, err := store.seedPeerKey(entry.Signer)
	if err != nil {
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	// First key wins for an instance ID while its listing lives:
	// a heartbeat under another key is a conflict, not a rotation.
	if listed && heldKey != detail.PublicKey {
		http.Error(w, "conflict", http.StatusConflict)
		return
	}
	if !listed {
		n, err := store.countSeedPeers()
		if err != nil {
			http.Error(w, "bad gateway", http.StatusBadGateway)
			return
		}
		if n >= maxStoredSeedPeers {
			http.Error(w, "busy", http.StatusTooManyRequests)
			return
		}
	}
	if err := store.upsertSeedPeer(entry.Signer, detail.BaseURL, detail.PublicKey, detail.URLSig, detail.IssuedAt, now); err != nil {
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	writeSwarmJSON(w, map[string]any{"ok": true})
}

// isHTTPSURL reports whether raw is an https URL with a host —
// the worker's rule, loopback included in the refusal.
func isHTTPSURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return false
	}
	return strings.ToLower(u.Scheme) == "https"
}
