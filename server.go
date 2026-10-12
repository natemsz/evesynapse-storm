package main

// ---------------------------------------------------------------------------
// The swarm HTTP API: how the main instance talks to this node.
// Three endpoints, all secret-gated, all dark (404) to anything
// else:
//
//   GET  /swarm/members       — this node plus its seed directory
//   POST /swarm/pull          — signed public-data entries for wanted keys
//   POST /swarm/seed/register — file one heartbeat in the directory
//
// Pulls serve what callers ask for from what the poll loop holds
// fresh, and nothing else. Unknown kinds and keys it does not
// hold are skipped silently, so the response never says what is
// missing — only what is shared. Registration mirrors the
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
	"net/http"
	"net/url"
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

// handler routes the three swarm endpoints. Anything else is
// dark: 404, the way a disabled instance answers.
func (s *server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/swarm/members":
			s.handleMembers(w, r)
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
	members := []swarmMember{{
		InstanceID: s.id.id, BaseURL: s.cfg.publicBaseURL,
		PublicKey: s.id.publicString(),
	}}
	for _, p := range peers {
		members = append(members, swarmMember{
			InstanceID: p.instanceID, BaseURL: p.baseURL, PublicKey: p.publicKey,
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

// handlePull serves the signed entries for the requested keys
// this node holds fresh.
func (s *server) handlePull(w http.ResponseWriter, r *http.Request) {
	if !swarmAuth(s.cfg.secret, r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	var req swarmPullRequest
	if err := readSwarmJSON(r, &req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if len(req.Keys) > maxSwarmPullKeys {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	now := time.Now().UTC()
	entries := []swarmSignedEntry{}
	for _, k := range req.Keys {
		if !validPullKey(k.Kind, k.Key) {
			continue
		}
		payload, fetchedAt, ok := s.poller.serveKey(ctx, k.Kind, k.Key, now)
		if !ok {
			continue
		}
		entry, err := signSwarmEntry(s.id, s.id.id, k.Kind, k.Key, payload, fetchedAt)
		if err != nil {
			continue
		}
		entries = append(entries, entry)
	}
	writeSwarmJSON(w, map[string]any{"entries": entries})
}

// handleSeedRegister files one heartbeat in the seed directory.
// Validation and status codes mirror the Cloudflare seed worker
// exactly: anonymous callers stay dark (404), a wrong secret is
// 403, an unreadable or misshapen announce is 400, and a full
// directory answers 429. The signature verifies against the
// CLAIMED key — self-signed, the same trust-on-first-use as mesh
// gossip — and the address must be https, like the worker
// demands.
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
	now := time.Now().UTC()
	store := s.poller.store
	_ = store.pruneSeedPeers(now)
	listed, err := store.hasSeedPeer(entry.Signer)
	if err != nil {
		http.Error(w, "bad gateway", http.StatusBadGateway)
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
	if err := store.upsertSeedPeer(entry.Signer, detail.BaseURL, detail.PublicKey, now); err != nil {
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
