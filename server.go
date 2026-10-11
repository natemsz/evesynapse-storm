package main

// ---------------------------------------------------------------------------
// The swarm HTTP API: how the main instance talks to this node.
// Two endpoints, both bearer-gated by the shared secret, both
// dark (404) to anything else:
//
//   GET  /swarm/members  — this node's sealed membership list
//   POST /swarm/pull     — signed public-data entries for wanted keys
//
// The API is pull-only: the node serves what callers ask for
// from what its poll loop holds fresh, and nothing else. Unknown
// kinds and keys it does not hold are skipped silently, so the
// response never says what is missing — only what is shared.
// Behavior mirrors the main instance's swarm_api.go: 403 on a
// bad bearer, 400 on an unreadable pull, entries signed at
// serve time over the row's own fetch time.
// ---------------------------------------------------------------------------

import (
	"encoding/json"
	"net/http"
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

// handler routes the two swarm endpoints. Anything else is
// dark: 404, the way a disabled instance answers.
func (s *server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/swarm/members":
			s.handleMembers(w, r)
		case r.Method == http.MethodPost && r.URL.Path == "/swarm/pull":
			s.handlePull(w, r)
		default:
			http.NotFound(w, r)
		}
	})
	return mux
}

// handleMembers serves this node's sealed membership list: the
// node itself, the only member it knows. The main instance pins
// the serving key on first contact from this list.
func (s *server) handleMembers(w http.ResponseWriter, r *http.Request) {
	if !swarmAuth(s.cfg.secret, r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	members := []swarmMember{{
		InstanceID: s.id.id, BaseURL: s.cfg.publicBaseURL,
		PublicKey: s.id.publicString(),
	}}
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
