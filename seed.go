package main

// ---------------------------------------------------------------------------
// Seed announcements: how this node tells the Cloudflare seed
// worker who is listening where, so main instances discover it.
// One heartbeat per poll pass when due (well inside the seed's
// 48-hour directory TTL): this node's self-signed announce entry
// (kind "announce", key and signer the node id, payload its base
// URL and public key). The worker verifies the signature against
// the claimed key — the same trust-on-first-use as mesh gossip —
// and files the record.
//
// A node with no public address configured stays silent: a URL
// nobody can dial would only pollute the directory.
// ---------------------------------------------------------------------------

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// seedHTTPTimeout bounds one seed round trip. The seed is a
// bulletin board, not a dependency: a hung seed must not hold
// the poll pass.
const seedHTTPTimeout = 15 * time.Second

// sendSeedAnnounce POSTs one heartbeat and reports whether the
// seed kept it. Strict-decode, size-capped, like every swarm
// call; the secret travels in the Bearer only.
func sendSeedAnnounce(ctx context.Context, secret, seedURL string, entry swarmSignedEntry) error {
	if !validSwarmBaseURL(seedURL) {
		return fmt.Errorf("swarm: refusing to announce to %q (https, or http on loopback, only)", seedURL)
	}
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(map[string]any{"entry": entry}); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(seedURL, "/")+"/swarm/seed/register", &buf)
	if err != nil {
		return fmt.Errorf("swarm: announce %s: %w", seedURL, err)
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	client := &http.Client{Timeout: seedHTTPTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("swarm: announce %s: %w", seedURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("swarm: announce %s: status %d", seedURL, resp.StatusCode)
	}
	var body struct {
		OK bool `json:"ok"`
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, maxSwarmBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		return fmt.Errorf("swarm: announce %s: %w", seedURL, err)
	}
	if !body.OK {
		return fmt.Errorf("swarm: announce %s: seed refused the heartbeat", seedURL)
	}
	return nil
}
