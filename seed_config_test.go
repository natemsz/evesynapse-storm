package main

// ---------------------------------------------------------------------------
// Seed and config tests: the heartbeat's request shape (the seed
// worker rejects any other) and the fail-closed configuration.
// ---------------------------------------------------------------------------

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestSeedAnnounceRoundTrip heartbeats a fake seed and asserts
// the request the worker verifies: bearer, path, and the exact
// six-key announce entry.
func TestSeedAnnounceRoundTrip(t *testing.T) {
	const secret = "0123456789abcdef0123456789abcdef"
	id, err := mintSwarmIdentity()
	if err != nil {
		t.Fatal(err)
	}
	var gotAuth, gotPath string
	var gotKeys []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotPath = r.Header.Get("Authorization"), r.URL.Path
		var body struct {
			Entry map[string]any `json:"entry"`
		}
		dec := json.NewDecoder(io.LimitReader(r.Body, maxSwarmBodyBytes))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&body); err != nil {
			t.Errorf("seed: unreadable heartbeat: %v", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		for k := range body.Entry {
			gotKeys = append(gotKeys, k)
		}
		entry := body.Entry
		if entry["kind"] != swarmAnnounceKind || entry["key"] != entry["signer"] {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		var detail seedAnnouncePayload
		raw, _ := json.Marshal(entry["payload"])
		var payload string
		_ = json.Unmarshal(raw, &payload)
		if err := json.Unmarshal([]byte(payload), &detail); err != nil || detail.BaseURL == "" || detail.PublicKey == "" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	entry, err := signSwarmEntry(id, id.id, swarmAnnounceKind, id.id,
		announcePayload("https://warmer.example.com", id.publicString()), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := sendSeedAnnounce(context.Background(), secret, srv.URL, entry); err != nil {
		t.Fatalf("announce: %v", err)
	}
	if gotAuth != "Bearer "+secret {
		t.Errorf("seed saw auth %q", gotAuth)
	}
	if gotPath != "/swarm/seed/register" {
		t.Errorf("seed saw path %q", gotPath)
	}
	if len(gotKeys) != 6 {
		t.Errorf("announce has %d keys: %v", len(gotKeys), gotKeys)
	}
}

// TestSeedAnnounceRefused propagates seed refusals: a bad
// bearer, a refusing seed, and an undialable URL all error.
func TestSeedAnnounceRefused(t *testing.T) {
	id, err := mintSwarmIdentity()
	if err != nil {
		t.Fatal(err)
	}
	entry, err := signSwarmEntry(id, id.id, swarmAnnounceKind, id.id, `{"base_url":"https://w.example","public_key":"k"}`, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	deny := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer deny.Close()
	if err := sendSeedAnnounce(context.Background(), "secret", deny.URL, entry); err == nil {
		t.Error("403 seed accepted")
	}
	liar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":false}`))
	}))
	defer liar.Close()
	if err := sendSeedAnnounce(context.Background(), "secret", liar.URL, entry); err == nil {
		t.Error("refusing seed accepted")
	}
	if err := sendSeedAnnounce(context.Background(), "secret", "http://warmer.example.com", entry); err == nil {
		t.Error("public http seed accepted")
	}
}

// TestLoadConfig pins the fail-closed configuration: the secret
// and contact are required, nonsense refuses, and the seed
// requires a dialable https address.
func TestLoadConfig(t *testing.T) {
	full := map[string]string{
		"SHARED_CACHE_SECRET": "0123456789abcdef0123456789abcdef",
		"ESI_CONTACT":         "op@example.com",
		"SWARM_SEED_URL":      "https://seed.example.com",
		"PUBLIC_BASE_URL":     "https://warmer.example.com",
		"POLL_INTERVAL":       "90s",
		"BIND_ADDR":           "127.0.0.1:8090",
		"DB_PATH":             "w.db",
		"IDENTITY_PATH":       "w.json",
	}
	getenv := func(env map[string]string) func(string) string {
		return func(k string) string { return env[k] }
	}
	cfg, err := loadConfig(getenv(full))
	if err != nil {
		t.Fatalf("full config refused: %v", err)
	}
	if cfg.pollInterval != 90e9 || cfg.bindAddr != "127.0.0.1:8090" || cfg.dbPath != "w.db" || cfg.identityPath != "w.json" {
		t.Errorf("config parsed as %+v", cfg)
	}
	// Defaults apply when optional settings are empty.
	minimal := map[string]string{
		"SHARED_CACHE_SECRET": "0123456789abcdef0123456789abcdef",
		"ESI_CONTACT":         "op@example.com",
	}
	cfg, err = loadConfig(getenv(minimal))
	if err != nil {
		t.Fatalf("minimal config refused: %v", err)
	}
	if cfg.pollInterval != defaultPollInterval || cfg.bindAddr != defaultBindAddr || cfg.dbPath != defaultDBPath {
		t.Errorf("defaults not applied: %+v", cfg)
	}
	cases := map[string]map[string]string{
		"no secret": {"ESI_CONTACT": "op@example.com"},
		"short secret": {
			"SHARED_CACHE_SECRET": "too-short",
			"ESI_CONTACT":         "op@example.com",
		},
		"no contact": {"SHARED_CACHE_SECRET": "0123456789abcdef0123456789abcdef"},
		"bad interval": {
			"SHARED_CACHE_SECRET": "0123456789abcdef0123456789abcdef",
			"ESI_CONTACT":         "op@example.com",
			"POLL_INTERVAL":       "1s",
		},
		"seed without address": {
			"SHARED_CACHE_SECRET": "0123456789abcdef0123456789abcdef",
			"ESI_CONTACT":         "op@example.com",
			"SWARM_SEED_URL":      "https://seed.example.com",
		},
		"seed with loopback address": {
			"SHARED_CACHE_SECRET": "0123456789abcdef0123456789abcdef",
			"ESI_CONTACT":         "op@example.com",
			"SWARM_SEED_URL":      "https://seed.example.com",
			"PUBLIC_BASE_URL":     "http://127.0.0.1:8079",
		},
		"public http seed": {
			"SHARED_CACHE_SECRET": "0123456789abcdef0123456789abcdef",
			"ESI_CONTACT":         "op@example.com",
			"SWARM_SEED_URL":      "http://seed.example.com",
			"PUBLIC_BASE_URL":     "https://warmer.example.com",
		},
	}
	for name, env := range cases {
		if _, err := loadConfig(getenv(env)); err == nil {
			t.Errorf("%s: refused config accepted", name)
		}
	}
	// Loopback serving without a seed is allowed (local testing
	// against a main instance on the same box).
	local := map[string]string{
		"SHARED_CACHE_SECRET": "0123456789abcdef0123456789abcdef",
		"ESI_CONTACT":         "op@example.com",
		"PUBLIC_BASE_URL":     "http://127.0.0.1:8079",
	}
	if _, err := loadConfig(getenv(local)); err != nil {
		t.Errorf("loopback serving refused: %v", err)
	}
	if !strings.Contains(userAgent("op@example.com"), "op@example.com") {
		t.Error("User-Agent drops the contact")
	}
}
