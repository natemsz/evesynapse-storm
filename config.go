package main

// ---------------------------------------------------------------------------
// Configuration: environment only, fail-closed. The warmer refuses to
// start when anything it needs to run safely is missing — a silent
// default must never stand in for an operator decision.
// ---------------------------------------------------------------------------

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// Defaults for the optional settings.
const (
	defaultPollInterval = time.Minute
	defaultBindAddr     = "127.0.0.1:8079"
	defaultDBPath       = "warmer.db"
	defaultIdentityPath = "warmer-identity.json"
)

// minPollInterval keeps a typo (POLL_INTERVAL=1s) from turning the
// node into an ESI hammer. The loop is cache-driven anyway: a due
// dataset is fetched when its Expires lapses, never because the
// tick fired.
const minPollInterval = 10 * time.Second

// minSharedSecret mirrors the main instance: the secret is the
// Bearer for the whole swarm, so a short one refuses to start.
const minSharedSecret = 32

// config is the warmer's whole configuration.
type config struct {
	secret        string
	esiContact    string
	seedURL       string
	publicBaseURL string
	pollInterval  time.Duration
	bindAddr      string
	dbPath        string
	identityPath  string
}

// loadConfig reads the environment. Any refusal is an error:
// main logs it and exits without listening or fetching.
func loadConfig(getenv func(string) string) (config, error) {
	c := config{
		secret:        strings.TrimSpace(getenv("SHARED_CACHE_SECRET")),
		esiContact:    strings.TrimSpace(getenv("ESI_CONTACT")),
		seedURL:       strings.TrimSpace(getenv("SWARM_SEED_URL")),
		publicBaseURL: strings.TrimSpace(getenv("PUBLIC_BASE_URL")),
		pollInterval:  defaultPollInterval,
		bindAddr:      defaultBindAddr,
		dbPath:        defaultDBPath,
		identityPath:  defaultIdentityPath,
	}
	if len(c.secret) < minSharedSecret {
		if c.secret == "" {
			return config{}, fmt.Errorf("SHARED_CACHE_SECRET is required (at least %d random characters, for example: openssl rand -hex 32)", minSharedSecret)
		}
		return config{}, fmt.Errorf("SHARED_CACHE_SECRET is %d characters long; it needs at least %d random ones (for example: openssl rand -hex 32)", len(c.secret), minSharedSecret)
	}
	if c.esiContact == "" {
		return config{}, fmt.Errorf("ESI_CONTACT is required: CCP must be able to reach whoever runs this node, and it travels in every User-Agent")
	}
	if raw := strings.TrimSpace(getenv("POLL_INTERVAL")); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil || d < minPollInterval {
			return config{}, fmt.Errorf("POLL_INTERVAL %q is not a duration of at least %s", raw, minPollInterval)
		}
		c.pollInterval = d
	}
	if raw := strings.TrimSpace(getenv("BIND_ADDR")); raw != "" {
		c.bindAddr = raw
	}
	if raw := strings.TrimSpace(getenv("DB_PATH")); raw != "" {
		c.dbPath = raw
	}
	if raw := strings.TrimSpace(getenv("IDENTITY_PATH")); raw != "" {
		c.identityPath = raw
	}
	if c.seedURL != "" && !validSwarmBaseURL(c.seedURL) {
		return config{}, fmt.Errorf("SWARM_SEED_URL %q is not dialable (https, or http on loopback, only)", c.seedURL)
	}
	if c.publicBaseURL != "" && !validSwarmBaseURL(c.publicBaseURL) {
		return config{}, fmt.Errorf("PUBLIC_BASE_URL %q is not servable (https, or http on loopback, only)", c.publicBaseURL)
	}
	if c.seedURL != "" {
		// The seed only files https records: announcing a
		// loopback URL would register a peer nobody can dial.
		if c.publicBaseURL == "" {
			return config{}, fmt.Errorf("SWARM_SEED_URL is set but PUBLIC_BASE_URL is empty: the seed only lists an https address peers can dial")
		}
		if !strings.HasPrefix(c.publicBaseURL, "https://") {
			return config{}, fmt.Errorf("PUBLIC_BASE_URL %q must be https when SWARM_SEED_URL is set: the seed refuses anything else", c.publicBaseURL)
		}
	}
	return c, nil
}

// loadConfigFromEnv reads the process environment.
func loadConfigFromEnv() (config, error) {
	return loadConfig(os.Getenv)
}
