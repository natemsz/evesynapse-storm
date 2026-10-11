package main

// ---------------------------------------------------------------------------
// The warmer: a headless node that mirrors public ESI data into
// the EveSynapse swarm. One loop polls ESI into SQLite; one HTTP
// server answers pulls from the warmed tables; heartbeats keep
// the seed directory listing this node. No SSO, no tokens, no
// sessions, no UI — there is no credential on this box worth
// stealing.
// ---------------------------------------------------------------------------

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// run wires the node and blocks until the context ends. It is
// split from main for tests, which drive the server and the
// poller without listening on a real port.
func run(ctx context.Context, cfg config) error {
	store, err := openStore(cfg.dbPath)
	if err != nil {
		return err
	}
	defer store.close()
	id, rotated, err := loadIdentity(cfg.identityPath, cfg.secret)
	if err != nil {
		return err
	}
	if rotated {
		log.Printf("warmer: the sealed identity did not open with the configured secret; minted a fresh node identity — re-allowlist this node")
	}
	esi := newESIClient(cfg.esiContact)
	poller := newPoller(cfg, esi, store, id)
	srv := newServer(cfg, poller, id)

	httpSrv := &http.Server{Addr: cfg.bindAddr, Handler: srv.handler()}
	go func() {
		<-ctx.Done()
		shut, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shut)
	}()
	go func() {
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("warmer: serve: %v", err)
		}
	}()
	log.Printf("warmer: listening on %s, polling every %s", cfg.bindAddr, cfg.pollInterval)

	tick := time.NewTicker(cfg.pollInterval)
	defer tick.Stop()
	for {
		now := time.Now().UTC()
		if hold := poller.tick(ctx, now); hold > 0 {
			log.Printf("warmer: ESI signaled a limit; holding %s", hold.Round(time.Second))
			if !sleepOrDone(ctx, hold) {
				return nil
			}
			continue
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}

// sleepOrDone waits out a hold, reporting false on shutdown.
func sleepOrDone(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func main() {
	cfg, err := loadConfigFromEnv()
	if err != nil {
		log.Printf("warmer: %v", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, cfg); err != nil {
		log.Printf("warmer: %v", err)
		os.Exit(1)
	}
}
