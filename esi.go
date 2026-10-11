package main

// ---------------------------------------------------------------------------
// ESI: the one client that talks to CCP. Tokenless throughout —
// every warmed dataset is public, so no Authorization header is
// ever sent. Etiquette mirrors the main instance:
//
//   - urgency reorders, never widens: one poll pass at a time,
//     sequential requests, bounded pages;
//   - 420/429 stop the pass (errLimited, never retried);
//   - transport failures and 5xx retry twice, honoring
//     Retry-After, then fail the dataset, not the loop;
//   - Expires headers are recorded per cache key in SQLite and
//     never fetched against while fresh;
//   - the X-Esi-Error-Limit budget is tracked, and a low budget
//     holds the loop before ESI has to refuse anything.
// ---------------------------------------------------------------------------

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// version is the warmer's release. It travels in the User-Agent
// so CCP can tell this client apart from the main instance.
const version = "0.1.0"

// esiBase is CCP's production API. Tests override it through
// newESIClientWithBase.
const esiBase = "https://esi.evetech.net"

// Bounds on the ESI client.
const (
	esiRequestTimeout = 30 * time.Second
	esiMaxBodyBytes   = 8 << 20
	esiMaxPages       = 500
	maxRetryAfter     = 30 * time.Second
	esiFallbackCache  = 5 * time.Minute
)

// errLimited is ESI's stop signal (420, or a 429): the pass ends
// and the loop holds until retryAfter. It is never retried —
// retrying a refusal is how budgets burn.
type errLimited struct {
	status     int
	retryAfter time.Duration
}

func (e *errLimited) Error() string {
	return fmt.Sprintf("ESI status %d: error limit", e.status)
}

// statusError is any other non-200 answer.
type statusError struct {
	status int
	path   string
}

func (e *statusError) Error() string {
	return fmt.Sprintf("ESI %s: status %d", e.path, e.status)
}

// esiClient GETs (and once POSTs) public ESI endpoints.
type esiClient struct {
	base string
	ua   string
	http *http.Client

	mu         sync.Mutex
	errRemain  int
	errReset   time.Time
	budgetSeen bool
}

// newESIClient builds the production client.
func newESIClient(contact string) *esiClient {
	return newESIClientWithBase(esiBase, contact)
}

// newESIClientWithBase builds a client against any base URL
// (tests point it at a fake ESI).
func newESIClientWithBase(base, contact string) *esiClient {
	return &esiClient{base: strings.TrimSuffix(base, "/"), ua: userAgent(contact), http: &http.Client{Timeout: esiRequestTimeout}}
}

// userAgent identifies this node to CCP: the product and its
// version, where the code lives, and how to reach the operator.
// A header value cannot carry control characters; anything of
// the sort becomes a space.
func userAgent(contact string) string {
	ua := "EveSynapse-Warmer/" + version + " (+https://github.com/natemsz/evesynapse"
	contact = strings.TrimSpace(strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, contact))
	if len(contact) > 120 {
		contact = contact[:120]
	}
	if contact != "" {
		ua += "; " + contact
	}
	return ua + ")"
}

// parseRetryAfter reads a Retry-After value: seconds, or an HTTP
// date. False when the value is missing or junk.
func parseRetryAfter(value string) (time.Duration, bool) {
	if value == "" {
		return 0, false
	}
	if secs, err := strconv.Atoi(strings.TrimSpace(value)); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second, true
	}
	if at, err := time.Parse(time.RFC1123, strings.TrimSpace(value)); err == nil {
		if d := time.Until(at); d > 0 {
			return d, true
		}
		return 0, true
	}
	return 0, false
}

// parseExpires reads an Expires header, or five minutes from now
// when ESI sent none usable.
func parseExpires(header http.Header, now time.Time) time.Time {
	if exp := header.Get("Expires"); exp != "" {
		if at, err := time.Parse(time.RFC1123, strings.TrimSpace(exp)); err == nil {
			return at.UTC()
		}
	}
	return now.Add(esiFallbackCache)
}

// noteBudget tracks ESI's error-budget headers from every
// response, so the loop can hold before discovering a 420.
func (c *esiClient) noteBudget(header http.Header, now time.Time) {
	remainRaw := strings.TrimSpace(header.Get("X-Esi-Error-Limit-Remain"))
	resetRaw := strings.TrimSpace(header.Get("X-Esi-Error-Limit-Reset"))
	if remainRaw == "" || resetRaw == "" {
		return
	}
	remain, err := strconv.Atoi(remainRaw)
	if err != nil || remain < 0 {
		return
	}
	reset, err := strconv.ParseInt(resetRaw, 10, 64)
	if err != nil || reset <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.errRemain = remain
	c.errReset = time.Unix(reset, 0).UTC()
	c.budgetSeen = true
}

// budgetHold reports how long the loop must hold before spending
// more budget: until the reset when nearly out, else zero.
func (c *esiClient) budgetHold(now time.Time) time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.budgetSeen || c.errRemain > 10 {
		return 0
	}
	if hold := time.Until(c.errReset); hold > 0 {
		return hold
	}
	return 0
}

// get fetches one path and returns the body with its Expires.
func (c *esiClient) get(ctx context.Context, path string) ([]byte, time.Time, error) {
	body, header, err := c.request(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, time.Time{}, err
	}
	return body, parseExpires(header, time.Now().UTC()), nil
}

// postJSON posts one JSON body and returns the answer with its
// Expires. Only universe/names uses it.
func (c *esiClient) postJSON(ctx context.Context, path string, payload any) ([]byte, time.Time, error) {
	body, header, err := c.request(ctx, http.MethodPost, path, payload)
	if err != nil {
		return nil, time.Time{}, err
	}
	return body, parseExpires(header, time.Now().UTC()), nil
}

// request makes one request with the idempotent-read retry rule:
// transport failures and 5xx twice, honoring Retry-After;
// 420/429 and other statuses never.
func (c *esiClient) request(ctx context.Context, method, path string, payload any) ([]byte, http.Header, error) {
	var raw []byte
	if payload != nil {
		var err error
		raw, err = json.Marshal(payload)
		if err != nil {
			return nil, nil, err
		}
	}
	backoff := 500 * time.Millisecond
	var last error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			wait := backoff
			backoff *= 2
			if w, ok := retryWait(last); ok {
				wait = w
				if wait > maxRetryAfter {
					wait = maxRetryAfter
				}
			}
			timer := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, nil, ctx.Err()
			case <-timer.C:
			}
		}
		body, header, retryable, err := c.requestOnce(ctx, method, path, raw)
		if err == nil {
			return body, header, nil
		}
		last = err
		if !retryable {
			return nil, nil, err
		}
	}
	return nil, nil, last
}

// retryWait recovers the wait a retryable error carried.
func retryWait(err error) (time.Duration, bool) {
	var re *retryableError
	if errors.As(err, &re) {
		return re.wait, true
	}
	return 0, false
}

// retryableError marks a failure a retry may cure, with the wait
// ESI asked for (zero when it asked for none).
type retryableError struct {
	wait time.Duration
	err  error
}

func (e *retryableError) Error() string { return e.err.Error() }
func (e *retryableError) Unwrap() error { return e.err }

// requestOnce makes one request and reads its answer the one
// way: 420/429 are errLimited, a status outside 200 is a
// statusError, anything else is the body with its headers.
func (c *esiClient) requestOnce(ctx context.Context, method, path string, raw []byte) (body []byte, header http.Header, retryable bool, err error) {
	now := time.Now().UTC()
	u := c.base + path
	if strings.Contains(path, "?") {
		u += "&datasource=tranquility"
	} else {
		u += "?datasource=tranquility"
	}
	var reqBody io.Reader
	if raw != nil {
		reqBody = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, reqBody)
	if err != nil {
		return nil, nil, false, err
	}
	req.Header.Set("User-Agent", c.ua)
	req.Header.Set("Accept", "application/json")
	if raw != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, nil, true, &retryableError{err: err}
	}
	defer resp.Body.Close()
	c.noteBudget(resp.Header, now)
	body, err = io.ReadAll(io.LimitReader(resp.Body, esiMaxBodyBytes))
	if err != nil {
		return nil, nil, true, &retryableError{err: fmt.Errorf("ESI %s %s: read body: %w", method, path, err)}
	}
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == 420 {
		wait := time.Minute
		if w, ok := parseRetryAfter(resp.Header.Get("Retry-After")); ok && w > 0 {
			wait = w
		}
		if wait > 15*time.Minute {
			wait = 15 * time.Minute
		}
		return nil, nil, false, &errLimited{status: resp.StatusCode, retryAfter: wait}
	}
	if resp.StatusCode >= 500 {
		wait, _ := parseRetryAfter(resp.Header.Get("Retry-After"))
		return nil, nil, true, &retryableError{wait: wait, err: &statusError{status: resp.StatusCode, path: path}}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil, false, &statusError{status: resp.StatusCode, path: path}
	}
	return body, resp.Header, false, nil
}

// getPages GETs a paginated endpoint to the end: the first page
// states the page count in X-Pages, and every page follows. A
// missing count means one page; a lying one never balloons the
// sweep past the cap. It returns the earliest Expires across the
// pages: the sweep is fresh only while every page is.
func (c *esiClient) getPages(ctx context.Context, path string) ([][]byte, time.Time, error) {
	var bodies [][]byte
	var freshest time.Time
	pages := 1
	for page := 1; page <= pages && page <= esiMaxPages; page++ {
		sep := "?"
		if strings.Contains(path, "?") {
			sep = "&"
		}
		body, header, err := c.request(ctx, http.MethodGet, fmt.Sprintf("%s%spage=%d", path, sep, page), nil)
		if err != nil {
			return nil, time.Time{}, err
		}
		bodies = append(bodies, body)
		if exp := parseExpires(header, time.Now().UTC()); freshest.IsZero() || exp.Before(freshest) {
			freshest = exp
		}
		if page == 1 {
			if n, err := strconv.Atoi(strings.TrimSpace(header.Get("X-Pages"))); err == nil && n > pages {
				pages = n
			}
		}
	}
	return bodies, freshest, nil
}
