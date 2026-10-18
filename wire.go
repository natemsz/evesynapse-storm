package main

// ---------------------------------------------------------------------------
// The swarm wire: identity, entry signatures, sealed member lists,
// bearer auth, and endpoint bounds. This file mirrors the main
// instance's swarm_identity.go, swarm_crypt.go and swarm_api.go
// field for field — the main instance verifies every entry
// against its pinned key and rejects anything shaped otherwise,
// so any drift here means every served entry dies at staging.
//
// Cryptography throughout is the standard library (Ed25519,
// HKDF-SHA-256, AES-256-GCM). Nothing handrolled.
// ---------------------------------------------------------------------------

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// The shared data kinds, and the membership kind that signs with
// the same envelope but never stages as data.
const (
	swarmKindMembers     = "swarm_members"
	swarmKindHistory     = "market_history"
	swarmKindTypeName    = "type_name"
	swarmKindCorporation = "corporation_record"
	swarmKindAlliance    = "alliance_record"
	swarmKindStructure   = "structure_name"
	swarmAnnounceKind    = "announce"
)

// validSwarmKind reports whether kind is data the swarm carries
// (not the membership list or the seed announce, which are
// gossip, not data).
func validSwarmKind(kind string) bool {
	switch kind {
	case swarmKindHistory, swarmKindTypeName, swarmKindCorporation, swarmKindAlliance, swarmKindStructure:
		return true
	default:
		return false
	}
}

// Bounds on the swarm API, identical to the main instance: one
// pull names at most this many keys, and no request body past
// this size is read.
const (
	maxSwarmPullKeys  = 50
	maxSwarmBodyBytes = 1 << 20
)

// maxSwarmPayloadBytes caps one signed payload: a peer asked to
// store megabytes per entry could fill a staging table one
// entry at a time.
const maxSwarmPayloadBytes = 256 * 1024

// maxSwarmHistoryDays caps one history entry: a year of daily
// rows plus slack, never an unbounded table dump.
const maxSwarmHistoryDays = 400

// The sealed envelopes. Prefixes, salts and labels are part of
// the format: changing any of them stops every blob opening.
const (
	swarmSeedPrefix    = "sw:v1:"
	swarmSeedSalt      = "evesynapse/swarm-seed/v1"
	swarmSeedInfo      = "swarm entry signing"
	swarmMembersPrefix = "swm:v1:"
	swarmMembersSalt   = "evesynapse/swarm-members/v1"
	swarmMembersInfo   = "swarm member list"
)

// swarmEnvelope is the canonical signed document: struct field
// order makes encoding/json deterministic, so signer and
// verifier hash the same bytes without a canonicalizer.
type swarmEnvelope struct {
	V         int    `json:"v"`
	Kind      string `json:"kind"`
	Key       string `json:"key"`
	Payload   string `json:"payload"`
	FetchedAt int64  `json:"fetched_at"`
	Signer    string `json:"signer"`
}

// swarmSignedEntry is an envelope with its signature, as it
// travels over the swarm API.
type swarmSignedEntry struct {
	Kind      string `json:"kind"`
	Key       string `json:"key"`
	Payload   string `json:"payload"`
	FetchedAt int64  `json:"fetched_at"`
	Signer    string `json:"signer"`
	Signature string `json:"signature"`
}

// swarmMember is one instance as the membership list carries
// it: identity material only, never reputation judgments.
type swarmMember struct {
	InstanceID string `json:"instance_id"`
	BaseURL    string `json:"base_url"`
	PublicKey  string `json:"public_key"`
	// URLSig is the member's own signature over its ID, address
	// and IssuedAt (swarmMemberMessage), made with the key beside
	// it. A tuple is relayed exactly as its owner issued it.
	// IssuedAt is the owner's unix clock when it signed: of two
	// tuples for one member the later-issued is the current one.
	URLSig   string `json:"url_sig"`
	IssuedAt int64  `json:"issued_at"`
}

// swarmMemberMessage is what a member signs to own its address:
// "member\n" + instance ID + "\n" + base URL + "\n" + the unix
// time it was issued, in decimal. Byte-for-byte the main
// instance's function of the same name.
func swarmMemberMessage(instanceID, baseURL string, issuedAt int64) []byte {
	return []byte("member\n" + instanceID + "\n" + baseURL + "\n" + strconv.FormatInt(issuedAt, 10))
}

// signSwarmMember signs this node's own address as of issuedAt.
func signSwarmMember(id *swarmIdentity, baseURL string, issuedAt int64) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(id.private, swarmMemberMessage(id.id, baseURL, issuedAt)))
}

// verifySwarmMember checks a tuple's address signature against
// the public key in the same tuple.
func verifySwarmMember(m swarmMember) bool {
	pub, err := base64.StdEncoding.DecodeString(m.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(m.URLSig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, swarmMemberMessage(m.InstanceID, m.BaseURL, m.IssuedAt), sig)
}

// swarmPullRequest is one pull: the keys the caller wants.
type swarmPullRequest struct {
	Keys []swarmPullKey `json:"keys"`
}

// swarmPullKey names one public record.
type swarmPullKey struct {
	Kind string `json:"kind"`
	Key  string `json:"key"`
}

// seedAnnouncePayload is what a seed heartbeat seals: where to
// dial, the key the signature already proved, and the sender's
// own signature over its address. Together they are the member
// tuple the receiver stores and relays verbatim.
type seedAnnouncePayload struct {
	BaseURL   string `json:"base_url"`
	PublicKey string `json:"public_key"`
	URLSig    string `json:"url_sig"`
	IssuedAt  int64  `json:"issued_at"`
}

// The payload schemas, copied from the main instance's
// swarm_share.go. Receivers strictly decode into these shapes
// and bind the IDs inside to the signed key.
type swarmHistoryPayload struct {
	RegionID int64             `json:"region_id"`
	TypeID   int64             `json:"type_id"`
	Days     []swarmHistoryDay `json:"days"`
}

type swarmHistoryDay struct {
	Date       string  `json:"date"`
	Average    float64 `json:"average"`
	Highest    float64 `json:"highest"`
	Lowest     float64 `json:"lowest"`
	Volume     int64   `json:"volume"`
	OrderCount int64   `json:"order_count"`
}

type swarmTypeNamePayload struct {
	TypeID int64  `json:"type_id"`
	Name   string `json:"name"`
}

type swarmOrgPayload struct {
	ID      int64  `json:"id"`
	Payload string `json:"payload"`
}

type swarmStructurePayload struct {
	StructureID int64  `json:"structure_id"`
	Name        string `json:"name"`
}

// swarmIdentity is this node: its ID and its signing key.
type swarmIdentity struct {
	id      string
	public  ed25519.PublicKey
	private ed25519.PrivateKey
}

// publicString is the key as it travels in membership lists.
func (id *swarmIdentity) publicString() string {
	return base64.StdEncoding.EncodeToString(id.public)
}

// mintSwarmIdentity generates one fresh instance ID and keypair.
func mintSwarmIdentity() (*swarmIdentity, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return nil, fmt.Errorf("swarm: mint identity: %w", err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("swarm: mint identity: %w", err)
	}
	return &swarmIdentity{
		id:      base64.RawURLEncoding.EncodeToString(raw[:]),
		public:  pub,
		private: priv,
	}, nil
}

// gcmForKey opens AES-256-GCM under a 32-byte key.
func gcmForKey(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// sealSwarmSeed seals an Ed25519 seed under the shared secret.
func sealSwarmSeed(seed []byte, secret string) (string, error) {
	key, err := hkdf.Key(sha256.New, []byte(secret), []byte(swarmSeedSalt), swarmSeedInfo, 32)
	if err != nil {
		return "", err
	}
	aead, err := gcmForKey(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("swarm: seal seed: %w", err)
	}
	sealed := aead.Seal(nonce, nonce, seed, nil)
	return swarmSeedPrefix + base64.StdEncoding.EncodeToString(sealed), nil
}

// unsealSwarmSeed opens a sealed seed. Any failure is one
// error: callers must not learn whether the prefix, the
// encoding, the secret, or the key was wrong.
func unsealSwarmSeed(sealed, secret string) ([]byte, error) {
	rest, ok := strings.CutPrefix(sealed, swarmSeedPrefix)
	if !ok {
		return nil, errors.New("swarm: sealed seed does not open")
	}
	raw, err := base64.StdEncoding.DecodeString(rest)
	if err != nil {
		return nil, errors.New("swarm: sealed seed does not open")
	}
	key, err := hkdf.Key(sha256.New, []byte(secret), []byte(swarmSeedSalt), swarmSeedInfo, 32)
	if err != nil {
		return nil, errors.New("swarm: sealed seed does not open")
	}
	aead, err := gcmForKey(key)
	if err != nil {
		return nil, errors.New("swarm: sealed seed does not open")
	}
	if len(raw) < aead.NonceSize() {
		return nil, errors.New("swarm: sealed seed does not open")
	}
	seed, err := aead.Open(nil, raw[:aead.NonceSize()], raw[aead.NonceSize():], nil)
	if err != nil {
		return nil, errors.New("swarm: sealed seed does not open")
	}
	return seed, nil
}

// openSwarmIdentity unseals a stored identity. ok is false on
// any failure: a wrong key, a wrong secret, or a malformed
// record all refuse identically.
func openSwarmIdentity(instanceID, publicKey, sealed, secret string) (id *swarmIdentity, ok bool) {
	if instanceID == "" {
		return nil, false
	}
	pub, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, false
	}
	seed, err := unsealSwarmSeed(sealed, secret)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, false
	}
	priv := ed25519.NewKeyFromSeed(seed)
	if !ed25519.PublicKey(pub).Equal(priv.Public()) {
		return nil, false
	}
	return &swarmIdentity{id: instanceID, public: pub, private: priv}, true
}

// sealSwarmMembers seals one marshalled member list under the
// shared secret. The signature still goes over the sealed blob
// (encrypt-then-sign): authenticity is checked before anything
// decrypts.
func sealSwarmMembers(raw []byte, secret string) (string, error) {
	key, err := hkdf.Key(sha256.New, []byte(secret), []byte(swarmMembersSalt), swarmMembersInfo, 32)
	if err != nil {
		return "", err
	}
	aead, err := gcmForKey(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("swarm: seal members: %w", err)
	}
	sealed := aead.Seal(nonce, nonce, raw, nil)
	return swarmMembersPrefix + base64.StdEncoding.EncodeToString(sealed), nil
}

// openSwarmMembers opens a sealed member list. Any failure is
// one error.
func openSwarmMembers(sealed, secret string) ([]byte, error) {
	rest, ok := strings.CutPrefix(sealed, swarmMembersPrefix)
	if !ok {
		return nil, errors.New("swarm: member list does not open")
	}
	raw, err := base64.StdEncoding.DecodeString(rest)
	if err != nil {
		return nil, errors.New("swarm: member list does not open")
	}
	key, err := hkdf.Key(sha256.New, []byte(secret), []byte(swarmMembersSalt), swarmMembersInfo, 32)
	if err != nil {
		return nil, errors.New("swarm: member list does not open")
	}
	aead, err := gcmForKey(key)
	if err != nil {
		return nil, errors.New("swarm: member list does not open")
	}
	if len(raw) < aead.NonceSize() {
		return nil, errors.New("swarm: member list does not open")
	}
	opened, err := aead.Open(nil, raw[:aead.NonceSize()], raw[aead.NonceSize():], nil)
	if err != nil {
		return nil, errors.New("swarm: member list does not open")
	}
	return opened, nil
}

// signSwarmEntry signs one entry.
func signSwarmEntry(id *swarmIdentity, instanceID, kind, key, payload string, fetchedAt time.Time) (swarmSignedEntry, error) {
	entry := swarmSignedEntry{Kind: kind, Key: key, Payload: payload, FetchedAt: fetchedAt.UTC().Unix(), Signer: instanceID}
	if len(payload) > maxSwarmPayloadBytes {
		return swarmSignedEntry{}, fmt.Errorf("swarm: sign %s %s: payload %d bytes exceeds %d", kind, key, len(payload), maxSwarmPayloadBytes)
	}
	doc, err := json.Marshal(swarmEnvelope{V: 1, Kind: kind, Key: key, Payload: payload, FetchedAt: entry.FetchedAt, Signer: instanceID})
	if err != nil {
		return swarmSignedEntry{}, fmt.Errorf("swarm: sign %s %s: %w", kind, key, err)
	}
	entry.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(id.private, doc))
	return entry, nil
}

// verifySwarmEntry checks one entry against the signer's pinned
// public key. Every field the entry carries is covered; every
// failure is false, with no reason given.
func verifySwarmEntry(entry swarmSignedEntry, publicKey string) bool {
	if entry.Kind == "" || entry.Key == "" || entry.Signer == "" {
		return false
	}
	if len(entry.Payload) > maxSwarmPayloadBytes {
		return false
	}
	pub, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(entry.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	doc, err := json.Marshal(swarmEnvelope{V: 1, Kind: entry.Kind, Key: entry.Key, Payload: entry.Payload, FetchedAt: entry.FetchedAt, Signer: entry.Signer})
	if err != nil {
		return false
	}
	return ed25519.Verify(pub, doc, sig)
}

// swarmPullMessage is what a puller signs to authenticate one
// pull request: "pull\n" + instance ID + "\n" + the unix
// timestamp in decimal + "\n" + the lowercase hex SHA-256 of
// the exact request body bytes. Hashing the body binds the
// signature to this one request — a captured signature cannot
// be replayed over a different key list — and the timestamp
// bounds replay of the identical request to the freshness
// window the server enforces. Byte-for-byte the main
// instance's function of the same name: both sides must build
// identical bytes or every signed pull fails verification.
func swarmPullMessage(instanceID string, timestamp int64, body []byte) []byte {
	sum := sha256.Sum256(body)
	return []byte("pull\n" + instanceID + "\n" + strconv.FormatInt(timestamp, 10) + "\n" + hex.EncodeToString(sum[:]))
}

// verifySwarmPull checks one pull signature against the
// claimed instance's directory key. Every failure is false,
// with no reason given: a bad encoding, a wrong-sized key or
// signature, and a signature that does not verify are the same
// answer to the caller (the server falls back to the bearer).
func verifySwarmPull(publicKey, instanceID string, timestamp int64, body []byte, signature string) bool {
	pub, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, swarmPullMessage(instanceID, timestamp, body), sig)
}

// swarmAuth checks the request's Bearer against the shared
// secret. Hashes are compared (not the secret itself) so a
// length difference leaks nothing, in constant time so a prefix
// match learns nothing. False on any failure, with no reason.
func swarmAuth(secret string, r *http.Request) bool {
	if secret == "" {
		return false
	}
	present, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || present == "" {
		return false
	}
	want := sha256.Sum256([]byte(secret))
	got := sha256.Sum256([]byte(strings.TrimSpace(present)))
	return subtle.ConstantTimeCompare(want[:], got[:]) == 1
}

// validPullKey reports whether one requested key may be served:
// a carried kind, a non-empty key, nothing overlong.
func validPullKey(kind, key string) bool {
	return validSwarmKind(kind) && key != "" && len(key) <= 128
}

// parseSwarmID reads one positive EVE ID from a key part.
// Malformed IDs refuse; a shared key must name its entity.
func parseSwarmID(part string) (int64, bool) {
	if strings.IndexFunc(part, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
		return 0, false
	}
	id, err := strconv.ParseInt(part, 10, 64)
	if err != nil || id <= 0 {
		return 0, false
	}
	return id, true
}

// swarmURL is a parsed peer URL: scheme and host only, so
// validation never depends on paths or query strings.
type swarmURL struct {
	scheme string
	host   string
}

// parseSwarmURL parses a peer URL strictly: a scheme, a host,
// nothing else trusted.
func parseSwarmURL(raw string) (swarmURL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || u.Scheme == "" {
		return swarmURL{}, fmt.Errorf("not a URL")
	}
	return swarmURL{scheme: strings.ToLower(u.Scheme), host: u.Hostname()}, nil
}

// swarmHostIsLoopback reports whether a host is loopback.
func swarmHostIsLoopback(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// validSwarmBaseURL reports whether a URL may be dialed: https
// anywhere, http on loopback only.
func validSwarmBaseURL(raw string) bool {
	u, err := parseSwarmURL(raw)
	if err != nil {
		return false
	}
	switch u.scheme {
	case "https":
		return true
	case "http":
		return swarmHostIsLoopback(u.host)
	default:
		return false
	}
}

// readSwarmJSON strictly decodes one size-capped request body.
// Unknown fields reject the request: the wire format is fixed,
// and anything else is a probe or a version skew to notice.
func readSwarmJSON(r *http.Request, into any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, maxSwarmBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return err
	}
	return nil
}

// writeSwarmJSON writes one response envelope.
func writeSwarmJSON(w http.ResponseWriter, body any) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(body); err != nil {
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = buf.WriteTo(w)
}
