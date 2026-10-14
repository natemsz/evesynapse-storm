# EveSynapseStorm Swarm Cache Worker

A standalone node that mirrors public ESI data and serves it to the
EveSynapse swarm. Same wire protocol as the main instance
(`internal/app/swarm_identity.go`, `swarm_api.go`, `swarm_share.go`
in the main repo) — entry format, signing, verification, the sealed
member list, the pull endpoint, auth, and size caps match
byte-for-byte, or the main instance rejects every entry.

The main instance **pulls** from this node through the existing
swarm protocol. This node is a source, never a puller: it holds no
peer list, dials no peer, stages no entries, and serves only what
its own ESI polling warmed. Its sole outbound call besides ESI is
the seed heartbeat. It holds no credentials: no SSO, no client
secret, no token key, no character or corporation logic.

## What it warms

Across all five hub regions (The Forge, Domain, Heimatar,
Metropolis, Sinq Laison), in a loop:

| Dataset | Source | Swarm kind |
|---|---|---|
| Market history per (region, type) with orders | `GET /markets/{region}/history/` | `market_history` |
| Type names for every seen type | `POST /universe/names/` | `type_name` |
| Corporation / alliance records, on first demand | `GET /corporations/{id}/`, `/alliances/{id}/` | `corporation_record`, `alliance_record` |
| Order books per region | `GET /markets/{region}/orders/` | — (polled for the type universe and persisted; no wire kind exists yet) |

Player structure names are never fetched: that endpoint needs a
token, and this node holds none by design. The main instance keeps
serving those itself.

Beyond the routine sweep, a pull is also demand: when a peer asks
for a key of a covered kind (`market_history`, `type_name`,
`corporation_record`, `alliance_record`) and this node misses, the
key queues, the next poll pass fetches it before routine warming
(at most 100 per pass, a failed key backing off an hour), and a
later pull serves it. A key nobody asks for again within a day is
dropped unfetched.

Everything persists in one SQLite file. A restart reopens warm —
nothing refetches while its `Expires` (or the 20-hour history
gate) holds.

## Run

```sh
go build -o warmer .
cp .env.example .env   # fill in the secrets, then:
set -a; source .env; set +a
./warmer
```

Systemd, Docker, or a plain VM all work: it is one static binary
plus the env file. Point `DB_PATH` and `IDENTITY_PATH` at a volume
you back up — the swarm allowlist pins this node's key, so losing
the identity file means re-allowlisting a fresh key.

## Configuration (environment only)

| Variable | Required | Default | Notes |
|---|---|---|---|
| `SHARED_CACHE_SECRET` | yes | — | The swarm secret, ≥32 chars (`openssl rand -hex 32`). Same value as the main instance. Bearer-gates the API; seals the member list and the identity file. |
| `ESI_CONTACT` | yes | — | Operator contact, sent in every ESI `User-Agent` (`EveSynapse-Warmer/0.1.0 (+https://github.com/natemsz/evesynapse; contact)`). |
| `SWARM_SEED_URL` | no | — | Seed worker URL for discovery heartbeats. Empty means no heartbeat (a main instance can still pull by direct address). |
| `PUBLIC_BASE_URL` | no* | — | The `https` address main instances dial for this node. *Required when `SWARM_SEED_URL` is set (the seed only files `https` records). `http` loopback is allowed for local testing without a seed. |
| `POLL_INTERVAL` | no | `60s` | Loop tick (minimum `10s`). Fetching is cache-driven: a due dataset refreshes when its `Expires` lapses. |
| `BIND_ADDR` | no | `127.0.0.1:8079` | Listen address. Put TLS (or a reverse proxy) in front when the address leaves the box. |
| `DB_PATH` | no | `warmer.db` | SQLite file. Back it up. |
| `IDENTITY_PATH` | no | `warmer-identity.json` | Ed25519 keypair, seed sealed under the shared secret, mode `0600`. Back it up with the database. |

The node refuses to start on a short secret, a missing contact, an
undialable seed URL, or a seed pairing without a public `https`
address.

## Protocol notes (for the main-repo side)

- `GET /swarm/members` returns `{"entry": …}` — a self-signed
  `swarm_members` entry whose payload is the member list sealed
  under the shared secret (`swm:v1:` envelope). The list names
  this node only; gossip files the signer under the dialed URL.
- `POST /swarm/pull` takes `{"keys": [{"kind","key"}]}` (strict
  JSON, ≤50 keys, 1 MiB cap) and returns `{"entries": […]}` —
  never null. Unknown kinds and unheld keys are skipped
  silently. Entries are signed at serve time over the row's own
  fetch time. A miss on a covered kind queues the key as demand;
  the response does not change.
- `GET /swarm/warms` returns `{"kinds": [...]}` and nothing else
  — the kinds this node fetches on demand, for the main
  instance's swarm-first warming. `structure_name` is never
  listed. Older nodes answer 404, read as covering nothing.
- `POST /swarm/seed/register` files one heartbeat, mirroring the
  Cloudflare seed worker (same shapes, same status codes): a
  self-signed `announce` entry whose payload names an `https`
  address and a public key. Listings live 48 hours, a thousand
  store, five hundred serve — after that this node doubles as
  the directory instances discover each other through.
- Every entry envelope is `{v:1, kind, key, payload, fetched_at,
  signer}` as canonical `encoding/json` (struct order, HTML
  escaping); the signature is standard Ed25519, base64.
- The seed heartbeat posts `{"entry": …}` (`kind: "announce"`,
  key and signer the node id) to
  `{seed}/swarm/seed/register`, every 12 h and on first boot.

## ESI etiquette

One sequential pass, bounded pages (a lying `X-Pages` never
balloons the sweep), per-URL `Expires` persisted in SQLite and
never fetched against while fresh, the `X-Esi-Error-Limit`
budget tracked with a hold before it runs out, `420/429`
ending the pass with the `Retry-After` hold (never retried),
transport/5xx retried twice. History refreshes past a 20-hour
gate, at most 100 pairs per tick, so a cold start ramps
gradually.

## Dependencies

Standard library, plus one: `modernc.org/sqlite` (pure Go, no
cgo toolchain needed) — the SQLite requirement forces a driver,
and the pure-Go one keeps the build a single static binary.
Routing is the standard `ServeMux`; no router dependency.

## Install

Grab the latest release for your architecture (arm64 and amd64 available) or compile from source. Move the .tar.gz to your box, unpack, and run setup.sh. After that, follow the instructions to set up your .env properly and start the service.

## Development

```sh
go vet ./...
go test ./... -count=1
```

(`go test -race` needs a C compiler; run it in CI.)
