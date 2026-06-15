# goblin-nip05d

A self-hostable **NIP-05 name authority**: it maps `name@yourdomain` to a nostr
public key, with NIP-98-authenticated self-service registration. Anyone can run
their own instance to issue `name@yourdomain` identities — the Goblin wallet's
`goblin.st` is just one operator. It pairs with a nostr relay (which the bundled
Docker Compose file runs for you), but the relay is a separate service; this
binary only *advertises* it in the NIP-05 response.

It stores names and pubkeys only — **no avatars**. Clients render an identity
picture deterministically from the pubkey, so there is nothing to upload, host,
or moderate here.

## How it works

- **NIP-05** ([spec](https://github.com/nostr-protocol/nips/blob/master/05.md)):
  clients resolve `name@yourdomain` by fetching
  `https://yourdomain/.well-known/nostr.json?name=<name>`, which returns the
  pubkey and the relays to find that user on.
- **NIP-98** ([spec](https://github.com/nostr-protocol/nips/blob/master/98.md)):
  every write (register, release, transfer) is authorized by a signed
  nostr event in the `Authorization: Nostr <base64-event>` header. **Ownership
  is your nostr key** — whoever holds the secret key controls the name. There
  are no passwords and no accounts.

## Security model

- **Cryptographic ownership, no recovery.** A name is bound to a nostr pubkey.
  Control of the name is control of the key. There is no password reset and no
  operator override: **lose the key, lose the name.** The operator cannot
  recover or reassign it for you.
- **Anti-squatting, tied to your domain.** A built-in reserved list blocks
  generic sensitive handles (`admin`, `support`, `wallet`, `relay`, …), and the
  operator's **own domain labels are reserved automatically** — `goblin.st`
  reserves `goblin`, `acme.example` reserves `acme` — so nobody can claim the
  brand the domain stands for. **Look-alike folding** stops digit/separator
  homographs: `supp0rt`, `g0blin` and `g-o-b-l-i-n` all fold onto a reserved
  term and are rejected, while genuine names like `goblinfan` stay free.
  Operators can extend the list via `GOBLIN_RESERVED_FILE`.
- **One active name per key.** Enforced at the database layer by a partial
  unique index, so the check-then-insert race app code alone can't close is
  closed for good.
- **No PII, nothing private.** The service stores only public data: names and
  pubkeys. It holds **no secrets** — a host compromise leaks only data that is
  already public, and cannot forge a registration (that needs the user's key).
- **TLS is the operator's job, and the proxy MUST set `X-Real-IP`.** All per-IP
  rate limiting keys off the `X-Real-IP` header. If your reverse proxy does not
  set it from the real client address, every request looks like one client and
  the limiter is defeated. The provided proxy configs set it and call this out.
- **Replay protection resets on restart.** NIP-98 events are single-use within
  the freshness window, tracked in memory; a restart clears that set (and the
  release cooldown), which only re-opens a ≤60s window for already-signed events.

## Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/.well-known/nostr.json?name=<name>` | — | NIP-05 resolution (CORS `*`) |
| GET | `/api/v1/name/{name}` | — | availability: `{name, available, reason?}` |
| POST | `/api/v1/register` `{name, pubkey}` | NIP-98 | register a name (one per pubkey) |
| DELETE | `/api/v1/register/{name}` | NIP-98 (owner) | release a name |
| POST | `/api/v1/transfer` `{name, new_pubkey}` | NIP-98 (owner) | re-point a name to a new key (for key rotation) |
| GET | `/api/v1/profile/{name}` | — | public profile: `{name, pubkey}` |
| GET | `/api/v1/health` | — | liveness (`ok`) |
| GET | `/` | — | landing page |

Rules: names match `^[a-z0-9._-]{3,20}$`, start/end alphanumeric, lowercase, with
the reserved list enforced. A released name is immediately available for anyone
to register — **releasing is permanent, not a hold.** Releasing a name arms a
cooldown (default 10 min) that blocks *re-registering* a new name (anti-churn);
claiming a name is always free and never blocks an immediate release. NIP-98 auth
events must be kind `27235`, ≤60s old, with matching `u`/`method` tags and (for
bodies) a `payload` sha256 tag.

## Configuration

All configuration is environment variables (see `.env.example` for a copy you can
edit). Defaults reproduce the original `goblin.st` deployment.

| Variable | Default | Meaning |
|---|---|---|
| `GOBLIN_DOMAIN` | `goblin.st` | bare host for names (the `@domain` part) |
| `GOBLIN_BASE_URL` | `https://goblin.st` | public base URL — **load-bearing** (see warning) |
| `GOBLIN_RELAYS` | `wss://nrelay.us-ea.st` | comma-separated relays advertised in NIP-05 |
| `NIP05_BIND` | `127.0.0.1:8191` | listen address |
| `NIP05_DB` | `/opt/goblin/nip05d/nip05.db` | SQLite path |
| `GOBLIN_NAME_CHANGE_COOLDOWN_SECS` | `600` | re-register cooldown after a release |
| `GOBLIN_AUTH_MAX_AGE_SECS` | `60` | max age of a NIP-98 auth event |
| `GOBLIN_NAME_MIN` / `GOBLIN_NAME_MAX` | `3` / `20` | name length bounds (chars) |
| `GOBLIN_READ_RATE_MAX` / `GOBLIN_READ_RATE_WINDOW_SECS` | `120` / `60` | read rate limit per IP |
| `GOBLIN_WRITE_RATE_MAX` / `GOBLIN_WRITE_RATE_WINDOW_SECS` | `10` / `3600` | write rate limit per IP |
| `GOBLIN_RESERVED_FILE` | _(unset)_ | optional file of extra reserved names (one per line) |

> **⚠️ `GOBLIN_BASE_URL` and `GOBLIN_DOMAIN` must match the public host clients
> actually reach.** NIP-98 verification rebuilds the expected `u`-tag from
> `GOBLIN_BASE_URL`; if it doesn't match what the client signed, **every
> authenticated call fails**. The host of `GOBLIN_BASE_URL` must equal
> `GOBLIN_DOMAIN` (a port is allowed) — the service validates this and refuses
> to start otherwise.

## Deployment

Three supported paths. Whichever you pick, put TLS termination in front and make
the proxy set `X-Real-IP` (see the security model).

### 1. Docker Compose (recommended)

Brings up the name authority, a `nostr-rs-relay`, and a Caddy reverse proxy with
automatic HTTPS — a complete authority + relay in one command.

```sh
cp .env.example .env
# Edit .env: set GOBLIN_DOMAIN, GOBLIN_BASE_URL (https://yourdomain),
# and GOBLIN_RELAYS (e.g. wss://yourdomain).
# Point DNS for yourdomain at this host FIRST so Caddy can get a certificate.
docker compose up -d
```

The relay config lives in `deploy/relay-config.toml` (kinds `0,3,5,1059,10002,10050`,
64 KiB event cap). The Caddy config is `deploy/Caddyfile`.

### 2. systemd + reverse proxy (bare metal)

```sh
./scripts/setup.sh         # builds, installs binary + hardened unit + env file
sudo nano /etc/goblin-nip05d.env   # set your domain
sudo systemctl restart goblin-nip05d
```

Then put a TLS-terminating proxy in front — see `deploy/Caddyfile` or
`deploy/nginx.conf.example` (both set `X-Real-IP` and route `/.well-known/...`
and `/api/` to the authority, websocket to the relay). The systemd unit
(`deploy/goblin-nip05d.service`) runs under `DynamicUser` with
`ProtectSystem=strict`, `NoNewPrivileges`, `PrivateTmp`, and a single
`ReadWritePaths` for its state directory.

### 3. Bare `cargo run` (local development)

```sh
GOBLIN_DOMAIN=localhost GOBLIN_BASE_URL=https://localhost \
NIP05_DB=/tmp/nip05.db NIP05_BIND=127.0.0.1:8085 cargo run
# a local relay for wallet dev:
docker run -d --name dev-relay -p 8088:8080 scsibug/nostr-rs-relay:latest
```

Note: `GOBLIN_BASE_URL` is what NIP-98 `u`-tags are checked against, so sign your
test auth events with the same value you set here.

## Run your own name authority

1. **Fork** this repo (or just clone it — no source changes are required).
2. **Set your domain.** Copy `.env.example` to `.env` and set `GOBLIN_DOMAIN`,
   `GOBLIN_BASE_URL=https://yourdomain`, and `GOBLIN_RELAYS=wss://yourdomain`
   (or whatever relay you advertise).
3. **Point DNS** for `yourdomain` (an `A`/`AAAA` record) at your host so the
   proxy can obtain a TLS certificate.
4. **Bring it up:** `docker compose up -d`.

You now serve `name@yourdomain` identities and a relay, independent of any other
operator — exactly the redundancy a community wants.

## Development

```sh
cargo test                      # unit + HTTP integration tests
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
```

The crate is a small module tree (`config`, `db`, `auth`, `ratelimit`, `names`,
`handlers/`). Integration tests build the same
router the binary serves via `handlers::routes(App::open(...))` with an in-memory
database, so the full HTTP surface is exercised with real signed NIP-98 events.

## License

Apache-2.0. See [LICENSE](LICENSE).

🤖 Built with AI pair-programming assistance (Claude).
