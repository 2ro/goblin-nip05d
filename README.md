# goblin-nip05d

NIP-05 identity service for the Goblin wallet, serving `goblin.st`.

## Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/.well-known/nostr.json?name=<name>` | — | NIP-05 resolution (CORS `*`) |
| GET | `/api/v1/name/{name}` | — | availability: `{name, available, reason?}` |
| POST | `/api/v1/register` `{name, pubkey}` | NIP-98 | register a name (one per pubkey) |
| DELETE | `/api/v1/register/{name}` | NIP-98 (owner) | release a name |
| GET | `/api/v1/health` | — | liveness |

Rules: names `^[a-z0-9._-]{3,30}$` starting/ending alphanumeric, lowercase, reserved list
enforced, one active name per pubkey. A released name is immediately available for anyone to
register — releasing is permanent, not a hold, so don't release a name you want to keep. Name
changes (register or release) are limited to one per pubkey per 10 minutes. NIP-98 auth events
must be kind 27235, ≤60s old, with matching `u`/`method` tags and (for bodies) a `payload`
sha256 tag. Per-IP rate limits on registration.

## Deployment

Build with `cargo build --release` and run the binary as an unprivileged user behind a
TLS-terminating reverse proxy, listening on loopback only. Configure via environment:
`NIP05_DB` (sqlite path) and `NIP05_BIND` (listen address). Per-IP rate limiting reads
`X-Real-IP`, which the reverse proxy must set.

## Local development

```sh
NIP05_DB=/tmp/nip05.db NIP05_BIND=127.0.0.1:8085 cargo run
# local relay for wallet dev:
docker run -d --name dev-relay -p 8088:8080 scsibug/nostr-rs-relay:latest
```

Point the wallet's dev config at `http://127.0.0.1:8085` (NIP-05) and `ws://127.0.0.1:8088` (relay).
Note: `BASE_URL` is compile-time `https://goblin.st`; NIP-98 `u`-tag checks use it, so for local
registration tests either patch `BASE_URL` or sign auth events with the production URL.
