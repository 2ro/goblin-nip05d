# Goblin relay = stock strfry + this spec

The Goblin relay is **[strfry](https://github.com/hoytech/strfry), unmodified.**
We do **not** fork it, patch its source, or vendor a copy into this repo. The
`Dockerfile` here clones strfry fresh from upstream at a pinned commit and
compiles it **untouched**; everything Goblin-specific lives in two small files
that use strfry's **own** extension points:

| File | What it is | strfry mechanism |
| --- | --- | --- |
| `strfry.conf` | relay config — name, size/limits, NIP-40 expiry, NIP-77 negentropy, and the `writePolicy.plugin` pointer | strfry's native config file |
| `strfry-writepolicy.py` | restricts **stored** event kinds to the wallet's set — everything else is rejected at ingest | strfry's documented [write-policy plugin protocol](https://github.com/hoytech/strfry/blob/master/docs/plugins.md) (one JSON request/reply per line over stdin/stdout) |

That's the entire "Goblin spec." strfry's binary, wire protocol, and **read
path are 100% upstream** — the plugin only governs what gets written, and the
config only tunes documented knobs. Drop these two files onto any strfry build
and you have the Goblin relay; remove them and you have plain strfry.

### Allowed event kinds

The write policy accepts only the kinds the Goblin wallet uses; all others are
rejected at ingest (including events pulled in via negentropy sync):

```
0      profile metadata
3      contact list
5      event deletion (NIP-09)
1059   gift wrap (NIP-59, private payments)
10002  relay list metadata (NIP-65)
10050  preferred DM relays (NIP-17)
```

### Pinned version

```
strfry  github.com/hoytech/strfry
commit  7984f80822189bf8124699f3d49580334b32385e   (== upstream master HEAD, 2026-06-16)
```

The pin lives in the `Dockerfile` `STRFRY_REF` arg (and `apply-goblin-spec.sh`).
To update strfry: set both to a newer upstream commit and rebuild — nothing else
changes, because we never touched strfry's source.

## Running it

**Docker (wired into the compose stack).** From the repo root:

```sh
docker compose up -d relay          # builds this dir, runs on :7777 in the compose net
```

**Fresh strfry clone + apply the spec (no Docker).** `apply-goblin-spec.sh`
clones stock strfry at the pinned commit, builds it untouched, and drops the two
spec files in — proving the "stock strfry + spec" claim end to end:

```sh
./apply-goblin-spec.sh [target-dir]   # default: ./strfry-build
cd <target-dir> && ./strfry relay     # serves the Goblin relay
```

Needs strfry's build deps (a C++ toolchain plus `liblmdb`, `flatbuffers`,
`libsecp256k1`, `libb2`, `zstd`, `libressl`/openssl, `perl`); see strfry's own
[build instructions](https://github.com/hoytech/strfry#compile-strfry). The
Docker path bundles them for you.
