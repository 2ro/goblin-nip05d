// goblin-nip05d — a self-hostable NIP-05 name authority.
//
// `name@yourdomain` → nostr pubkey, with NIP-98-authenticated self-service
// registration. Avatars are not stored here: clients render them
// deterministically from the pubkey. The relay is a separate service; this
// crate only advertises it in `/.well-known/nostr.json`.
//
// The crate is split so HTTP integration tests can build the same router the
// binary serves: construct an `App` (use `:memory:` for the db), then
// `handlers::routes(app)`.

pub mod auth;
pub mod config;
pub mod db;
pub mod handlers;
pub mod names;
pub mod ratelimit;
pub mod util;

pub use config::Config;
pub use db::App;
pub use handlers::routes;
