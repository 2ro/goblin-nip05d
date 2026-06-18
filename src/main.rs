// goblin-nip05d — a self-hostable NIP-05 name authority for the Goblin wallet
// and any community that wants its own `name@domain` identities.
//
// Endpoints (see README for the full table):
//   GET    /.well-known/nostr.json?name=<name>   NIP-05 resolution (CORS *)
//   GET    /api/v1/name/{name}                   availability check
//   POST   /api/v1/register                      {name, pubkey} + NIP-98 auth
//   DELETE /api/v1/register/{name}               NIP-98 auth by owner
//   GET    /api/v1/profile/{name}                public profile (pubkey)
//   GET    /api/v1/health                        liveness
//   GET    /                                     landing page

use goblin_nip05d::{handlers, App, Config};
use std::sync::Arc;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cfg = match Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("configuration error: {e}");
            eprintln!("configuration error: {e}");
            std::process::exit(1);
        }
    };
    tracing::info!("resolved config: {}", cfg.summary());

    let bind = cfg.bind_addr.clone();
    let app = Arc::new(App::open(cfg));
    let router = handlers::routes(app);

    let listener = tokio::net::TcpListener::bind(&bind).await.expect("bind");
    tracing::info!("goblin-nip05d listening on {bind}");
    axum::serve(listener, router)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .expect("server");
}
