// Runtime configuration. Everything that identifies a particular operator's
// name authority lives here and is read from the environment at startup, so a
// second operator can run their own authority without touching the source.
//
// The defaults reproduce the original goblin.st deployment, so an existing
// install keeps working with no env set.

use std::time::Duration;

/// Resolved, validated runtime configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// Bare host the names live under, e.g. `goblin.st` (the `@domain` part of
    /// `name@domain`).
    pub domain: String,
    /// Public base URL, e.g. `https://goblin.st`. Load-bearing: NIP-98 `u`-tag
    /// verification builds the expected URL from this, so it MUST equal the
    /// scheme+host clients actually reach, or all authenticated calls fail.
    pub base_url: String,
    /// Relays advertised in `/.well-known/nostr.json` `relays` map.
    pub relays: Vec<String>,
    /// Address the HTTP server binds (loopback by default; sit behind a proxy).
    pub bind_addr: String,
    /// SQLite database path.
    pub db_path: String,

    /// After releasing a name, how long a pubkey must wait before claiming a
    /// new one (anti-churn brake).
    pub name_change_cooldown: Duration,
    /// Max age (seconds) of an accepted NIP-98 auth event.
    pub auth_max_age_secs: i64,
    /// Minimum/maximum name length in characters.
    pub name_min: usize,
    pub name_max: usize,

    /// Read endpoints: requests per IP per `read_window`.
    pub read_rate_max: usize,
    pub read_rate_window: Duration,
    /// Write endpoints (register/unregister): per IP per `write_window`.
    pub write_rate_max: usize,
    pub write_rate_window: Duration,

    /// Additional reserved names: the operator's own domain labels (so the
    /// brand a domain represents can't be impersonated) plus any names from
    /// an optional `GOBLIN_RESERVED_FILE`. Extends the built-in generic list.
    pub extra_reserved: Vec<String>,
}

fn env_string(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn env_parse<T: std::str::FromStr>(key: &str, default: T) -> T {
    match std::env::var(key) {
        Ok(v) => v.parse().unwrap_or(default),
        Err(_) => default,
    }
}

impl Config {
    /// Load from the environment, applying the goblin.st defaults, then
    /// validate. Returns an error string on misconfiguration (caller should
    /// fail fast).
    pub fn from_env() -> Result<Self, String> {
        let domain = env_string("GOBLIN_DOMAIN", "goblin.st");
        let base_url = env_string("GOBLIN_BASE_URL", "https://goblin.st");
        let relays = env_string("GOBLIN_RELAYS", "wss://relay.goblin.st")
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>();
        let bind_addr = env_string("NIP05_BIND", "127.0.0.1:8191");
        let db_path = env_string("NIP05_DB", "/opt/goblin/nip05d/nip05.db");

        let name_change_cooldown =
            Duration::from_secs(env_parse("GOBLIN_NAME_CHANGE_COOLDOWN_SECS", 600u64));
        let auth_max_age_secs = env_parse("GOBLIN_AUTH_MAX_AGE_SECS", 60i64);
        let name_min = env_parse("GOBLIN_NAME_MIN", 3usize);
        let name_max = env_parse("GOBLIN_NAME_MAX", 20usize);

        let read_rate_max = env_parse("GOBLIN_READ_RATE_MAX", 120usize);
        let read_rate_window =
            Duration::from_secs(env_parse("GOBLIN_READ_RATE_WINDOW_SECS", 60u64));
        let write_rate_max = env_parse("GOBLIN_WRITE_RATE_MAX", 10usize);
        let write_rate_window =
            Duration::from_secs(env_parse("GOBLIN_WRITE_RATE_WINDOW_SECS", 3600u64));

        // Reserve the operator's own domain labels (e.g. `goblin` for
        // `goblin.st`, `acme` for `acme.example`) so the brand the domain
        // stands for can't be claimed or look-alike-folded into. Then layer on
        // any names from the optional reserved file.
        let mut extra_reserved = crate::names::domain_reserved(&domain);
        if let Ok(path) = std::env::var("GOBLIN_RESERVED_FILE") {
            if !path.is_empty() {
                extra_reserved.extend(load_reserved_file(&path)?);
            }
        }

        let cfg = Config {
            domain,
            base_url,
            relays,
            bind_addr,
            db_path,
            name_change_cooldown,
            auth_max_age_secs,
            name_min,
            name_max,
            read_rate_max,
            read_rate_window,
            write_rate_max,
            write_rate_window,
            extra_reserved,
        };
        cfg.validate()?;
        Ok(cfg)
    }

    /// Fail-fast consistency checks. A wrong BASE_URL silently breaks every
    /// authenticated call (the `u`-tag never matches), so we refuse to start.
    fn validate(&self) -> Result<(), String> {
        if self.domain.is_empty() {
            return Err("GOBLIN_DOMAIN must not be empty".into());
        }
        let host = self.base_url.strip_prefix("https://").ok_or_else(|| {
            format!(
                "GOBLIN_BASE_URL must start with https:// (got `{}`)",
                self.base_url
            )
        })?;
        if host.is_empty() {
            return Err("GOBLIN_BASE_URL has no host".into());
        }
        // The host part of BASE_URL must match DOMAIN (allowing an explicit
        // port), otherwise the `@domain` names and the auth URL disagree.
        let host_no_port = host.split('/').next().unwrap_or(host);
        let host_bare = host_no_port.split(':').next().unwrap_or(host_no_port);
        if host_bare != self.domain {
            return Err(format!(
                "GOBLIN_BASE_URL host `{host_bare}` does not match GOBLIN_DOMAIN `{}`",
                self.domain
            ));
        }
        if self.name_min == 0 || self.name_min > self.name_max {
            return Err(format!(
                "invalid name length bounds: min={} max={}",
                self.name_min, self.name_max
            ));
        }
        Ok(())
    }

    /// One-line summary for the startup log (no secrets are involved here —
    /// the service holds none).
    pub fn summary(&self) -> String {
        format!(
            "domain={} base_url={} relays={:?} bind={} db={} \
             name_len={}..={} cooldown={}s auth_max_age={}s \
             read={}req/{}s write={}req/{}s reserved_extra={}",
            self.domain,
            self.base_url,
            self.relays,
            self.bind_addr,
            self.db_path,
            self.name_min,
            self.name_max,
            self.name_change_cooldown.as_secs(),
            self.auth_max_age_secs,
            self.read_rate_max,
            self.read_rate_window.as_secs(),
            self.write_rate_max,
            self.write_rate_window.as_secs(),
            self.extra_reserved.len(),
        )
    }
}

/// Read an optional reserved-names file: one lowercase name per line, blank
/// lines and `#` comments ignored. Missing file is a hard error (the operator
/// asked for it via env), but the names themselves are not validated here.
fn load_reserved_file(path: &str) -> Result<Vec<String>, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("GOBLIN_RESERVED_FILE `{path}` unreadable: {e}"))?;
    Ok(text
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_lowercase())
        .collect())
}

impl Config {
    /// A minimal config for tests/integration, pointing at in-memory state.
    /// Kept out of the public docs but available to integration tests (which
    /// compile as a separate crate and so can't see `#[cfg(test)]` items).
    #[doc(hidden)]
    pub fn for_test() -> Self {
        Config {
            domain: "goblin.st".into(),
            base_url: "https://goblin.st".into(),
            relays: vec!["wss://relay.goblin.st".into()],
            bind_addr: "127.0.0.1:0".into(),
            db_path: ":memory:".into(),
            name_change_cooldown: Duration::from_secs(600),
            auth_max_age_secs: 60,
            name_min: 3,
            name_max: 20,
            read_rate_max: 100_000,
            read_rate_window: Duration::from_secs(60),
            write_rate_max: 100_000,
            write_rate_window: Duration::from_secs(3600),
            // Mirror from_env: the domain's own label is reserved.
            extra_reserved: crate::names::domain_reserved("goblin.st"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Config {
        Config::for_test()
    }

    #[test]
    fn rejects_non_https_base_url() {
        let mut c = base();
        c.base_url = "http://goblin.st".into();
        assert!(c.validate().is_err());
    }

    #[test]
    fn rejects_base_url_domain_mismatch() {
        let mut c = base();
        c.base_url = "https://example.com".into();
        assert!(c.validate().is_err());
    }

    #[test]
    fn accepts_matching_base_url_with_port() {
        let mut c = base();
        c.domain = "names.example".into();
        c.base_url = "https://names.example:8443".into();
        assert!(c.validate().is_ok());
    }

    #[test]
    fn rejects_bad_name_bounds() {
        let mut c = base();
        c.name_min = 10;
        c.name_max = 5;
        assert!(c.validate().is_err());
    }
}
