//! Postgres URL helpers for pooled vs direct endpoints.
//!
//! sqlx migrations take a **session-scoped** `pg_advisory_lock`. A
//! transaction-mode pooler (Neon `-pooler`, PgBouncer) can route `LOCK` and
//! `UNLOCK` to different backends, or return a backend to the pool with the
//! lock still held after the client disconnects. The next boot then waits on
//! that lock, inherits a leaked `lock_timeout`, and panics.
//!
//! Migrations must run against the direct compute endpoint. Runtime query
//! pools may keep the pooled URL.

use sqlx::postgres::PgConnectOptions;
use std::borrow::Cow;
use std::str::FromStr;

/// True when `url` points at a transaction-mode pooler hostname.
///
/// Neon names these `*-pooler.*` (e.g. `ep-foo-pooler.c-2.aws.neon.tech`).
pub fn is_transaction_pooler_url(url: &str) -> bool {
    postgres_host(url).is_some_and(|host| host.contains("-pooler."))
}

/// Rewrite a Neon/PgBouncer pooled URL to the direct compute hostname.
///
/// Leaves already-direct URLs, unparseable strings, and unix sockets
/// unchanged. Credentials and query params are preserved.
#[allow(dead_code)]
pub fn direct_postgres_url(url: &str) -> Cow<'_, str> {
    let Ok(mut parsed) = url::Url::parse(url) else {
        return Cow::Borrowed(url);
    };
    let Some(host) = parsed.host_str() else {
        return Cow::Borrowed(url);
    };
    if !host.contains("-pooler.") {
        return Cow::Borrowed(url);
    }
    let direct_host = host.replace("-pooler.", ".");
    if parsed.set_host(Some(&direct_host)).is_err() {
        return Cow::Borrowed(url);
    }
    Cow::Owned(parsed.to_string())
}

pub(crate) fn postgres_host(url: &str) -> Option<String> {
    url::Url::parse(url)
        .ok()
        .and_then(|parsed| parsed.host_str().map(str::to_owned))
}

/// Extract any explicit `search_path` or `currentSchema` schema name from a URL.
pub fn postgres_search_path(raw_url: &str) -> Option<String> {
    let parsed = url::Url::parse(raw_url).ok()?;
    for (key, value) in parsed.query_pairs() {
        if key.eq_ignore_ascii_case("search_path") || key.eq_ignore_ascii_case("currentSchema") {
            let val = value.trim();
            if !val.is_empty() {
                return Some(val.to_ascii_lowercase());
            }
        }
        if key.eq_ignore_ascii_case("options") {
            for part in value.split(&[' ', '&'][..]) {
                let part = part.trim();
                let clean = part.strip_prefix("-c").unwrap_or(part).trim();
                if let Some((opt_k, opt_v)) = clean.split_once('=') {
                    if opt_k.trim().eq_ignore_ascii_case("search_path") {
                        let val = opt_v.trim();
                        if !val.is_empty() {
                            return Some(val.to_ascii_lowercase());
                        }
                    }
                }
            }
        }
    }
    None
}

/// True when two PostgreSQL URLs point to the same database instance and schema.
///
/// Normalizes Neon `-pooler` hostnames to direct endpoints and compares host, port,
/// socket, database, and search_path.
#[allow(dead_code)]
pub fn postgres_urls_share_target(a: &str, b: &str) -> bool {
    let a_trimmed = a.trim();
    let b_trimmed = b.trim();
    if a_trimmed == b_trimmed {
        return true;
    }

    let direct_a = direct_postgres_url(a_trimmed);
    let direct_b = direct_postgres_url(b_trimmed);

    let Ok(opt_a) = PgConnectOptions::from_str(direct_a.as_ref()) else {
        return false;
    };
    let Ok(opt_b) = PgConnectOptions::from_str(direct_b.as_ref()) else {
        return false;
    };

    let host_match = opt_a.get_host().eq_ignore_ascii_case(opt_b.get_host());
    let port_match = opt_a.get_port() == opt_b.get_port();
    let socket_match = opt_a.get_socket() == opt_b.get_socket();
    let db_match = opt_a.get_database().unwrap_or("") == opt_b.get_database().unwrap_or("");

    if !(host_match && port_match && socket_match && db_match) {
        return false;
    }

    let schema_a = postgres_search_path(a_trimmed);
    let schema_b = postgres_search_path(b_trimmed);
    let effective_schema_a = schema_a.as_deref().unwrap_or("public");
    let effective_schema_b = schema_b.as_deref().unwrap_or("public");

    let schemas_a: Vec<&str> = effective_schema_a
        .split(',')
        .map(|s| s.trim().trim_matches('"'))
        .filter(|s| !s.is_empty())
        .collect();
    let schemas_b: Vec<&str> = effective_schema_b
        .split(',')
        .map(|s| s.trim().trim_matches('"'))
        .filter(|s| !s.is_empty())
        .collect();

    schemas_a.iter().any(|sa| schemas_b.contains(sa))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn neon_pooler_host_rewrites_to_direct() {
        let pooled = "postgresql://memwal:s3cret@ep-odd-cake-aorg5ujz-pooler.c-2.ap-southeast-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require";
        let direct = direct_postgres_url(pooled);
        assert_eq!(
            url::Url::parse(&direct).unwrap().host_str(),
            Some("ep-odd-cake-aorg5ujz.c-2.ap-southeast-1.aws.neon.tech")
        );
        assert!(direct.contains("sslmode=require"));
        assert!(direct.contains("channel_binding=require"));
        assert!(direct.contains("memwal:s3cret"));
        assert!(
            direct.ends_with("/neondb?sslmode=require&channel_binding=require")
                || direct.contains("/neondb?")
        );
        assert!(is_transaction_pooler_url(pooled));
        assert!(!is_transaction_pooler_url(&direct));
    }

    #[test]
    fn already_direct_url_is_unchanged() {
        let url = "postgresql://memwal:s3cret@ep-odd-cake-aorg5ujz.c-2.ap-southeast-1.aws.neon.tech/neondb";
        assert!(matches!(direct_postgres_url(url), Cow::Borrowed(_)));
        assert!(!is_transaction_pooler_url(url));
    }

    #[test]
    fn pooler_in_user_or_db_name_is_not_rewritten() {
        let url = "postgresql://pooler-user:x@localhost:5432/pooler";
        assert!(matches!(direct_postgres_url(url), Cow::Borrowed(_)));
        assert!(!is_transaction_pooler_url(url));
    }

    #[test]
    fn percent_encoded_password_survives_rewrite() {
        let pooled = "postgresql://memwal:p%40ss@ep-foo-pooler.us-east-2.aws.neon.tech/neondb";
        let direct = direct_postgres_url(pooled);
        let parsed = url::Url::parse(&direct).unwrap();
        assert_eq!(parsed.password(), Some("p%40ss"));
        assert_eq!(parsed.host_str(), Some("ep-foo.us-east-2.aws.neon.tech"));
    }

    #[test]
    fn unparseable_or_socket_urls_pass_through() {
        assert!(matches!(
            direct_postgres_url("not a url"),
            Cow::Borrowed("not a url")
        ));
        let socket = "postgresql://memwal@/neondb?host=/tmp";
        // url crate may or may not treat this as host-less; either way we
        // must not panic or invent a hostname.
        let _ = direct_postgres_url(socket);
        assert!(!is_transaction_pooler_url(socket));
    }

    #[test]
    fn share_target_detects_identical_and_neon_pooler_urls() {
        let direct =
            "postgresql://memwal:secret@ep-foo.us-east-2.aws.neon.tech:5432/neondb?sslmode=require";
        let pooler = "postgresql://memwal:secret@ep-foo-pooler.us-east-2.aws.neon.tech:5432/neondb?sslmode=require";
        assert!(postgres_urls_share_target(direct, pooler));
        assert!(postgres_urls_share_target(direct, direct));
        assert!(postgres_urls_share_target(
            "  postgresql://user:pass@localhost:5432/db  ",
            "postgresql://user:pass@localhost:5432/db"
        ));
    }

    #[test]
    fn share_target_distinguishes_different_databases_and_ports() {
        let url_a = "postgresql://user:pass@localhost:5432/db_a";
        let url_b = "postgresql://user:pass@localhost:5432/db_b";
        let url_other_port = "postgresql://user:pass@localhost:5433/db_a";
        assert!(!postgres_urls_share_target(url_a, url_b));
        assert!(!postgres_urls_share_target(url_a, url_other_port));
    }

    #[test]
    fn share_target_respects_search_path_options() {
        let base = "postgresql://user:pass@localhost:5432/db";
        let legacy_opt = "postgresql://user:pass@localhost:5432/db?options=-csearch_path%3Dlegacy";
        let legacy_query = "postgresql://user:pass@localhost:5432/db?search_path=legacy";
        let primary_query = "postgresql://user:pass@localhost:5432/db?search_path=primary";
        let public_query = "postgresql://user:pass@localhost:5432/db?search_path=public";

        // Explicit distinct schemas on the same database do not share target
        assert!(!postgres_urls_share_target(base, legacy_opt));
        assert!(!postgres_urls_share_target(base, legacy_query));
        assert!(!postgres_urls_share_target(legacy_opt, primary_query));

        // Matching explicit schemas do share target
        assert!(postgres_urls_share_target(legacy_opt, legacy_query));

        // Explicit public schema matches default public schema
        assert!(postgres_urls_share_target(base, public_query));

        // Fallback search_path containing public overlaps with default public schema
        let fallback_public = "postgresql://user:pass@localhost:5432/db?search_path=legacy,public";
        assert!(postgres_urls_share_target(base, fallback_public));
        assert!(postgres_urls_share_target(public_query, fallback_public));
    }
}
