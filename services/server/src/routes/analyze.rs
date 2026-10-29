//! `/api/analyze` — AI fact extraction → store.
//!
//! Production path (default): extract facts via the Extractor service,
//! then per fact concurrently embed + SEAL-encrypt, quota-check the total
//! ciphertext, and enqueue one `UploadAndTransfer` WalletJob per fact —
//! returns HTTP 202 with `status: "pending"` and the per-fact job ids.
//!
//! Benchmark-mode bypass (BENCHMARK_MODE on; off by default, not for
//! production): per fact, embed → `engine.store_blob(plaintext bytes)`
//! synchronously (the `PlaintextEngine` writes the `plaintext` column — no
//! SEAL, no Walrus, no Sui tx, no job row). The response carries the real
//! stored ids and `status: "done"`, so the benchmark harness can treat
//! `/api/analyze` as synchronous the way the SDK's analyze contract did
//! before.

use axum::extract::State;
use axum::http::StatusCode;
use axum::{Extension, Json};
use base64::Engine as _;
use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::jobs::WalletOperation;
use crate::rate_limit;
use crate::services::extractor::{ExtractedFact, MAX_ANALYZE_FACTS};
use crate::types::*;

use super::{collect_bounded_results, enqueue_wallet_job};

const ANALYZE_CONCURRENCY: usize = 5;

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn is_base64url_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

fn take_while_len<F: Fn(u8) -> bool>(bytes: &[u8], f: F) -> usize {
    bytes.iter().take_while(|&&b| f(b)).count()
}

fn match_pem_header(s: &str) -> Option<usize> {
    let rest = s.strip_prefix("-----BEGIN ")?;
    let end_idx = rest.find("PRIVATE KEY-----")?;
    let label = &rest[..end_idx];
    if label
        .bytes()
        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b' ')
    {
        Some("-----BEGIN ".len() + end_idx + "PRIVATE KEY-----".len())
    } else {
        None
    }
}

fn match_pem_footer(s: &str) -> Option<usize> {
    let rest = s.strip_prefix("-----END ")?;
    let end_idx = rest.find("PRIVATE KEY-----")?;
    let label = &rest[..end_idx];
    if label
        .bytes()
        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b' ')
    {
        Some("-----END ".len() + end_idx + "PRIVATE KEY-----".len())
    } else {
        None
    }
}

fn redact_pem_blocks(input: &str, count: &mut usize) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(begin_pos) = rest.find("-----BEGIN ") {
        out.push_str(&rest[..begin_pos]);
        let candidate = &rest[begin_pos..];
        let Some(header_len) = match_pem_header(candidate) else {
            out.push_str("-----BEGIN ");
            rest = &candidate["-----BEGIN ".len()..];
            continue;
        };
        let after_header = &candidate[header_len..];
        let mut search_offset = 0;
        let mut closed_end = None;
        while let Some(rel_end) = after_header[search_offset..].find("-----END ") {
            let idx = search_offset + rel_end;
            if let Some(footer_len) = match_pem_footer(&after_header[idx..]) {
                closed_end = Some(header_len + idx + footer_len);
                break;
            }
            search_offset = idx + "-----END ".len();
        }
        *count += 1;
        out.push_str("[redacted:private-key-block]");
        if let Some(total_len) = closed_end {
            rest = &candidate[total_len..];
        } else {
            return out;
        }
    }
    out.push_str(rest);
    out
}

fn is_url_userinfo_user_byte(b: u8) -> bool {
    !b.is_ascii_whitespace() && !matches!(b, b'/' | b'@' | b':' | b'?' | b'=' | b'&')
}

fn is_url_userinfo_pass_byte(b: u8) -> bool {
    !b.is_ascii_whitespace() && !matches!(b, b'/' | b'@' | b'?' | b'=' | b'&')
}

fn redact_url_userinfo(input: &str, count: &mut usize) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < bytes.len() {
        if i + 3 <= bytes.len() && &bytes[i..i + 3] == b"://" {
            // Confirm preceded by a valid 1..=31 byte scheme.
            let mut scheme_start = i;
            while scheme_start > 0
                && (i - scheme_start) < 31
                && (bytes[scheme_start - 1].is_ascii_alphanumeric()
                    || matches!(bytes[scheme_start - 1], b'+' | b'.' | b'-'))
            {
                scheme_start -= 1;
            }
            let valid_scheme = scheme_start < i && bytes[scheme_start].is_ascii_alphabetic();
            if valid_scheme {
                let after_scheme = i + 3;
                let user_len = take_while_len(&bytes[after_scheme..], is_url_userinfo_user_byte);
                let colon_pos = after_scheme + user_len;
                if user_len > 0 && colon_pos < bytes.len() && bytes[colon_pos] == b':' {
                    let pass_start = colon_pos + 1;
                    let pass_len = take_while_len(&bytes[pass_start..], is_url_userinfo_pass_byte);
                    let at_pos = pass_start + pass_len;
                    if pass_len > 0 && at_pos < bytes.len() && bytes[at_pos] == b'@' {
                        out.push_str("://[redacted:url-credentials]@");
                        *count += 1;
                        i = at_pos + 1;
                        continue;
                    }
                }
            }
        }
        let ch = input[i..].chars().next().expect("char boundary");
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Match a high-confidence vendor key or JWT at the start of `s`, returning
/// `(matched_byte_len, placeholder)`. Caller guarantees left word boundary.
fn match_secret_token_at_start(s: &str) -> Option<(usize, &'static str)> {
    let bytes = s.as_bytes();

    // 1. Bech32 Sui private key: suiprivkey1[0-9a-z]{16,} (case-insensitive) (#435)
    if bytes.len() >= 27 && bytes[..11].eq_ignore_ascii_case(b"suiprivkey1") {
        let body_len = take_while_len(&bytes[11..], |b| b.is_ascii_alphanumeric());
        let total = 11 + body_len;
        if body_len >= 16 && (total == bytes.len() || !is_word_byte(bytes[total])) {
            return Some((total, "[redacted:vendor-api-key]"));
        }
    }

    // 2. Anthropic / OpenAI keys
    for prefix in [b"sk-ant-" as &[u8], b"sk-proj-"] {
        if bytes.starts_with(prefix) {
            let body_len = take_while_len(&bytes[prefix.len()..], is_base64url_byte);
            if body_len >= 16 {
                return Some((prefix.len() + body_len, "[redacted:vendor-api-key]"));
            }
        }
    }
    if bytes.starts_with(b"sk-") {
        let body_len = take_while_len(&bytes[3..], |b| b.is_ascii_alphanumeric());
        if body_len >= 20 {
            return Some((3 + body_len, "[redacted:vendor-api-key]"));
        }
    }

    // 3. GitHub tokens
    for prefix in [b"ghp_" as &[u8], b"gho_", b"ghu_", b"ghs_", b"ghr_"] {
        if bytes.starts_with(prefix) {
            let body_len = take_while_len(&bytes[4..], |b| b.is_ascii_alphanumeric());
            if body_len >= 20 {
                return Some((4 + body_len, "[redacted:vendor-api-key]"));
            }
        }
    }
    if bytes.starts_with(b"github_pat_") {
        let body_len = take_while_len(&bytes[11..], is_word_byte);
        if body_len >= 20 {
            return Some((11 + body_len, "[redacted:vendor-api-key]"));
        }
    }

    // 4. AWS access key ID: (AKIA|ASIA)[0-9A-Z]{16}\b
    if bytes.starts_with(b"AKIA") || bytes.starts_with(b"ASIA") {
        let body_len = take_while_len(&bytes[4..], |b| {
            b.is_ascii_uppercase() || b.is_ascii_digit()
        });
        if body_len == 16 && (bytes.len() == 20 || !is_word_byte(bytes[20])) {
            return Some((20, "[redacted:vendor-api-key]"));
        }
    }

    // 5. Slack: xox[baprs]-[A-Za-z0-9-]{10,}
    if bytes.len() >= 15
        && bytes.starts_with(b"xox")
        && matches!(bytes[3], b'b' | b'a' | b'p' | b'r' | b's')
        && bytes[4] == b'-'
    {
        let body_len = take_while_len(&bytes[5..], |b| b.is_ascii_alphanumeric() || b == b'-');
        if body_len >= 10 {
            return Some((5 + body_len, "[redacted:vendor-api-key]"));
        }
    }

    // 6. Google API: AIza[0-9A-Za-z_-]{35}\b
    if bytes.starts_with(b"AIza") {
        let body_len = take_while_len(&bytes[4..], is_base64url_byte);
        if body_len == 35 && (bytes.len() == 39 || !is_word_byte(bytes[39])) {
            return Some((39, "[redacted:vendor-api-key]"));
        }
    }

    // 7. GitLab: glpat-[A-Za-z0-9_-]{16,}
    if bytes.starts_with(b"glpat-") {
        let body_len = take_while_len(&bytes[6..], is_base64url_byte);
        if body_len >= 16 {
            return Some((6 + body_len, "[redacted:vendor-api-key]"));
        }
    }

    // 8. npm: npm_[A-Za-z0-9]{36}\b
    if bytes.starts_with(b"npm_") {
        let body_len = take_while_len(&bytes[4..], |b| b.is_ascii_alphanumeric());
        if body_len == 36 && (bytes.len() == 40 || !is_word_byte(bytes[40])) {
            return Some((40, "[redacted:vendor-api-key]"));
        }
    }

    // 9. SendGrid: SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}
    if bytes.starts_with(b"SG.") {
        let seg1 = take_while_len(&bytes[3..], is_base64url_byte);
        let dot_pos = 3 + seg1;
        if seg1 >= 16 && dot_pos < bytes.len() && bytes[dot_pos] == b'.' {
            let seg2 = take_while_len(&bytes[dot_pos + 1..], is_base64url_byte);
            if seg2 >= 16 {
                return Some((dot_pos + 1 + seg2, "[redacted:vendor-api-key]"));
            }
        }
    }

    // 10. Stripe: [sprk]k_(live|test)_[A-Za-z0-9]{16,}
    if bytes.len() >= 24
        && matches!(bytes[0], b's' | b'p' | b'r' | b'k')
        && bytes[1] == b'k'
        && bytes[2] == b'_'
    {
        for mode in [b"live_" as &[u8], b"test_"] {
            if bytes[3..].starts_with(mode) {
                let prefix_len = 3 + mode.len();
                let body_len = take_while_len(&bytes[prefix_len..], |b| b.is_ascii_alphanumeric());
                if body_len >= 16 {
                    return Some((prefix_len + body_len, "[redacted:vendor-api-key]"));
                }
            }
        }
    }

    // 11. Shopify: shp(at|ss|ca|pa)_[a-fA-F0-9]{32}\b
    for prefix in [b"shpat_" as &[u8], b"shpss_", b"shpca_", b"shppa_"] {
        if bytes.starts_with(prefix) {
            let body_len = take_while_len(&bytes[6..], |b| b.is_ascii_hexdigit());
            if body_len == 32 && (bytes.len() == 38 || !is_word_byte(bytes[38])) {
                return Some((38, "[redacted:vendor-api-key]"));
            }
        }
    }

    // 12. DigitalOcean: dop_v1_[a-f0-9]{64}\b
    if bytes.starts_with(b"dop_v1_") {
        let body_len = take_while_len(&bytes[7..], |b| {
            b.is_ascii_digit() || matches!(b, b'a'..=b'f')
        });
        if body_len == 64 && (bytes.len() == 71 || !is_word_byte(bytes[71])) {
            return Some((71, "[redacted:vendor-api-key]"));
        }
    }

    // 13. Hugging Face: hf_[A-Za-z0-9]{30,}\b
    if bytes.starts_with(b"hf_") {
        let body_len = take_while_len(&bytes[3..], |b| b.is_ascii_alphanumeric());
        let total = 3 + body_len;
        if body_len >= 30 && (total == bytes.len() || !is_word_byte(bytes[total])) {
            return Some((total, "[redacted:vendor-api-key]"));
        }
    }

    // 14. JWT: eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}
    if bytes.starts_with(b"eyJ") {
        let seg1 = 3 + take_while_len(&bytes[3..], is_base64url_byte);
        if seg1 >= 11 && seg1 < bytes.len() && bytes[seg1] == b'.' {
            let seg2_len = take_while_len(&bytes[seg1 + 1..], is_base64url_byte);
            let dot2 = seg1 + 1 + seg2_len;
            if seg2_len >= 8 && dot2 < bytes.len() && bytes[dot2] == b'.' {
                let seg3_len = take_while_len(&bytes[dot2 + 1..], is_base64url_byte);
                if seg3_len >= 8 {
                    return Some((dot2 + 1 + seg3_len, "[redacted:jwt]"));
                }
            }
        }
    }

    None
}

fn redact_token_secrets(input: &str, count: &mut usize) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < bytes.len() {
        let at_word_boundary = i == 0 || !is_word_byte(bytes[i - 1]);
        if at_word_boundary {
            if let Some((matched_len, replacement)) = match_secret_token_at_start(&input[i..]) {
                out.push_str(replacement);
                *count += 1;
                i += matched_len;
                continue;
            }
        }
        let ch = input[i..].chars().next().expect("char boundary");
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn redact_credential_assignments(input: &str, count: &mut usize) -> String {
    const KEYWORDS: &[&str] = &[
        "db_passwords",
        "db-passwords",
        "dbpasswords",
        "db_password",
        "db-password",
        "dbpassword",
        "db_pass",
        "db-pass",
        "dbpass",
        "passwords",
        "password",
        "passwd",
        "pwd",
        "passphrases",
        "passphrase",
        "secret_keys",
        "secret-keys",
        "secret_key",
        "secret-key",
        "access_keys",
        "access-keys",
        "access_key",
        "access-key",
        "encryption_keys",
        "encryption-keys",
        "encryption_key",
        "encryption-key",
        "enc_keys",
        "enc-keys",
        "enc_key",
        "enc-key",
        "client_secrets",
        "client-secrets",
        "client_secret",
        "client-secret",
        "api_keys",
        "api-keys",
        "api_key",
        "api-key",
        "apikeys",
        "apikey",
        "secrets",
        "secret",
        "access_tokens",
        "access-tokens",
        "access_token",
        "access-token",
        "refresh_tokens",
        "refresh-tokens",
        "refresh_token",
        "refresh-token",
        "auth_tokens",
        "auth-tokens",
        "auth_token",
        "auth-token",
        "bearer_tokens",
        "bearer-tokens",
        "bearer_token",
        "bearer-token",
        "tokens",
        "token",
        "private_keys",
        "private-keys",
        "private_key",
        "private-key",
        "priv_keys",
        "priv-keys",
        "priv_key",
        "priv-key",
        "credentials",
        "credential",
    ];

    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;

    while i < bytes.len() {
        let left_ok = i == 0 || !bytes[i - 1].is_ascii_uppercase();

        if left_ok {
            let mut matched_kw_len = None;
            for kw in KEYWORDS {
                if bytes[i..]
                    .get(..kw.len())
                    .map(|b| b.eq_ignore_ascii_case(kw.as_bytes()))
                    .unwrap_or(false)
                {
                    matched_kw_len = Some(kw.len());
                    break;
                }
            }

            if let Some(kw_len) = matched_kw_len {
                let mut p = i + kw_len;
                if p < bytes.len() && matches!(bytes[p], b'"' | b'\'' | b'`') {
                    p += 1;
                }
                while p < bytes.len() && (bytes[p] == b' ' || bytes[p] == b'\t') {
                    p += 1;
                }
                if p < bytes.len() && (bytes[p] == b':' || bytes[p] == b'=') {
                    p += 1;
                    while p < bytes.len() && (bytes[p] == b' ' || bytes[p] == b'\t') {
                        p += 1;
                    }
                    if p < bytes.len() {
                        let val_bytes = &bytes[p..];
                        let val_len = if matches!(val_bytes[0], b'"' | b'\'' | b'`') {
                            let open_q = val_bytes[0];
                            let mut end_q = 1;
                            while end_q < val_bytes.len()
                                && val_bytes[end_q] != open_q
                                && val_bytes[end_q] != b'\n'
                            {
                                end_q += 1;
                            }
                            if end_q < val_bytes.len() && val_bytes[end_q] == open_q {
                                end_q + 1
                            } else {
                                0
                            }
                        } else {
                            val_bytes
                                .iter()
                                .take_while(|&&b| {
                                    !b.is_ascii_whitespace() && b != b',' && b != b';'
                                })
                                .count()
                        };

                        if val_len > 0 {
                            out.push_str(&input[i..p]);
                            out.push_str("[redacted:credential-assignment]");
                            *count += 1;
                            i = p + val_len;
                            continue;
                        }
                    }
                }
            }
        }

        let ch = input[i..].chars().next().expect("char boundary");
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn redact_auth_and_cookie_headers(input: &str, count: &mut usize) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;

    while i < bytes.len() {
        let at_word_boundary = i == 0 || !is_word_byte(bytes[i - 1]);

        if at_word_boundary {
            let slice = &bytes[i..];
            let header_match = if slice
                .get(..19)
                .map(|b| b.eq_ignore_ascii_case(b"proxy-authorization"))
                .unwrap_or(false)
            {
                Some(19)
            } else if slice
                .get(..13)
                .map(|b| b.eq_ignore_ascii_case(b"authorization"))
                .unwrap_or(false)
            {
                Some(13)
            } else {
                None
            };

            if let Some(h_len) = header_match {
                let mut p = i + h_len;
                while p < bytes.len() && (bytes[p] == b' ' || bytes[p] == b'\t') {
                    p += 1;
                }
                if p < bytes.len() && (bytes[p] == b':' || bytes[p] == b'=') {
                    p += 1;
                    while p < bytes.len() && (bytes[p] == b' ' || bytes[p] == b'\t') {
                        p += 1;
                    }
                    let p_sep = p;
                    let after_sep = &bytes[p..];
                    let prefix_len = if after_sep
                        .get(..6)
                        .map(|b| b.eq_ignore_ascii_case(b"bearer"))
                        .unwrap_or(false)
                    {
                        Some(6)
                    } else if after_sep
                        .get(..5)
                        .map(|b| b.eq_ignore_ascii_case(b"basic"))
                        .unwrap_or(false)
                    {
                        Some(5)
                    } else if after_sep
                        .get(..5)
                        .map(|b| b.eq_ignore_ascii_case(b"token"))
                        .unwrap_or(false)
                    {
                        Some(5)
                    } else if after_sep
                        .get(..6)
                        .map(|b| b.eq_ignore_ascii_case(b"digest"))
                        .unwrap_or(false)
                    {
                        Some(6)
                    } else {
                        None
                    };
                    if let Some(plen) = prefix_len {
                        p += plen;
                        while p < bytes.len() && (bytes[p] == b' ' || bytes[p] == b'\t') {
                            p += 1;
                        }
                    }
                    let val_len = bytes[p..]
                        .iter()
                        .take_while(|&&b| !b.is_ascii_whitespace())
                        .count();
                    if val_len > 0 || prefix_len.is_some() {
                        out.push_str(&input[i..p_sep]);
                        out.push_str("[redacted:auth-header]");
                        *count += 1;
                        i = p + val_len;
                        continue;
                    }
                }
            }

            let cookie_match = if slice
                .get(..10)
                .map(|b| b.eq_ignore_ascii_case(b"set-cookie"))
                .unwrap_or(false)
            {
                Some(10)
            } else if slice
                .get(..6)
                .map(|b| b.eq_ignore_ascii_case(b"cookie"))
                .unwrap_or(false)
            {
                Some(6)
            } else {
                None
            };
            if let Some(c_len) = cookie_match {
                let mut p = i + c_len;
                while p < bytes.len() && (bytes[p] == b' ' || bytes[p] == b'\t') {
                    p += 1;
                }
                if p < bytes.len() && (bytes[p] == b':' || bytes[p] == b'=') {
                    p += 1;
                    while p < bytes.len() && (bytes[p] == b' ' || bytes[p] == b'\t') {
                        p += 1;
                    }
                    let mut cp = p;
                    let first_pair = bytes[cp..]
                        .iter()
                        .take_while(|&&b| !b.is_ascii_whitespace() && b != b';')
                        .count();
                    if first_pair > 0 {
                        cp += first_pair;
                        loop {
                            let mut look = cp;
                            while look < bytes.len()
                                && (bytes[look] == b' ' || bytes[look] == b'\t')
                            {
                                look += 1;
                            }
                            if look < bytes.len() && bytes[look] == b';' {
                                look += 1;
                                while look < bytes.len()
                                    && (bytes[look] == b' ' || bytes[look] == b'\t')
                                {
                                    look += 1;
                                }
                                let next_pair = bytes[look..]
                                    .iter()
                                    .take_while(|&&b| !b.is_ascii_whitespace() && b != b';')
                                    .count();
                                if next_pair > 0 {
                                    cp = look + next_pair;
                                    continue;
                                }
                            }
                            break;
                        }
                        out.push_str(&input[i..p]);
                        out.push_str("[redacted:auth-header]");
                        *count += 1;
                        i = cp;
                        continue;
                    }
                }
            }
        }

        let ch = input[i..].chars().next().expect("char boundary");
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn redact_seed_phrase(input: &str, count: &mut usize) -> String {
    const SEED_LABELS: &[&str] = &[
        "recovery_phrase",
        "recovery phrase",
        "secret_phrase",
        "secret phrase",
        "mnemonic_phrase",
        "mnemonic phrase",
        "recovery_words",
        "recovery words",
        "secret_words",
        "secret words",
        "mnemonic_words",
        "mnemonic words",
        "seed_phrase",
        "seed phrase",
        "seedphrase",
        "seed_words",
        "seed words",
        "mnemonic",
    ];

    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;

    while i < bytes.len() {
        let left_ok = i == 0 || !is_word_byte(bytes[i - 1]);

        if left_ok {
            let mut matched_label_len = None;
            for label in SEED_LABELS {
                if bytes[i..]
                    .get(..label.len())
                    .map(|b| b.eq_ignore_ascii_case(label.as_bytes()))
                    .unwrap_or(false)
                {
                    matched_label_len = Some(label.len());
                    break;
                }
            }

            if let Some(l_len) = matched_label_len {
                let mut p = i + l_len;
                while p < bytes.len() && (p - (i + l_len)) < 4 && !bytes[p].is_ascii_alphanumeric()
                {
                    p += 1;
                }
                if bytes[p..]
                    .get(..2)
                    .map(|b| b.eq_ignore_ascii_case(b"is"))
                    .unwrap_or(false)
                {
                    p += 2;
                } else if bytes[p..]
                    .get(..3)
                    .map(|b| b.eq_ignore_ascii_case(b"are"))
                    .unwrap_or(false)
                {
                    p += 3;
                }
                let p_anchor = p;
                while p < bytes.len() && (p - p_anchor) < 4 && !bytes[p].is_ascii_alphanumeric() {
                    p += 1;
                }

                let mut word_count = 0;
                let mut wp = p;
                while wp < bytes.len() {
                    let wlen = bytes[wp..]
                        .iter()
                        .take_while(|&&b| b.is_ascii_lowercase())
                        .count();
                    if wlen >= 3 && wlen <= 10 {
                        word_count += 1;
                        wp += wlen;
                        if wp < bytes.len() && (bytes[wp] == b' ' || bytes[wp] == b'\t') {
                            wp += 1;
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                }

                if word_count >= 11 && word_count <= 24 {
                    out.push_str(&input[i..p]);
                    out.push_str("[redacted:seed-phrase]");
                    *count += 1;
                    i = wp;
                    continue;
                }
            }
        }

        let ch = input[i..].chars().next().expect("char boundary");
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn contains_credential_label(s: &str) -> bool {
    const LABELS: &[&str] = &[
        "delegateprivatekey",
        "delegate_private_key",
        "delegate-private-key",
        "delegate private key",
        "delegateprivate",
        "delegate_private",
        "delegate-private",
        "delegate private",
        "privatekey",
        "private_key",
        "private-key",
        "private key",
        "secretkey",
        "secret_key",
        "secret-key",
        "secret key",
        "signingkey",
        "signing_key",
        "signing-key",
        "signing key",
        "privkey",
        "priv_key",
        "priv-key",
        "priv key",
        "sui.keystore",
        "sui_keystore",
        "sui keystore",
        "encryption_key",
        "encryption key",
        "enc_key",
        "api_key",
        "api key",
        "access_key",
        "access key",
        "auth_key",
        "auth key",
        "db_password",
        "db password",
        "db_pass",
        "db pass",
        "secret",
        "seed",
        "mnemonic",
        "passphrase",
    ];
    let lower = s.to_ascii_lowercase();
    for kw in LABELS {
        if lower.contains(kw) {
            return true;
        }
    }
    false
}

fn has_adjacent_credential_label(input: &str, start: usize, end: usize, window: usize) -> bool {
    let mut before_start = start.saturating_sub(window);
    while before_start > 0 && !input.is_char_boundary(before_start) {
        before_start -= 1;
    }
    let before_slice = &input[before_start..start];
    if contains_credential_label(before_slice) {
        return true;
    }
    let mut after_end = (end + window).min(input.len());
    while after_end < input.len() && !input.is_char_boundary(after_end) {
        after_end += 1;
    }
    let after_slice = &input[end..after_end];
    if contains_credential_label(after_slice) {
        return true;
    }
    false
}

fn redact_labelled_key_material(input: &str, count: &mut usize) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < bytes.len() {
        let at_word_boundary = i == 0 || !is_word_byte(bytes[i - 1]);
        if at_word_boundary {
            let has_0x = bytes[i..].starts_with(b"0x");
            let hex_start = if has_0x { i + 2 } else { i };
            let hex_len = bytes[hex_start..]
                .iter()
                .take_while(|&&b| b.is_ascii_hexdigit())
                .count();
            if hex_len >= 32 {
                let total_hex_len = (hex_start - i) + hex_len;
                let end = i + total_hex_len;
                let right_ok = end == bytes.len() || !is_word_byte(bytes[end]);
                if right_ok && has_adjacent_credential_label(input, i, end, 48) {
                    out.push_str("[redacted:labelled-key-material]");
                    *count += 1;
                    i = end;
                    continue;
                }
            }
        }
        let ch = input[i..].chars().next().expect("char boundary");
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn has_salvageable_fact_content(text: &str) -> bool {
    // Strip `[redacted:...]` placeholders before counting words >= 2 chars.
    let mut without_placeholders = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("[redacted:") {
        without_placeholders.push_str(&rest[..start]);
        let after = &rest[start + "[redacted:".len()..];
        if let Some(end) = after.find(']') {
            without_placeholders.push(' ');
            rest = &after[end + 1..];
        } else {
            without_placeholders.push_str(&rest[start..]);
            rest = "";
            break;
        }
    }
    without_placeholders.push_str(rest);

    let mut word_count = 0usize;
    let mut current_word_chars = 0usize;
    for ch in without_placeholders.chars() {
        if ch.is_alphanumeric() {
            current_word_chars += 1;
        } else {
            if current_word_chars >= 2 {
                word_count += 1;
                if word_count >= 3 {
                    return true;
                }
            }
            current_word_chars = 0;
        }
    }
    if current_word_chars >= 2 {
        word_count += 1;
    }
    word_count >= 3
}

/// Post-extraction secret screen for a single extracted fact (#435).
///
/// Returns `Some(fact_text)` when the fact is clean or still carries a
/// salvageable fact after redacting secret spans, or `None` when the fact was
/// purely credential material with no surrounding fact.
fn screen_fact_text(input: &str) -> Option<String> {
    let mut count = 0usize;
    let text = redact_pem_blocks(input, &mut count);
    let text = redact_url_userinfo(&text, &mut count);
    let text = redact_auth_and_cookie_headers(&text, &mut count);
    let text = redact_credential_assignments(&text, &mut count);
    let text = redact_seed_phrase(&text, &mut count);
    let text = redact_token_secrets(&text, &mut count);
    let text = redact_labelled_key_material(&text, &mut count);
    if count == 0 {
        return Some(input.to_string());
    }
    if !has_salvageable_fact_content(&text) {
        return None;
    }
    Some(text)
}

/// Screen all extracted facts before embedding and SEAL encryption (#435).
fn screen_extracted_facts(facts: Vec<ExtractedFact>) -> Vec<ExtractedFact> {
    facts
        .into_iter()
        .filter_map(|mut fact| {
            let screened = screen_fact_text(&fact.text)?;
            fact.text = screened;
            Some(fact)
        })
        .collect()
}

/// Stable per-fact key so an HTTP retry of `/api/analyze` collapses onto the
/// in-flight or completed upload instead of minting a second Walrus blob.
///
/// Importance is intentionally not hashed in. The extractor assigns a
/// vital/standard/trivial bucket per fact; a later call that extracts the
/// same text with a different bucket updates the live `vector_entries` row
/// rather than paying for a duplicate write. `forget` NULLs this key so a
/// re-analyze after delete is a new write, not a silent no-op.
fn analyze_fact_idempotency_key(owner: &str, namespace: &str, fact_text: &str) -> String {
    let digest = Sha256::digest(format!("{owner}\n{namespace}\n{fact_text}").as_bytes());
    format!("analyze:{}", hex::encode(digest))
}

#[derive(Debug, PartialEq, Eq)]
enum AnalyzeJobReuse {
    /// In-flight, or already stored with the same importance: return the existing job.
    Collapse,
    /// Failed before a blob was paid for: reset and re-enqueue on the same id.
    RetryUnpaidFailure,
    /// Live memory exists, but the extractor now scores it differently.
    UpdateImportance,
    /// Job completed and the vector is gone (forget / expiry): free the key and write again.
    RewriteForgotten,
}

fn importance_changed(existing: f32, incoming: f32) -> bool {
    (existing - incoming).abs() > 1e-6
}

/// Reset an unpaid failed analyze job before enqueueing a fresh ciphertext.
///
/// SEAL encryption is not deterministic, so the retry's bytes are a new Walrus
/// blob. The previous `encoded` checkpoint still names the old blob id. Leaving
/// it in place makes the sidecar reject the retry with `Resume blobId mismatch`
/// and burn the attempt budget. A registered-or-later resume, or any recorded
/// blob, is left untouched: those bytes may already have been submitted.
fn unpaid_analyze_retry_reset_sql() -> &'static str {
    "UPDATE remember_jobs SET status = 'pending', error_msg = NULL, \
     upload_wallet_index = NULL, upload_wallet_address = NULL, \
     upload_execution_identity = NULL, upload_resume_step = NULL, \
     upload_register_transaction = NULL, updated_at = NOW() \
     WHERE id = $1 AND status = 'failed' AND blob_id IS NULL AND blob_object_id IS NULL \
     AND (upload_resume_step IS NULL OR upload_resume_step->>'step' = 'encoded')"
}

fn classify_analyze_job_reuse(
    status: &str,
    blob_id: Option<&str>,
    live_importance: Option<f32>,
    incoming_importance: f32,
) -> AnalyzeJobReuse {
    if status == "failed" && blob_id.is_none() {
        return AnalyzeJobReuse::RetryUnpaidFailure;
    }
    match live_importance {
        None if blob_id.is_some() && status == "done" => AnalyzeJobReuse::RewriteForgotten,
        Some(existing) if importance_changed(existing, incoming_importance) => {
            AnalyzeJobReuse::UpdateImportance
        }
        _ => AnalyzeJobReuse::Collapse,
    }
}

// /api/analyze does not benefit from larger inputs — it sends the
// full text to gpt-4o-mini for fact extraction in a single LLM call (no
// chunking like remember). Cap it at the previous /api/remember ceiling
// so a hostile client cannot burn ~1 MiB of LLM tokens for the same
// rate-limit weight as a tiny request.
const MAX_ANALYZE_TEXT_BYTES: usize = 64 * 1024;

/// How many existing memories to pull as pre-extraction dedup
/// context for the extractor. This matches the default `recall_limit` the
/// benchmark harness uses, so the dedup context reflects what the user is
/// most likely to ask about next.
///
/// Sized for the cost trade-off: each retrieved memory adds ~50-150ms
/// of latency (one extra `search_similar` + `fetch_batch` round-trip),
/// and roughly 50-100 tokens to the LLM input. K=10 keeps p95 latency
/// within the expected +50-150ms budget.
const PRE_EXTRACTION_CONTEXT_LIMIT: usize = 10;

/// Per-leg timeouts on the pre-extraction context retrieval.
/// Set generously above measured p95 (embed ~150ms, search ~30ms warm /
/// 500ms cold, fetch ~50ms warm) so a healthy server is unaffected, but
/// tight enough to cap a stalled external dependency (OpenAI hiccup,
/// pgvector cold-namespace tail, sidecar 5xx). On expiry the leg's
/// fallback path fires — context goes empty, analyze continues. Total
/// pre-extraction worst case after timeouts: ~1.6s vs the observed
/// 30s benchmark outlier under no-timeout.
const EMBED_TIMEOUT_MS: u64 = 800;
const SEARCH_TIMEOUT_MS: u64 = 300;
const FETCH_TIMEOUT_MS: u64 = 500;

/// Largest input handed to the embedder for the pre-extraction dedup query.
/// Matches the embedder's local byte cap: larger inputs already fail before
/// any HTTP request. Skipping them here reports an expected skip instead of
/// an embed failure, while preserving dedup attempts for inputs up to 16 KiB.
///
/// This is a byte limit, not a token guarantee: dense inputs below it can
/// still exceed the provider's token limit and fall back to plain extraction.
/// It is independent of `remember`'s summarize-before-store cost threshold.
const MAX_PRE_EXTRACT_EMBED_BYTES: usize = 16 * 1024;

/// Whether to skip the pre-extraction dedup embed for an input of this size.
///
/// Skipping costs the extractor its dedup context, which is why the boundary
/// is inclusive: input of exactly `MAX_PRE_EXTRACT_EMBED_BYTES` is still
/// handed to the embedder.
fn should_skip_pre_extract_embed(text_len: usize) -> bool {
    text_len > MAX_PRE_EXTRACT_EMBED_BYTES
}

/// One fact that has finished embed + SEAL encrypt and is ready to enqueue:
/// `(plaintext, importance, embedding, ciphertext)`.
type PreparedFact = (String, f32, Vec<f32>, Vec<u8>);

/// POST /api/analyze
///
/// AI fact extraction flow:
/// 1. Verify auth (middleware) → get owner
/// 2. Call LLM to extract memorable facts from text
/// 3. For each fact concurrently: embed + encrypt → Walrus upload → store
pub async fn analyze(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthInfo>,
    Json(body): Json<AnalyzeRequest>,
) -> Result<(StatusCode, Json<AnalyzeAcceptedResponse>), AppError> {
    reject_if_writes_paused(state.config.writes_paused)?;
    if text_is_blank(&body.text) {
        return Err(AppError::BadRequest("Text cannot be empty".into()));
    }
    // Reject oversize plaintext before spending an LLM call.
    if body.text.len() > MAX_ANALYZE_TEXT_BYTES {
        return Err(AppError::BadRequest(format!(
            "Text exceeds maximum length of {} bytes",
            MAX_ANALYZE_TEXT_BYTES
        )));
    }
    validate_namespace(&body.namespace)?;

    let owner = &auth.owner;
    let namespace = &body.namespace;
    tracing::info!(
        text_len = body.text.len(),
        owner = %owner,
        namespace = %namespace,
        "analyze request"
    );

    // ── Pre-extraction dedup context ──────────────────────────
    //
    // Before the extractor LLM call, fetch the top-K nearest existing
    // memories for this input. The extractor sees them as
    // `<related_memories>` and uses the context to skip duplicates and
    // anchor borderline facts. This is the architectural fix for the
    // benchmark LME `single_session_assistant` regression — gives the
    // LLM stronger signal for what is new vs already-known, so
    // borderline assistant content gets confidently extracted rather
    // than dropped under "be concise".
    //
    // Pre-extraction context is an *optimisation* — every recall-side
    // failure mode (embed, search, fetch) falls back to plain extraction
    // rather than failing the user's write. A user's write should not
    // depend on their own read working. Each per-leg failure logs a
    // `warn!` so production incidents are visible without breaking the
    // ingest path.
    //
    // Empty-namespace fast path (task #84): a cheap btree existence
    // check on `idx_vector_entries_owner_ns` skips the embed +
    // `search_similar` round-trip on first-ingest-into-a-namespace.
    // pgvector ≤0.7 HNSW with an `owner+namespace` filter does
    // post-filtering and can have a 100-500ms tail on cold namespaces
    // — the existence check eliminates that landmine, saves the embed
    // call ($, ~60-120ms p50), and degrades gracefully on its own
    // failure (treats "unknown" as "non-empty" → fall through to
    // full path, safer than skipping context erroneously).
    let pre_extract_t0 = std::time::Instant::now();
    let mut pre_extract_status = "ok";
    let mut pre_extract_embed_ms: u128 = 0;
    let mut pre_extract_search_ms: u128 = 0;
    let mut pre_extract_walrus_ms: u128 = 0;
    let mut pre_extract_seal_ms: u128 = 0;
    let mut pre_extract_dropped: usize = 0;

    let namespace_has_memories: bool = sqlx::query_scalar::<_, i32>(
        "SELECT 1 FROM vector_entries WHERE owner = $1 AND namespace = $2 LIMIT 1",
    )
    .bind(owner)
    .bind(namespace)
    .fetch_optional(state.db.pool())
    .await
    .map(|r| r.is_some())
    .unwrap_or_else(|e| {
        tracing::warn!(
            error = %e,
            owner = %owner,
            namespace = %namespace,
            "analyze pre-extraction namespace-existence check failed; falling through to full path"
        );
        // Safer to *not* skip the recall when the existence check is
        // ambiguous — degrades to "task #83 behaviour", not "no context".
        true
    });

    let related_memories: Vec<crate::engine::HydratedMemory> = if !namespace_has_memories {
        pre_extract_status = "skipped_empty_namespace";
        Vec::new()
    } else if should_skip_pre_extract_embed(body.text.len()) {
        // The embedder already rejects inputs above its byte cap locally.
        // Classify this expected outcome as a skip instead of logging an
        // embed failure; no network round-trip would occur either way.
        //
        // The consequence is that large inputs extract without dedup context.
        // Recovering it would need summarize-before-embed, the way
        // `remember` does it — not affordable here, where pre-extraction is
        // inline on the caller's request under a ~1.6s total budget while
        // `remember` summarizes inside a spawned job.
        pre_extract_status = "skipped_oversized";
        Vec::new()
    } else {
        // Embed the input as a query. On embed failure, log + degrade —
        // do NOT propagate via `?`, even though the embed below uses the
        // same OpenAI endpoint as per-fact embeds (which DO propagate).
        // The distinction: per-fact embeds produce vectors that get
        // stored (data loss on failure); this one only feeds dedup
        // context (best-effort optimisation).
        // each leg of the pre-extraction recall is wrapped in
        // a `tokio::time::timeout`. On expiry the corresponding status
        // (`embed_timeout`, `search_timeout`, `fetch_timeout`) is set
        // and the context falls back to empty — analyze continues with
        // plain extraction rather than blocking the user's write on a
        // stalled external dependency.
        let embed_t = std::time::Instant::now();
        let input_vector_opt = match tokio::time::timeout(
            std::time::Duration::from_millis(EMBED_TIMEOUT_MS),
            state.embedder.embed(&body.text),
        )
        .await
        {
            Ok(Ok(v)) => Some(v),
            Ok(Err(e)) => {
                tracing::warn!(
                    error = %e,
                    owner = %owner,
                    namespace = %namespace,
                    "analyze pre-extraction embed failed; falling back to plain extract"
                );
                pre_extract_status = "embed_failed";
                None
            }
            Err(_elapsed) => {
                tracing::warn!(
                    owner = %owner,
                    namespace = %namespace,
                    timeout_ms = EMBED_TIMEOUT_MS,
                    "analyze pre-extraction embed timed out; falling back to plain extract"
                );
                pre_extract_status = "embed_timeout";
                None
            }
        };
        pre_extract_embed_ms = embed_t.elapsed().as_millis();

        match input_vector_opt {
            None => Vec::new(),
            Some(input_vector) => {
                let search_t = std::time::Instant::now();
                let search_result = tokio::time::timeout(
                    std::time::Duration::from_millis(SEARCH_TIMEOUT_MS),
                    state.db.search_similar(
                        &input_vector,
                        owner,
                        namespace,
                        PRE_EXTRACTION_CONTEXT_LIMIT,
                    ),
                )
                .await;
                pre_extract_search_ms = search_t.elapsed().as_millis();

                match search_result {
                    Ok(Ok(hits)) if hits.is_empty() => {
                        // Existence check said non-empty but search found
                        // 0 hits — possible if pgvector statistics are
                        // stale or the index hasn't caught up. Rare but
                        // not an error. Just no context this time.
                        Vec::new()
                    }
                    Ok(Ok(hits)) => {
                        let hit_refs: Vec<(String, f64)> = hits
                            .iter()
                            .map(|h| (h.blob_id.clone(), h.distance))
                            .collect();
                        // `fetch_batch` handles decrypt + cache + reactive
                        // cleanup on 404 / decrypt failure. Dropped hits
                        // just shrink the context; the extractor still
                        // works with whatever survives. On total failure
                        // (e.g. sidecar 5xx) or timeout, log and fall back.
                        match tokio::time::timeout(
                            std::time::Duration::from_millis(FETCH_TIMEOUT_MS),
                            state.engine.fetch_batch(owner, namespace, &hit_refs, &auth),
                        )
                        .await
                        {
                            Ok(Ok((hydrated, dropped, timings))) => {
                                pre_extract_walrus_ms = timings.walrus_ms;
                                pre_extract_seal_ms = timings.seal_ms;
                                pre_extract_dropped = dropped;
                                if dropped > 0 {
                                    // Some context memories failed to
                                    // decrypt — surface so we can see
                                    // mass-decrypt-rot in production.
                                    tracing::warn!(
                                        owner = %owner,
                                        namespace = %namespace,
                                        requested = hit_refs.len(),
                                        got = hydrated.len(),
                                        dropped,
                                        "analyze pre-extraction: some context memories dropped at decrypt"
                                    );
                                    pre_extract_status = "ok_with_dropped";
                                }
                                hydrated
                            }
                            Ok(Err(e)) => {
                                tracing::warn!(
                                    error = %e,
                                    owner = %owner,
                                    namespace = %namespace,
                                    "analyze pre-extraction fetch_batch failed; falling back to plain extract"
                                );
                                pre_extract_status = "fetch_failed";
                                Vec::new()
                            }
                            Err(_elapsed) => {
                                tracing::warn!(
                                    owner = %owner,
                                    namespace = %namespace,
                                    timeout_ms = FETCH_TIMEOUT_MS,
                                    "analyze pre-extraction fetch_batch timed out; falling back to plain extract"
                                );
                                pre_extract_status = "fetch_timeout";
                                Vec::new()
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        tracing::warn!(
                            error = %e,
                            owner = %owner,
                            namespace = %namespace,
                            "analyze pre-extraction search_similar failed; falling back to plain extract"
                        );
                        pre_extract_status = "search_failed";
                        Vec::new()
                    }
                    Err(_elapsed) => {
                        tracing::warn!(
                            owner = %owner,
                            namespace = %namespace,
                            timeout_ms = SEARCH_TIMEOUT_MS,
                            "analyze pre-extraction search_similar timed out; falling back to plain extract"
                        );
                        pre_extract_status = "search_timeout";
                        Vec::new()
                    }
                }
            }
        }
    };
    let related_texts: Vec<&str> = related_memories.iter().map(|m| m.text.as_str()).collect();
    let pre_extract_ms = pre_extract_t0.elapsed().as_millis();
    tracing::info!(
        owner = %owner,
        namespace = %namespace,
        related_count = related_texts.len(),
        requested = PRE_EXTRACTION_CONTEXT_LIMIT,
        dropped = pre_extract_dropped,
        pre_extract_ms = %pre_extract_ms,
        embed_ms = %pre_extract_embed_ms,
        search_ms = %pre_extract_search_ms,
        walrus_ms = %pre_extract_walrus_ms,
        seal_ms = %pre_extract_seal_ms,
        status = pre_extract_status,
        "analyze pre-extraction context retrieved"
    );

    // Step 1: Extract facts using the Extractor service (sync — fast, ~1-2s).
    // pass `related_memories` as dedup context. The LlmExtractor
    // short-circuits to plain `extract` on empty slice — no wasted tokens
    // when the namespace had no nearest hits.
    // also pass `body.occurred_at` as the temporal anchor. When
    // present, the extractor renders a `<context occurred_at="..."/>` tag
    // alongside the prompt so the LLM can resolve relative-time
    // references ("last Friday") to absolute dates *inside the extracted
    // fact text* (Architecture A — no metadata column, date flows into
    // the encrypted blob + embedding only).
    let extracted = state
        .extractor
        .extract_with_context(&body.text, &related_texts, body.occurred_at)
        .await?;
    let raw_fact_count = extracted.raw_count;
    // Screen extracted facts before embedding or SEAL encryption (#435) so any
    // credential material emitted or re-assembled by the extractor LLM is
    // redacted or dropped before reaching append-only Walrus storage.
    let facts = screen_extracted_facts(extracted.facts);
    let reserved_additional_weight = rate_limit::analyze_additional_weight(facts.len());
    tracing::info!(
        "  → Extracted {} facts (accepted={} cap={})",
        raw_fact_count,
        facts.len(),
        MAX_ANALYZE_FACTS,
    );

    if facts.is_empty() {
        return Ok((
            StatusCode::ACCEPTED,
            Json(AnalyzeAcceptedResponse {
                job_ids: vec![],
                facts: vec![],
                fact_count: 0,
                status: "pending".to_string(),
                owner: owner.clone(),
            }),
        ));
    }

    rate_limit::charge_explicit_weight(&state, &auth, reserved_additional_weight, "/api/analyze")
        .await?;

    // ── Benchmark-mode bypass: synchronous ingestion ──────────────────────
    //
    // The production path below is async (encrypt → enqueue WalletJob →
    // worker uploads to Walrus → insert_vector → SDK polls job_id). The
    // benchmark harness expects `POST /api/analyze` to return when the
    // memories are stored and searchable, the way the SDK's synchronous
    // analyze contract worked before. In benchmark mode we honour
    // that: per fact, embed → engine.store_blob(plaintext bytes) (the
    // PlaintextEngine writes the `plaintext` column — no SEAL, no Walrus,
    // no Sui transaction, no job row), in parallel across facts. The
    // response carries the real stored ids and status "done".
    //
    // Production behaviour is untouched — this branch only runs when
    // BENCHMARK_MODE is on (which is off by default and not for production).
    if state.config.benchmark_mode {
        // Quota check on plaintext byte length (benchmark mode has no
        // ciphertext — plaintext is the closest analog).
        let total_plaintext_bytes: i64 = facts.iter().map(|f| f.text.len() as i64).sum();
        // Inline path: one reservation covering the whole batch, released once
        // the rows are committed. Local id because these rows have no
        // `remember_jobs` row to key on (benchmark mode skips the job queue).
        let reservation_id = uuid::Uuid::new_v4().to_string();
        rate_limit::reserve_storage_quota_one(
            &state,
            owner,
            reservation_id.clone(),
            total_plaintext_bytes,
        )
        .await?;

        let store_tasks: Vec<_> = facts
            .iter()
            .map(|fact| {
                let state = Arc::clone(&state);
                let owner = owner.clone();
                let account_id = auth.account_id.clone();
                let namespace = namespace.clone();
                let agent_pk = auth.public_key.clone();
                let fact = fact.clone();
                async move {
                    let vector = state.embedder.embed(&fact.text).await?;
                    // importance is threaded through the engine
                    // (see store_blob signature in engine::MemoryEngine).
                    // The PlaintextEngine persists it on the new
                    // `vector_entries.importance` column; the ranker
                    // consumes it at recall time.
                    let mref = state
                        .engine
                        .store_blob(
                            &owner,
                            &account_id,
                            &namespace,
                            fact.text.as_bytes(),
                            &vector,
                            fact.importance,
                            Some(&agent_pk),
                        )
                        .await?;
                    Ok::<_, AppError>(AnalyzeAcceptedFact {
                        text: fact.text,
                        id: mref.id.clone(),
                        job_id: mref.id,
                    })
                }
            })
            .collect();

        let store_results = collect_bounded_results(store_tasks, ANALYZE_CONCURRENCY).await;

        // Release before the `?` below so a partial failure cannot strand the
        // reservation for the full TTL. Any facts that did land are already
        // counted as rows, and the ones that did not should not keep holding
        // quota.
        rate_limit::release_storage_quota_one(&state, &reservation_id).await;

        let mut stored_facts: Vec<AnalyzeAcceptedFact> = Vec::with_capacity(store_results.len());
        for r in store_results {
            stored_facts.push(r?);
        }

        let fact_count = stored_facts.len();
        let job_ids: Vec<String> = stored_facts.iter().map(|f| f.id.clone()).collect();
        tracing::info!(
            "analyze (benchmark mode) complete: {} facts stored synchronously owner={} ns={}",
            fact_count,
            owner,
            namespace
        );

        return Ok((
            StatusCode::ACCEPTED,
            Json(AnalyzeAcceptedResponse {
                job_ids,
                facts: stored_facts,
                fact_count,
                // "done" (not "pending") — the memories are stored and
                // searchable by the time this response is sent. "done"
                // matches the existing remember_jobs status vocabulary
                // ("done" = stored, blob_id known), rather than coining a
                // new term for the benchmark-only case.
                status: "done".to_string(),
                owner: owner.clone(),
            }),
        ));
    }

    // Step 2: embed + SEAL encrypt all facts concurrently (no wallet needed yet).
    // This is the fast part (~300-500ms), done in the request handler so:
    //   - No plaintext stored in job payload
    //   - Exact ciphertext size known for quota check
    let auth_pubkey_base = auth.public_key.clone();
    let account_id = auth.account_id.clone();
    let prep_tasks: Vec<_> = facts
        .iter()
        .map(|fact| {
            let state = Arc::clone(&state);
            let owner = owner.clone();
            let account_id = account_id.clone();
            let fact = fact.clone();
            async move {
                let embed_fut = state.embedder.embed(&fact.text);
                let encrypt_fut = crate::storage::seal::seal_encrypt(
                    &state.http_client,
                    &state.config.seal_sidecar_url,
                    state.config.sidecar_secret.as_deref(),
                    fact.text.as_bytes(),
                    &owner,
                    &account_id,
                    &state.config.package_id,
                    state.config.seal_expected_committee_identity.as_ref(),
                );
                let (vector_result, encrypted_result) = tokio::join!(embed_fut, encrypt_fut);
                // carry `importance` through the prep tuple so
                // the job payload below can persist it alongside the
                // ciphertext + vector.
                Ok::<_, AppError>((
                    fact.text,
                    fact.importance,
                    vector_result?,
                    encrypted_result?,
                ))
            }
        })
        .collect();

    let prep_results = collect_bounded_results(prep_tasks, ANALYZE_CONCURRENCY).await;

    // Exact ciphertext size per fact is known here, which is what the
    // per-fact reservations below are sized from.
    let mut prepared: Vec<PreparedFact> = Vec::with_capacity(prep_results.len());
    for r in prep_results {
        prepared.push(r?);
    }
    // Job ids are minted here, before admission, rather than inside the loop
    // below: each one keys the reservation for the fact it will store, so
    // jobs.rs can release from the job id it already carries once the vector
    // row lands. The insert happens minutes later (after the Walrus upload),
    // which is exactly the window a bare check left unprotected.
    let pending: Vec<(String, PreparedFact)> = prepared
        .into_iter()
        .map(|fact| (uuid::Uuid::new_v4().to_string(), fact))
        .collect();

    // All-or-nothing across the batch, so an over-quota analyze request is
    // still rejected whole with the same 402 shape.
    let reservations: Vec<crate::storage::db::StorageReservationRequest> = pending
        .iter()
        .map(
            |(job_id, (_, _, _, encrypted))| crate::storage::db::StorageReservationRequest {
                id: job_id.clone(),
                bytes: encrypted.len() as i64,
            },
        )
        .collect();
    rate_limit::reserve_storage_quota(&state, owner, &reservations).await?;

    // Facts are enqueued in order, so at iteration `idx` the set
    // `all_ids[idx..]` is exactly what holds a reservation with no queued job
    // to release it. Those get released explicitly if we bail out mid-loop;
    // without that they would sit against the owner's quota until the TTL.
    let all_ids: Vec<String> = pending.iter().map(|(id, _)| id.clone()).collect();

    // Step 3: For each prepared fact — insert remember_jobs row + enqueue WalletJob.
    // Round-robin across wallet pool so facts upload in parallel.
    let mut job_ids: Vec<String> = Vec::with_capacity(pending.len());
    let mut accepted_facts: Vec<AnalyzeAcceptedFact> = Vec::with_capacity(pending.len());
    for (idx, (job_id, (fact_text, importance, vector, encrypted))) in
        pending.into_iter().enumerate()
    {
        let idem_key = analyze_fact_idempotency_key(owner, namespace, &fact_text);
        let inserted = match sqlx::query(
            "INSERT INTO remember_jobs (id, owner, namespace, status, idempotency_key, request_fingerprint)
             VALUES ($1, $2, $3, 'pending', $4, $4)
             ON CONFLICT (owner, namespace, idempotency_key) WHERE idempotency_key IS NOT NULL DO NOTHING",
        )
        .bind(&job_id)
        .bind(owner)
        .bind(namespace)
        .bind(&idem_key)
        .execute(state.db.pool())
        .await
        {
            Ok(result) => result,
            Err(e) if super::remember::is_idempotency_key_unique_violation(&e) => {
                rate_limit::release_storage_quota(&state, &all_ids[idx..]).await;
                return Err(AppError::Conflict(
                    super::remember::IDEMPOTENCY_KEY_CONFLICT_MESSAGE.into(),
                ));
            }
            Err(e) => {
                rate_limit::release_storage_quota(&state, &all_ids[idx..]).await;
                return Err(AppError::Internal(format!(
                    "Failed to create analyze job row: {}",
                    e
                )));
            }
        };
        let mut upload_job_id = job_id.clone();
        if inserted.rows_affected() == 0 {
            rate_limit::release_storage_quota(&state, std::slice::from_ref(&job_id)).await;
            let existing = sqlx::query_as::<_, (String, String, Option<String>)>(
                "SELECT id, status, blob_id FROM remember_jobs WHERE owner = $1 AND namespace = $2 AND idempotency_key = $3",
            )
            .bind(owner)
            .bind(namespace)
            .bind(&idem_key)
            .fetch_optional(state.db.pool())
            .await;
            match existing {
                Err(e) => {
                    rate_limit::release_storage_quota(&state, &all_ids[idx + 1..]).await;
                    return Err(AppError::Internal(format!(
                        "Failed to look up analyze job: {}",
                        e
                    )));
                }
                Ok(None) => {
                    rate_limit::release_storage_quota(&state, &all_ids[idx + 1..]).await;
                    if super::remember::has_remember_job_for_owner_key(
                        state.db.pool(),
                        owner,
                        &idem_key,
                    )
                    .await?
                    {
                        return Err(AppError::Conflict(
                            super::remember::IDEMPOTENCY_KEY_CONFLICT_MESSAGE.into(),
                        ));
                    }
                    return Err(AppError::Internal(
                        "Failed to create analyze job row: insert affected no rows".into(),
                    ));
                }
                Ok(Some((existing_id, status, blob_id))) => {
                    let live_importance = match sqlx::query_scalar::<_, f32>(
                        "SELECT importance FROM vector_entries
                         WHERE id = $1 AND owner = $2 AND namespace = $3",
                    )
                    .bind(&existing_id)
                    .bind(owner)
                    .bind(namespace)
                    .fetch_optional(state.db.pool())
                    .await
                    {
                        Ok(value) => value,
                        Err(e) => {
                            rate_limit::release_storage_quota(&state, &all_ids[idx + 1..]).await;
                            return Err(AppError::Internal(format!(
                                "Failed to look up analyze memory: {}",
                                e
                            )));
                        }
                    };
                    let reuse = classify_analyze_job_reuse(
                        &status,
                        blob_id.as_deref(),
                        live_importance,
                        importance,
                    );
                    let rewrite = match reuse {
                        AnalyzeJobReuse::Collapse => {
                            accepted_facts.push(AnalyzeAcceptedFact {
                                text: fact_text,
                                id: existing_id.clone(),
                                job_id: existing_id.clone(),
                            });
                            job_ids.push(existing_id);
                            continue;
                        }
                        AnalyzeJobReuse::UpdateImportance => {
                            match state
                                .db
                                .update_vector_importance(
                                    &existing_id,
                                    owner,
                                    namespace,
                                    importance,
                                )
                                .await
                            {
                                Ok(true) => {
                                    accepted_facts.push(AnalyzeAcceptedFact {
                                        text: fact_text,
                                        id: existing_id.clone(),
                                        job_id: existing_id.clone(),
                                    });
                                    job_ids.push(existing_id);
                                    continue;
                                }
                                Ok(false) => true,
                                Err(e) => {
                                    rate_limit::release_storage_quota(&state, &all_ids[idx + 1..])
                                        .await;
                                    return Err(e);
                                }
                            }
                        }
                        AnalyzeJobReuse::RewriteForgotten => true,
                        AnalyzeJobReuse::RetryUnpaidFailure => false,
                    };
                    if rewrite {
                        if let Err(e) = sqlx::query(
                            "UPDATE remember_jobs
                             SET idempotency_key = NULL, updated_at = NOW()
                             WHERE id = $1 AND owner = $2",
                        )
                        .bind(&existing_id)
                        .bind(owner)
                        .execute(state.db.pool())
                        .await
                        {
                            rate_limit::release_storage_quota(&state, &all_ids[idx + 1..]).await;
                            return Err(AppError::Internal(format!(
                                "Failed to release analyze idempotency key: {}",
                                e
                            )));
                        }
                        let rewritten = match sqlx::query(
                            "INSERT INTO remember_jobs (id, owner, namespace, status, idempotency_key, request_fingerprint)
                             VALUES ($1, $2, $3, 'pending', $4, $4)
                             ON CONFLICT (owner, namespace, idempotency_key) WHERE idempotency_key IS NOT NULL DO NOTHING",
                        )
                        .bind(&job_id)
                        .bind(owner)
                        .bind(namespace)
                        .bind(&idem_key)
                        .execute(state.db.pool())
                        .await
                        {
                            Ok(result) => result,
                            Err(e) if super::remember::is_idempotency_key_unique_violation(&e) => {
                                rate_limit::release_storage_quota(&state, &all_ids[idx + 1..])
                                    .await;
                                return Err(AppError::Conflict(
                                    super::remember::IDEMPOTENCY_KEY_CONFLICT_MESSAGE.into(),
                                ));
                            }
                            Err(e) => {
                                rate_limit::release_storage_quota(&state, &all_ids[idx + 1..])
                                    .await;
                                return Err(AppError::Internal(format!(
                                    "Failed to recreate analyze job row: {}",
                                    e
                                )));
                            }
                        };
                        if rewritten.rows_affected() == 0 {
                            // Another retry won the key after we released it.
                            let winner = sqlx::query_scalar::<_, String>(
                                "SELECT id FROM remember_jobs WHERE owner = $1 AND namespace = $2 AND idempotency_key = $3",
                            )
                            .bind(owner)
                            .bind(namespace)
                            .bind(&idem_key)
                            .fetch_optional(state.db.pool())
                            .await;
                            match winner {
                                Ok(Some(winner_id)) => {
                                    accepted_facts.push(AnalyzeAcceptedFact {
                                        text: fact_text,
                                        id: winner_id.clone(),
                                        job_id: winner_id.clone(),
                                    });
                                    job_ids.push(winner_id);
                                    continue;
                                }
                                Ok(None) => {
                                    rate_limit::release_storage_quota(&state, &all_ids[idx + 1..])
                                        .await;
                                    return Err(AppError::Internal(
                                        "Failed to recreate analyze job row: insert affected no rows"
                                            .into(),
                                    ));
                                }
                                Err(e) => {
                                    rate_limit::release_storage_quota(&state, &all_ids[idx + 1..])
                                        .await;
                                    return Err(AppError::Internal(format!(
                                        "Failed to look up analyze job: {}",
                                        e
                                    )));
                                }
                            }
                        }
                        if let Err(e) = rate_limit::reserve_storage_quota(
                            &state,
                            owner,
                            &[crate::storage::db::StorageReservationRequest {
                                id: job_id.clone(),
                                bytes: encrypted.len() as i64,
                            }],
                        )
                        .await
                        {
                            rate_limit::release_storage_quota(&state, &all_ids[idx + 1..]).await;
                            return Err(e);
                        }
                    } else {
                        let reset = match sqlx::query(unpaid_analyze_retry_reset_sql())
                            .bind(&existing_id)
                            .execute(state.db.pool())
                            .await
                        {
                            Ok(result) => result,
                            Err(e) => {
                                rate_limit::release_storage_quota(&state, &all_ids[idx + 1..])
                                    .await;
                                return Err(AppError::Internal(format!(
                                    "Failed to reset analyze job: {}",
                                    e
                                )));
                            }
                        };
                        // A resume past encode, or a row that is no longer an
                        // unpaid failure, must not be overwritten with new
                        // ciphertext.
                        if reset.rows_affected() == 0 {
                            accepted_facts.push(AnalyzeAcceptedFact {
                                text: fact_text,
                                id: existing_id.clone(),
                                job_id: existing_id.clone(),
                            });
                            job_ids.push(existing_id);
                            continue;
                        }
                        if let Err(e) = rate_limit::reserve_storage_quota(
                            &state,
                            owner,
                            &[crate::storage::db::StorageReservationRequest {
                                id: existing_id.clone(),
                                bytes: encrypted.len() as i64,
                            }],
                        )
                        .await
                        {
                            rate_limit::release_storage_quota(&state, &all_ids[idx + 1..]).await;
                            return Err(e);
                        }
                        upload_job_id = existing_id;
                    }
                }
            }
        }

        // Pick next wallet slot (round-robin) and enqueue UploadAndTransfer
        let Some(wallet_index) = state.key_pool.least_loaded_index() else {
            rate_limit::release_storage_quota(&state, &all_ids[idx..]).await;
            return Err(AppError::Internal("No Sui keys configured".into()));
        };
        let encrypted_b64 = base64::engine::general_purpose::STANDARD.encode(&encrypted);

        if let Err(e) = enqueue_wallet_job(
            &state,
            wallet_index,
            WalletOperation::UploadAndTransfer {
                encrypted_b64,
                vector,
                importance,
                owner: owner.clone(),
                namespace: namespace.clone(),
                package_id: state.config.package_id.clone(),
                account_id: account_id.clone(),
                agent_public_key: Some(auth_pubkey_base.clone()),
                remember_job_id: Some(upload_job_id.clone()),
                prepare_claim_token: None,
                epochs: state.config.walrus_storage_epochs,
            },
        )
        .await
        {
            let _ = sqlx::query(
                "UPDATE remember_jobs SET status = 'failed', error_msg = $2, updated_at = NOW()
                 WHERE id = $1 AND blob_id IS NULL",
            )
            .bind(&upload_job_id)
            .bind(e.to_string())
            .execute(state.db.pool())
            .await;
            rate_limit::release_storage_quota(&state, std::slice::from_ref(&upload_job_id)).await;
            rate_limit::release_storage_quota(&state, &all_ids[idx + 1..]).await;
            return Err(AppError::Internal(format!(
                "Failed to enqueue analyze job: {}",
                e
            )));
        }

        // Queued: jobs.rs owns this reservation from here on.

        tracing::info!(
            job_id = %upload_job_id,
            wallet_index,
            fact_len = fact_text.len(),
            "analyze fact enqueued"
        );
        accepted_facts.push(AnalyzeAcceptedFact {
            text: fact_text,
            id: upload_job_id.clone(),
            job_id: upload_job_id.clone(),
        });
        job_ids.push(upload_job_id);
    }

    let fact_count = job_ids.len();
    tracing::info!(
        "analyze accepted: {} facts enqueued owner={} ns={}",
        fact_count,
        owner,
        namespace
    );

    Ok((
        StatusCode::ACCEPTED,
        Json(AnalyzeAcceptedResponse {
            job_ids,
            facts: accepted_facts,
            fact_count,
            status: "pending".to_string(),
            owner: owner.clone(),
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::{
        analyze_fact_idempotency_key, classify_analyze_job_reuse, should_skip_pre_extract_embed,
        unpaid_analyze_retry_reset_sql, AnalyzeJobReuse, ANALYZE_CONCURRENCY,
        MAX_ANALYZE_TEXT_BYTES, MAX_PRE_EXTRACT_EMBED_BYTES,
    };
    use crate::routes::remember::MAX_REMEMBER_TEXT_BYTES;
    use crate::services::extractor::MAX_ANALYZE_FACTS;

    // ── Text size limit ──────────────────────────────────────────

    #[test]
    fn max_analyze_text_bytes_is_64kb() {
        assert_eq!(MAX_ANALYZE_TEXT_BYTES, 64 * 1024);
    }

    #[test]
    fn analyze_text_strictly_smaller_than_remember() {
        // Analyze does fact extraction in a single LLM call without
        // chunking, so its ceiling must stay below remember's.
        const { assert!(MAX_ANALYZE_TEXT_BYTES < MAX_REMEMBER_TEXT_BYTES) }
    }

    // ── Pre-extraction embed size guard (WALM-411) ───────────────

    #[test]
    fn max_pre_extract_embed_bytes_is_16kb() {
        assert_eq!(MAX_PRE_EXTRACT_EMBED_BYTES, 16 * 1024);
    }

    #[test]
    fn pre_extract_guard_is_reachable_below_the_accepted_input_ceiling() {
        // If the guard sat at or above the endpoint's own cap it could never
        // fire, and the skip would be dead code.
        const { assert!(MAX_PRE_EXTRACT_EMBED_BYTES < MAX_ANALYZE_TEXT_BYTES) }
        // Lowering the embedder cap must not leave analyze attempting inputs
        // that are guaranteed to fail its local validation.
        const { assert!(MAX_PRE_EXTRACT_EMBED_BYTES <= crate::services::embedder::MAX_EMBED_INPUT_BYTES) }
    }

    #[test]
    fn embed_is_attempted_at_and_below_the_threshold() {
        assert!(!should_skip_pre_extract_embed(0));
        assert!(!should_skip_pre_extract_embed(1));
        // Preserve dedup attempts in the band the original 8 KiB guard skipped.
        assert!(!should_skip_pre_extract_embed(8 * 1024 + 1));
        assert!(!should_skip_pre_extract_embed(12 * 1024));
        assert!(!should_skip_pre_extract_embed(
            MAX_PRE_EXTRACT_EMBED_BYTES - 1
        ));
        // Boundary: exactly at the limit is still handed to the embedder.
        assert!(!should_skip_pre_extract_embed(MAX_PRE_EXTRACT_EMBED_BYTES));
    }

    #[test]
    fn embed_is_skipped_above_the_threshold() {
        assert!(should_skip_pre_extract_embed(
            MAX_PRE_EXTRACT_EMBED_BYTES + 1
        ));
        assert!(should_skip_pre_extract_embed(MAX_ANALYZE_TEXT_BYTES));
    }

    #[test]
    fn observed_production_rejection_would_now_be_skipped() {
        // Regression anchor: a real 31,782-byte /api/analyze input was
        // rejected by the embedding API on 2026-08-27 with
        // `Invalid 'input': maximum context length is 8192`, after burning
        // 564ms. Since #837, the embedder rejects it locally; analyze should
        // classify it as skipped_oversized instead of embed_failed.
        assert!(should_skip_pre_extract_embed(31_782));
    }

    // ── Analyze concurrency + weight ────────────────────

    #[test]
    fn analyze_concurrency_constant_is_5() {
        assert_eq!(ANALYZE_CONCURRENCY, 5);
    }

    #[test]
    fn analyze_fact_idempotency_key_is_stable_and_namespaced() {
        let a = analyze_fact_idempotency_key("0xowner", "work", "likes rust");
        let b = analyze_fact_idempotency_key("0xowner", "work", "likes rust");
        let c = analyze_fact_idempotency_key("0xowner", "work", "likes go");
        let other_owner = analyze_fact_idempotency_key("0xother", "work", "likes rust");
        let other_ns = analyze_fact_idempotency_key("0xowner", "home", "likes rust");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, other_owner);
        assert_ne!(a, other_ns);
        assert!(a.starts_with("analyze:"));
    }

    #[test]
    fn classify_collapses_inflight_and_matching_live_row() {
        assert_eq!(
            classify_analyze_job_reuse("pending", None, None, 0.5),
            AnalyzeJobReuse::Collapse
        );
        assert_eq!(
            classify_analyze_job_reuse("uploaded", Some("blob"), None, 0.5),
            AnalyzeJobReuse::Collapse
        );
        assert_eq!(
            classify_analyze_job_reuse("done", Some("blob"), Some(0.5), 0.5),
            AnalyzeJobReuse::Collapse
        );
        // Paid-but-not-indexed: do not mint a second blob.
        assert_eq!(
            classify_analyze_job_reuse("failed", Some("blob"), None, 0.5),
            AnalyzeJobReuse::Collapse
        );
    }

    #[test]
    fn classify_retries_unpaid_failure() {
        assert_eq!(
            classify_analyze_job_reuse("failed", None, None, 0.5),
            AnalyzeJobReuse::RetryUnpaidFailure
        );
    }

    #[test]
    fn unpaid_retry_drops_the_encoded_checkpoint_only() {
        let sql = unpaid_analyze_retry_reset_sql();
        assert!(sql.contains("upload_resume_step = NULL"));
        assert!(sql.contains("upload_register_transaction = NULL"));
        assert!(sql.contains("upload_wallet_address = NULL"));
        assert!(sql.contains("blob_id IS NULL"));
        assert!(sql.contains("blob_object_id IS NULL"));
        assert!(sql.contains("upload_resume_step->>'step' = 'encoded'"));
        assert!(!sql.contains("preparation_encrypted_b64"));
    }

    #[test]
    fn classify_updates_importance_on_live_row() {
        assert_eq!(
            classify_analyze_job_reuse("done", Some("blob"), Some(0.2), 0.9),
            AnalyzeJobReuse::UpdateImportance
        );
    }

    #[test]
    fn classify_rewrites_when_done_job_has_no_live_memory() {
        assert_eq!(
            classify_analyze_job_reuse("done", Some("blob"), None, 0.5),
            AnalyzeJobReuse::RewriteForgotten
        );
    }

    #[test]
    fn max_analyze_facts_constant_is_20() {
        assert_eq!(MAX_ANALYZE_FACTS, 20);
    }

    #[test]
    fn analyze_weight_proportional_to_facts() {
        use crate::rate_limit::{analyze_additional_weight, analyze_total_weight};
        // No facts → only base weight
        assert_eq!(analyze_total_weight(0), 5);
        // Max facts (20) → 5 + 20 = 25
        assert_eq!(analyze_total_weight(20), 25);
        // Additional weight is exactly fact_count
        assert_eq!(analyze_additional_weight(0), 0);
        assert_eq!(analyze_additional_weight(20), 20);
    }

    // ── Post-extraction secret screening (#435) ───────────────────

    #[test]
    fn post_extraction_redacts_suiprivkey_and_vendor_keys_while_keeping_surrounding_fact() {
        use super::{screen_extracted_facts, screen_fact_text};
        use crate::services::extractor::ExtractedFact;

        let repro_key = "suiprivkey1qzfake0000000000000000000000000000000000000000000000000000";
        let valid_key = "suiprivkey1qqtac0q7an7dcq2vp6axts0c0zt6hw7jznar94qp3ayxdx6axlzpxcetm48";

        // Bare credential with no surrounding fact is dropped completely.
        assert_eq!(screen_fact_text(repro_key), None);
        assert_eq!(screen_fact_text(valid_key), None);
        assert_eq!(
            screen_fact_text("sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789"),
            None
        );

        // Fact carrying a credential keeps the surrounding words and redacts the secret.
        let mixed = format!("User deploys on testnet using {repro_key} from laptop");
        let screened = screen_fact_text(&mixed).expect("fact around secret should survive");
        assert!(!screened.contains(repro_key));
        assert!(screened.contains("[redacted:vendor-api-key]"));
        assert!(screened.contains("User deploys on testnet"));

        // URL credentials keep host/path and strip userinfo.
        let url_fact =
            "Staging database lives at postgres://admin:hunter2@db.internal:5432/app for testing";
        let screened_url = screen_fact_text(url_fact).expect("url fact should survive");
        assert!(!screened_url.contains("hunter2"));
        assert!(screened_url.contains("postgres://[redacted:url-credentials]@db.internal:5432/app"));

        // PEM private key block is redacted.
        let pem_fact = "User's old box key -----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY----- was rotated";
        let screened_pem = screen_fact_text(pem_fact).expect("pem fact should survive");
        assert!(!screened_pem.contains("BEGIN OPENSSH PRIVATE KEY"));
        assert!(screened_pem.contains("[redacted:private-key-block]"));

        // Credential assignment (#435 review finding from @ducnmm).
        let assign_fact = "User staging DB password is POSTGRES_PASSWORD=hunter2 for local testing";
        let screened_assign =
            screen_fact_text(assign_fact).expect("assignment fact should survive");
        assert!(!screened_assign.contains("hunter2"));
        assert!(screened_assign.contains("POSTGRES_PASSWORD=[redacted:credential-assignment]"));
        assert!(screened_assign.contains("User staging DB password is"));

        // Bare credential assignment with no surrounding fact is dropped.
        assert_eq!(screen_fact_text("POSTGRES_PASSWORD=hunter2"), None);
        assert_eq!(screen_fact_text("api_key = secret1234567890"), None);

        // Auth header is redacted.
        let auth_fact =
            "User tests endpoint using Authorization: Bearer token1234567890 on dev host";
        let screened_auth = screen_fact_text(auth_fact).expect("auth header fact should survive");
        assert!(!screened_auth.contains("token1234567890"));
        assert!(screened_auth.contains("Authorization: [redacted:auth-header]"));

        // Seed phrase is redacted.
        let seed_fact = "User wallet seed phrase is apple banana cherry date dog elephant fish goat horse island jungle kite on ledger";
        let screened_seed = screen_fact_text(seed_fact).expect("seed phrase fact should survive");
        assert!(!screened_seed.contains("apple banana cherry"));
        assert!(screened_seed.contains("[redacted:seed-phrase]"));

        // Labelled hex key material is redacted, while unlabelled commit SHA is kept.
        let labelled_key = "User delegate private key is 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef in backup";
        let screened_labelled =
            screen_fact_text(labelled_key).expect("labelled key fact should survive");
        assert!(!screened_labelled
            .contains("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
        assert!(screened_labelled.contains("[redacted:labelled-key-material]"));

        let commit_sha =
            "User deployed relayer from commit 4f2b8c1e3a5d7f90123456789abcdef012345678 yesterday";
        let screened_commit =
            screen_fact_text(commit_sha).expect("clean commit sha should survive");
        assert!(screened_commit.contains("4f2b8c1e3a5d7f90123456789abcdef012345678"));

        // Multilingual and emoji context windows must not panic on char boundaries (#435).
        let unicode_fact = format!(
            "User loves {} and secret is {}",
            "😀".repeat(13),
            "a".repeat(64)
        );
        let screened_unicode =
            screen_fact_text(&unicode_fact).expect("unicode fact should survive without panic");
        assert!(screened_unicode.contains("User loves"));
        assert!(screened_unicode.contains(&"😀".repeat(13)));
        assert!(screened_unicode.contains("[redacted:labelled-key-material]"));

        let non_secret_unicode = format!("User status: {} {}", "😀".repeat(13), "a".repeat(64));
        let screened_non_secret =
            screen_fact_text(&non_secret_unicode).expect("unlabelled unicode hex fact survives");
        assert!(screened_non_secret.contains(&"a".repeat(64)));

        // Batch screening drops credential-only facts and preserves clean/redacted facts.
        let batch = vec![
            ExtractedFact {
                text: "User prefers dark mode".to_string(),
                importance: 0.5,
            },
            ExtractedFact {
                text: repro_key.to_string(),
                importance: 0.9,
            },
            ExtractedFact {
                text: "User's Sui package id is 0xe80f2feec1c139616a86c9f71210152e2a7ca552b20841f2e192f99f75864437".to_string(),
                importance: 0.5,
            },
        ];
        let kept = screen_extracted_facts(batch);
        assert_eq!(kept.len(), 2);
        assert_eq!(kept[0].text, "User prefers dark mode");
        assert!(kept[1]
            .text
            .contains("0xe80f2feec1c139616a86c9f71210152e2a7ca552b20841f2e192f99f75864437"));
    }
}
