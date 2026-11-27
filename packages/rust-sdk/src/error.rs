//! Error types returned by the Walrus Memory Rust SDK.

use std::time::Duration;

/// Convenience alias for `std::result::Result<T, Error>`.
pub type Result<T> = std::result::Result<T, Error>;

/// Type-erased error cause used to preserve error chains without exposing
/// third-party HTTP or serialization crate types in the public signature.
pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Errors produced by [`crate::MemWal`], [`crate::MemWalBuilder`], and SDK helpers.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Private key bytes, hex string, or `suiprivkey1` Bech32 encoding could not be parsed.
    #[error("invalid delegate private key: {0}")]
    InvalidKey(String),

    /// Server URL was empty, malformed, or used an unsupported scheme.
    #[error("invalid server url: {0}")]
    InvalidUrl(String),

    /// Caller passed an out-of-range or blank argument before a request was signed.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// Operation attempted after [`crate::MemWal::destroy`] wiped key material.
    #[error("memwal client has been destroyed; create a new instance to make further requests")]
    Destroyed,

    /// Authentication or authorization failed (`HTTP 401` or `HTTP 403`).
    #[error("authentication rejected (HTTP {status}): {message}")]
    AuthRejected {
        /// HTTP status code (`401` or `403`).
        status: u16,
        /// Optional machine-readable error code from the relayer.
        code: Option<String>,
        /// Sanitized diagnostic message.
        message: String,
    },

    /// Request timestamp fell outside the relayer clock-drift window.
    #[error("request clock drift rejected: {message}")]
    ClockDrift {
        /// Diagnostic guidance explaining how to synchronize local system time.
        message: String,
    },

    /// Relayer rate limit was exceeded (`HTTP 429`).
    #[error("rate limit exceeded: {message}")]
    RateLimited {
        /// Server-advertised backoff duration from `Retry-After` or response body.
        retry_after: Option<Duration>,
        /// Optional job IDs affected when bulk polling was rate limited.
        job_ids: Vec<String>,
        /// Sanitized diagnostic message.
        message: String,
    },

    /// Relayer API major version or minimum SDK floor is incompatible with this crate.
    #[error("incompatible relayer contract: {message}")]
    Incompatible {
        /// Human-readable upgrade or endpoint guidance.
        message: String,
    },

    /// Building or verifying an ephemeral SEAL `x-seal-session` credential failed.
    #[error("failed to build seal session: {0}")]
    SealSession(String),

    /// Relayer returned a non-success HTTP status not covered by a more specific variant.
    #[error("relayer error (HTTP {status}): {message}")]
    Server {
        /// HTTP status code returned by the relayer.
        status: u16,
        /// Optional machine-readable error code from the relayer JSON body.
        code: Option<String>,
        /// Sanitized diagnostic message.
        message: String,
    },

    /// A single HTTP request exceeded its configured deadline.
    #[error("request timed out after {}ms ({method} {path})", elapsed.as_millis())]
    RequestTimeout {
        /// HTTP method (`GET` or `POST`).
        method: String,
        /// Request path.
        path: String,
        ///Configured deadline that elapsed.
        elapsed: Duration,
    },

    /// Underlying network or TLS transport failed before an HTTP response completed.
    #[error("transport error during {context}: {source}")]
    Transport {
        /// Operation label describing the failed network phase.
        context: &'static str,
        /// Underlying transport cause.
        #[source]
        source: BoxError,
    },

    /// Response payload was empty or invalid JSON, or lacked required wire fields.
    #[error("invalid json payload for {context}: {source}")]
    Json {
        /// Endpoint or operation context.
        context: String,
        /// Underlying parse or schema cause.
        #[source]
        source: BoxError,
    },

    /// Background `remember` job settled in the `failed` terminal state.
    #[error("remember job {job_id} failed: {message}")]
    JobFailed {
        /// Failed job identifier.
        job_id: String,
        /// Sanitized error reported by the worker.
        message: String,
    },

    /// Background `remember` job ID was unknown or did not belong to this caller.
    #[error("remember job {job_id} was not found")]
    JobNotFound {
        /// Missing job identifier.
        job_id: String,
    },

    /// Polling budget expired before a background `remember` job reached a terminal state.
    #[error("remember job {job_id} timed out after {}ms", elapsed.as_millis())]
    JobTimeout {
        /// Unsettled job identifier.
        job_id: String,
        /// Total wait budget that elapsed.
        elapsed: Duration,
        /// Last non-terminal status observed, if any poll succeeded.
        last_status: Option<String>,
        /// Whether at least one poll encountered `HTTP 429` during the wait window.
        saw_rate_limit: bool,
    },
}

impl Error {
    /// Returns the HTTP status code associated with this error, if one was received.
    #[must_use]
    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::AuthRejected { status, .. } | Self::Server { status, .. } => Some(*status),
            Self::ClockDrift { .. } => Some(401),
            Self::RateLimited { .. } => Some(429),
            Self::RequestTimeout { .. } => Some(504),
            Self::InvalidKey(_)
            | Self::InvalidUrl(_)
            | Self::InvalidArgument(_)
            | Self::Destroyed
            | Self::Incompatible { .. }
            | Self::SealSession(_)
            | Self::Transport { .. }
            | Self::Json { .. }
            | Self::JobFailed { .. }
            | Self::JobNotFound { .. }
            | Self::JobTimeout { .. } => None,
        }
    }

    /// Returns the server-suggested retry delay when rate limited.
    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after, .. } => *retry_after,
            _ => None,
        }
    }

    /// Returns `true` when the failure is transient and safe to retry with backoff.
    #[must_use]
    pub const fn is_transient(&self) -> bool {
        match self {
            Self::RateLimited { .. } | Self::RequestTimeout { .. } | Self::Transport { .. } => true,
            Self::Server { status, .. } => matches!(*status, 408 | 429 | 502 | 503 | 504),
            Self::InvalidKey(_)
            | Self::InvalidUrl(_)
            | Self::InvalidArgument(_)
            | Self::Destroyed
            | Self::AuthRejected { .. }
            | Self::ClockDrift { .. }
            | Self::Incompatible { .. }
            | Self::SealSession(_)
            | Self::Json { .. }
            | Self::JobFailed { .. }
            | Self::JobNotFound { .. }
            | Self::JobTimeout { .. } => false,
        }
    }

    pub(crate) fn json_msg(context: impl Into<String>, message: impl Into<String>) -> Self {
        let msg = message.into();
        Self::Json {
            context: context.into(),
            source: Box::new(SimpleMessageError(msg)),
        }
    }
}

#[derive(Debug)]
struct SimpleMessageError(String);

impl std::fmt::Display for SimpleMessageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SimpleMessageError {}
