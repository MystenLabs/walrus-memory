mod admin;
mod crypto;
pub(crate) mod email;
mod erasure;
pub(crate) mod owner_session;
mod routes;
mod store;
#[cfg(test)]
pub(crate) mod tests;
mod verification;

pub(crate) use admin::{admin_routes, ADMIN_PATH};
pub(crate) use crypto::MarketingConsentConfig;
pub(crate) use erasure::spawn_erasure_sweep;
pub(crate) use routes::{owner_routes, CONFIRM_PATH, OWNER_PATH};

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, sqlx::Type, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "text", rename_all = "snake_case")]
pub(crate) enum ConsentStatus {
    None,
    PendingVerification,
    OptedIn,
    Withdrawn,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "text", rename_all = "snake_case")]
pub(crate) enum SourceSurface {
    Prompt,
    Settings,
}

#[derive(Clone, Copy, Debug, Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "text", rename_all = "snake_case")]
pub(crate) enum WithdrawalReason {
    User,
    Unsubscribe,
    Bounce,
    Complaint,
}
