use axum::{
    extract::{Path, State},
    http::StatusCode,
    middleware,
    routing::get,
    Json, Router,
};
use sqlx::PgPool;

use super::{store, MarketingConsentConfig};
use crate::{
    auth::verify_admin_key, observability::record_marketing_consent_erasure, types::AppError,
};

pub(crate) const ADMIN_PATH: &str = "/api/admin/marketing-consent/{owner}";

#[derive(Clone)]
struct AdminState {
    pool: PgPool,
    config: MarketingConsentConfig,
}

pub(crate) fn admin_routes<S: Clone + Send + Sync + 'static>(
    pool: &PgPool,
    config: Option<&MarketingConsentConfig>,
) -> Router<S> {
    let Some(config) = config else {
        return Router::new();
    };
    Router::new()
        .route(ADMIN_PATH, get(export).delete(erase))
        .layer(middleware::from_fn(verify_admin_key))
        .with_state(AdminState {
            pool: pool.clone(),
            config: config.clone(),
        })
}

async fn export(
    State(state): State<AdminState>,
    Path(owner): Path<String>,
) -> Result<Result<Json<store::ConsentExport>, StatusCode>, AppError> {
    let owner = store::owner_address(&owner)?;
    tracing::info!(%owner, action = "export", "admin marketing consent access");
    Ok(store::export(&state.pool, &state.config, &owner)
        .await?
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND))
}

async fn erase(
    State(state): State<AdminState>,
    Path(owner): Path<String>,
) -> Result<StatusCode, AppError> {
    let owner = store::owner_address(&owner)?;
    tracing::info!(%owner, action = "erase", "admin marketing consent access");
    if store::erase(&state.pool, &owner).await? {
        record_marketing_consent_erasure("admin");
    }
    Ok(StatusCode::NO_CONTENT)
}
