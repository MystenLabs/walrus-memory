use std::sync::Arc;

use tokio::time::{interval, MissedTickBehavior};

use super::store;
use crate::{
    observability::{record_marketing_consent_erasure, record_marketing_consent_sweep_error},
    types::AppState,
};

pub(crate) fn spawn_erasure_sweep(state: Arc<AppState>) {
    let Some(config) = &state.config.marketing_consent else {
        return;
    };
    let mut ticks = interval(config.erasure_interval);
    ticks.set_missed_tick_behavior(MissedTickBehavior::Skip);
    tokio::spawn(async move {
        loop {
            ticks.tick().await;
            match store::erase_deactivated(state.db.pool(), &state.config.package_id).await {
                Ok(owners) => {
                    for owner in owners {
                        tracing::info!(%owner, "erased marketing consent after owner deactivation");
                        record_marketing_consent_erasure("owner_deactivated");
                    }
                }
                Err(error) => {
                    tracing::warn!(%error, "marketing consent erasure sweep failed");
                    record_marketing_consent_sweep_error("database");
                }
            }
        }
    });
}
