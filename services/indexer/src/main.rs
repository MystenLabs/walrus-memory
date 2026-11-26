//! Walrus Memory indexer — wires `AccountPipeline` into a `sui-indexer-alt-framework`
//! `IndexerCluster`. The framework owns checkpoint ingestion, watermarks, batching, and
//! shutdown; this binary configures the cluster and registers the account pipelines.
//!
//! Ingestion source + checkpoint range come from CLI flags (`--remote-store-url`,
//! `--first-checkpoint`); package id + DATABASE_URL come from the environment.
use clap::Parser;
use diesel_migrations::{embed_migrations, EmbeddedMigrations};
use move_core_types::account_address::AccountAddress;
use sui_indexer_alt_framework::cluster::{Args, IndexerCluster};
use sui_indexer_alt_framework::pipeline::concurrent::ConcurrentConfig;

mod handler;
mod owner_deactivations;
mod schema;

use handler::AccountPipeline;

const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Pin the ring CryptoProvider before any TLS: the ingestion client fetches checkpoints
    // over HTTPS and rustls 0.23 panics on the first handshake if a provider isn't set.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let _ = dotenvy::dotenv();

    // No tracing_subscriber::init here — IndexerCluster::build installs the framework's
    // own global subscriber (honors RUST_LOG); a second init panics.
    let args = Args::parse();
    let package = AccountAddress::from_hex_literal(&std::env::var("MEMWAL_PACKAGE_ID")?)
        .map_err(|e| anyhow::anyhow!("invalid MEMWAL_PACKAGE_ID: {e}"))?;
    let database_url: url::Url = std::env::var("DATABASE_URL")?.parse()?;

    let mut cluster = IndexerCluster::builder()
        .with_database_url(database_url)
        .with_args(args)
        .with_migrations(&MIGRATIONS)
        .build()
        .await?;

    cluster
        .concurrent_pipeline(AccountPipeline { package }, ConcurrentConfig::default())
        .await?;

    cluster
        .concurrent_pipeline(
            owner_deactivations::OwnerDeactivationPipeline { package },
            ConcurrentConfig::default(),
        )
        .await?;

    cluster.run().await?.join().await?;
    Ok(())
}
