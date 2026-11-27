//! Runnable quick-start example demonstrating health check, `remember_and_wait`,
//! `recall`, `list_namespaces`, `forget`, and `destroy`.

#![expect(clippy::print_stdout, reason = "CLI example prints step outcomes")]

use memwal::{Env, ListNamespacesOptions, MemWal, RecallParams};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key = std::env::var("MEMWAL_PRIVATE_KEY")?;
    let account_id = std::env::var("MEMWAL_ACCOUNT_ID")?;
    let env: Env = std::env::var("MEMWAL_ENV")
        .unwrap_or_else(|_| "dev".to_owned())
        .parse()?;
    let namespace =
        std::env::var("MEMWAL_NAMESPACE").unwrap_or_else(|_| "rust-quickstart-demo".to_owned());

    let client = MemWal::builder(key, account_id)
        .env(env)
        .namespace(namespace)
        .build()?;

    let health = client.health().await?;
    println!("Relayer status: {} (v{})", health.status, health.version);

    let compat = client.compatibility().await?;
    println!("Relayer API version: {}", compat.api_version);

    let who = client.whoami().await?;
    println!("Authenticated owner: {}", who.owner);

    let stored = client
        .remember_and_wait("User prefers dark mode and Neovim keybindings")
        .await?;
    println!("Stored memory blob_id={}", stored.blob_id);

    let recalled = client
        .recall(RecallParams::new("editor preferences").with_limit(3))
        .await?;
    println!("Recall returned {} hit(s)", recalled.results.len());
    for hit in &recalled.results {
        println!("Recalled (distance={:.4}): {}", hit.distance, hit.text);
    }

    let namespaces = client
        .list_namespaces(&ListNamespacesOptions::new().with_limit(10))
        .await?;
    println!("Account holds {} namespace(s)", namespaces.namespaces.len());

    let forgotten = client.forget(None).await?;
    println!(
        "Cleaned up {} entries from {}",
        forgotten.deleted, forgotten.namespace
    );

    client.destroy();
    Ok(())
}
