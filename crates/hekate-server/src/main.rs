use anyhow::Context;
use hekate_server::{config::Config, run};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    hekate_server::tracing_init();

    let cfg = Config::load().context("loading config")?;
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        listen = %cfg.listen,
        db = cfg.database_url_redacted(),
        "hekate-server starting"
    );

    run(cfg).await
}
