use sqlx::any::{install_default_drivers, AnyPoolOptions};
use sqlx::AnyPool;

#[derive(Clone)]
pub struct Db {
    pool: AnyPool,
}

impl Db {
    pub async fn connect(url: &str) -> anyhow::Result<Self> {
        install_default_drivers();
        // SQLite `:memory:` (or `mode=memory`) gives each connection its own
        // private database. Pool > 1 would surface as missing-table errors
        // after migrations. Cap to a single connection in that case.
        let max_conns = if is_memory_sqlite(url) { 1 } else { 16 };
        let pool = AnyPoolOptions::new()
            .max_connections(max_conns)
            .acquire_timeout(std::time::Duration::from_secs(5))
            .connect(url)
            .await?;
        Ok(Self { pool })
    }

    pub async fn migrate(&self) -> anyhow::Result<()> {
        sqlx::migrate!("../../migrations").run(&self.pool).await?;
        tracing::info!("migrations applied");
        Ok(())
    }

    pub fn pool(&self) -> &AnyPool {
        &self.pool
    }

    pub async fn ping(&self) -> anyhow::Result<()> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        Ok(())
    }
}

pub fn is_memory_sqlite(url: &str) -> bool {
    let u = url.to_ascii_lowercase();
    u.starts_with("sqlite") && (u.contains(":memory:") || u.contains("mode=memory"))
}
