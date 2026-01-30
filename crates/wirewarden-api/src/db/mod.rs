pub mod user;

use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

pub async fn create_pool(database_url: &str) -> PgPool {
    PgPoolOptions::new()
        .max_connections(8)
        .connect(database_url)
        .await
        .expect("failed to create database connection pool")
}

pub async fn migrate(pool: &PgPool) {
    sqlx::migrate!("./migrations")
        .run(pool)
        .await
        .expect("failed to run database migrations");
}
