mod config;
mod db;

use actix_web::{web, App, HttpResponse, HttpServer};
use tracing::info;

use crate::config::Config;

fn init_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};

    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    #[cfg(distribute)]
    {
        fmt().json().with_env_filter(filter).init();
    }

    #[cfg(not(distribute))]
    {
        fmt().pretty().with_env_filter(filter).init();
    }
}

async fn health() -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({ "status": "ok" }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenvy::dotenv().ok();
    init_tracing();

    let config = Config::from_env().expect("failed to load configuration");
    info!(addr = %config.bind_addr, "starting wirewarden-api");

    let pool = db::create_pool(&config.database_url).await;
    db::migrate(&pool).await;
    info!("database migrations applied");

    let bind = config.bind_addr.clone();

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .wrap(tracing_actix_web::TracingLogger::default())
            .route("/health", web::get().to(health))
    })
    .bind(&bind)?
    .run()
    .await
}
