mod auth;
mod config;
mod db;
mod error;
mod extract;
mod routes;
mod webauthn;

use actix_web::{web, App, HttpResponse, HttpServer};
use tracing::info;

use crate::config::Config;
use crate::db::user::UserStore;

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

    let user_store = UserStore::new(pool.clone());
    let webauthn = webauthn::build_webauthn(&config);
    let challenge_store = webauthn::ChallengeStore::new();

    let bind = config.bind_addr.clone();

    let config_data = web::Data::new(config);
    let store_data = web::Data::new(user_store);
    let webauthn_data = web::Data::new(webauthn);
    let challenge_data = web::Data::new(challenge_store);

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .app_data(config_data.clone())
            .app_data(store_data.clone())
            .app_data(webauthn_data.clone())
            .app_data(challenge_data.clone())
            .wrap(tracing_actix_web::TracingLogger::default())
            .route("/health", web::get().to(health))
            .configure(routes::auth::configure)
            .configure(routes::passkey::configure)
    })
    .bind(&bind)?
    .run()
    .await
}
