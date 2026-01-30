use actix_web::{web, App, HttpResponse, HttpServer};
use tracing::info;

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
    init_tracing();

    let bind = std::env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    info!(addr = %bind, "starting wirewarden-api");

    HttpServer::new(|| {
        App::new()
            .wrap(tracing_actix_web::TracingLogger::default())
            .route("/health", web::get().to(health))
    })
    .bind(&bind)?
    .run()
    .await
}
