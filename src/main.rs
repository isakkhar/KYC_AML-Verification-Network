use actix_web::{web, App, HttpServer, middleware::Logger};
use actix_cors::Cors;
use std::sync::Arc;
use tracing::{info, error};
use tracing_subscriber;

mod api;
mod blockchain;
mod kyc;
mod crypto;
mod external;
mod models;
mod config;
mod utils;

use crate::config::Settings;
use crate::blockchain::SubstrateClient;
use crate::utils::error::AppError;

pub struct AppState {
    pub db_pool: sqlx::PgPool,
    pub substrate_client: Arc<SubstrateClient>,
    pub settings: Settings,
}

#[actix_web::main]
async fn main() -> Result<(), AppError> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    info!("Starting KYC Network Server");

    // Load configuration
    let settings = Settings::new()?;
    info!("Configuration loaded successfully");

    // Initialize database connection
    let db_pool = sqlx::PgPool::connect(&settings.database.url)
        .await
        .map_err(|e| {
            error!("Failed to connect to database: {}", e);
            AppError::DatabaseError(e.to_string())
        })?;

    // Run database migrations
    sqlx::migrate!("./migrations")
        .run(&db_pool)
        .await
        .map_err(|e| {
            error!("Failed to run migrations: {}", e);
            AppError::DatabaseError(e.to_string())
        })?;

    info!("Database connection established and migrations completed");

    // Initialize Substrate client
    let substrate_client = Arc::new(
        SubstrateClient::new(&settings.blockchain.endpoint)
            .await
            .map_err(|e| {
                error!("Failed to initialize Substrate client: {}", e);
                AppError::BlockchainError(e.to_string())
            })?
    );

    info!("Substrate client initialized");

    // Create application state
    let app_state = web::Data::new(AppState {
        db_pool,
        substrate_client,
        settings: settings.clone(),
    });

    let bind_address = format!("{}:{}", settings.server.host, settings.server.port);
    info!("Starting server on {}", bind_address);

    // Start HTTP server
    HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .max_age(3600);

        App::new()
            .app_data(app_state.clone())
            .wrap(cors)
            .wrap(Logger::default())
            .wrap(api::middleware::auth_middleware())
            .service(
                web::scope("/api/v1")
                    .configure(api::routes::configure_routes)
            )
            .service(
                web::scope("/health")
                    .route("", web::get().to(health_check))
            )
    })
        .bind(&bind_address)?
        .run()
        .await
        .map_err(|e| {
            error!("Server error: {}", e);
            AppError::ServerError(e.to_string())
        })?;

    Ok(())
}

async fn health_check() -> actix_web::Result<impl actix_web::Responder> {
    Ok(actix_web::HttpResponse::Ok().json(serde_json::json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "service": "kyc-network"
    })))
}