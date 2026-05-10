use axum::{
    response::{IntoResponse, Json},
    routing::get,
    Router,
};
use serde_json::json;

use crate::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/", get(index))
}

async fn index() -> impl IntoResponse {
    Json(json!({
        "service": "hekate",
        "version": env!("CARGO_PKG_VERSION"),
        "docs": "https://github.com/synapticcybersecurity/hekate",
        "endpoints": {
            "health_live":  "/health/live",
            "health_ready": "/health/ready",
            "version":      "/api/v1/version",
            "openapi":      "/api/v1/openapi.json",
        },
        "status": "running"
    }))
}
