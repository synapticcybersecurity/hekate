use axum::{
    response::{Html, IntoResponse, Json},
    routing::get,
    Router,
};
use serde_json::json;
use utoipa::OpenApi;

use crate::{openapi::ApiDoc, AppState};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/openapi.json", get(openapi_spec))
        .route("/api/v1/docs", get(docs_ui))
        .route("/api/v1/version", get(version))
}

async fn openapi_spec() -> impl IntoResponse {
    Json(ApiDoc::openapi())
}

/// Scalar-rendered interactive docs. Single self-contained HTML page that
/// pulls the spec from `/api/v1/openapi.json`.
async fn docs_ui() -> impl IntoResponse {
    Html(
        r##"<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>hekate API</title>
  </head>
  <body>
    <script
      id="api-reference"
      data-url="/api/v1/openapi.json"></script>
    <script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference"></script>
  </body>
</html>"##,
    )
}

async fn version() -> impl IntoResponse {
    Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "git_sha": option_env!("HEKATE_GIT_SHA").unwrap_or("dev"),
    }))
}
