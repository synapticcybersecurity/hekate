//! Server-Sent Events push channel.
//!
//! `GET /push/v1/stream` (auth required). Subscribers receive every push
//! event for their own user. Push is best-effort; clients converge through
//! delta sync regardless.

use std::convert::Infallible;

use axum::{
    extract::State,
    response::sse::{Event, KeepAlive, Sse},
    routing::get,
    Router,
};
use futures_util::stream::{Stream, StreamExt};
use serde_json::json;
use tokio_stream::wrappers::BroadcastStream;

use crate::{
    auth::{scope, AuthUser},
    AppState,
};

pub fn router() -> Router<AppState> {
    Router::new().route("/push/v1/stream", get(stream))
}

async fn stream(
    user: AuthUser,
    State(state): State<AppState>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, crate::routes::accounts::ApiError> {
    user.require(scope::VAULT_READ)?;
    let rx = state.push.subscribe();
    let user_id = user.user_id;

    let stream = BroadcastStream::new(rx).filter_map(move |item| {
        let user_id = user_id.clone();
        async move {
            // Drop lag/recv errors silently — push is best-effort.
            let event = item.ok()?;
            if event.user_id != user_id {
                return None;
            }
            let payload = json!({
                "id": event.id,
                "revision": event.revision,
            });
            Some(Ok(Event::default()
                .event(event.kind.as_str())
                .id(&event.revision)
                .data(payload.to_string())))
        }
    });

    Ok(Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(std::time::Duration::from_secs(15))
            .text("heartbeat"),
    ))
}
