//! Bearer-token extractor that authenticates the request and resolves to
//! `AuthUser { user_id, scopes }`. Accepts both interactive JWTs (from
//! /identity/connect/token) and PATs (`pmgr_pat_…`).
//!
//! Use as a route handler argument:
//!
//! ```ignore
//! async fn handler(user: AuthUser, State(state): State<AppState>) {
//!     user.require(scope::VAULT_WRITE)?;
//! }
//! ```

use axum::{
    extract::FromRequestParts,
    http::{header, request::Parts, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

use crate::{
    auth::{pat, sat, scope::ScopeSet},
    AppState,
};

#[derive(Debug, Clone)]
pub struct AuthUser {
    pub user_id: String,
    pub scopes: ScopeSet,
}

impl AuthUser {
    /// Reject the request with 403 if this caller lacks `scope`.
    pub fn require(&self, scope: &str) -> Result<(), AuthError> {
        if self.scopes.permits(scope) {
            Ok(())
        } else {
            Err(AuthError::Forbidden(format!(
                "this token lacks the `{scope}` scope"
            )))
        }
    }
}

#[derive(Debug)]
pub enum AuthError {
    Missing,
    Malformed,
    Invalid,
    Forbidden(String),
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (code, msg) = match self {
            AuthError::Missing => (StatusCode::UNAUTHORIZED, "missing bearer token".to_string()),
            AuthError::Malformed => (
                StatusCode::UNAUTHORIZED,
                "malformed authorization header".to_string(),
            ),
            AuthError::Invalid => (
                StatusCode::UNAUTHORIZED,
                "invalid or expired token".to_string(),
            ),
            AuthError::Forbidden(m) => (StatusCode::FORBIDDEN, m),
        };
        let mut resp = (code, Json(json!({"error": msg}))).into_response();
        if code == StatusCode::UNAUTHORIZED {
            resp.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                "Bearer realm=\"hekate\"".parse().unwrap(),
            );
        }
        resp
    }
}

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let auth = parts
            .headers
            .get(header::AUTHORIZATION)
            .ok_or(AuthError::Missing)?
            .to_str()
            .map_err(|_| AuthError::Malformed)?;

        let token = auth
            .strip_prefix("Bearer ")
            .or_else(|| auth.strip_prefix("bearer "))
            .ok_or(AuthError::Malformed)?
            .trim();

        if pat::looks_like_pat(token) {
            let verified = pat::verify(state.db.pool(), token)
                .await
                .map_err(|_| AuthError::Invalid)?
                .ok_or(AuthError::Invalid)?;
            Ok(AuthUser {
                user_id: verified.user_id,
                scopes: ScopeSet::from_csv(&verified.scopes),
            })
        } else if sat::looks_like_sat(token) {
            // Service-account tokens authenticate as a `Principal::ServiceAccount`,
            // which is NOT a user. Routes that take `AuthUser` refuse them.
            // Use the `AuthService` extractor on routes that accept SA tokens.
            Err(AuthError::Forbidden(
                "service-account tokens cannot be presented at user-scoped endpoints; \
                 use AuthService routes instead"
                    .to_string(),
            ))
        } else {
            let claims = state.signer.verify(token).map_err(|_| AuthError::Invalid)?;
            // 2FA challenge tokens are issued mid-login and must never be
            // accepted at any authenticated endpoint. Pre-M2.22 access
            // tokens have an empty purpose; M2.22+ access tokens carry
            // `"access"`. Anything else (incl. `"tfa"`) is refused.
            if !claims.purpose.is_empty() && claims.purpose != crate::auth::jwt::PURPOSE_ACCESS {
                return Err(AuthError::Invalid);
            }
            // Cross-check the stamp claim against the user's current
            // security_stamp. A password change or device revocation
            // updates the stamp, invalidating outstanding JWTs.
            let row: Option<(String,)> =
                sqlx::query_as("SELECT security_stamp FROM users WHERE id = $1")
                    .bind(&claims.sub)
                    .fetch_optional(state.db.pool())
                    .await
                    .map_err(|_| AuthError::Invalid)?;
            let Some((current_stamp,)) = row else {
                return Err(AuthError::Invalid);
            };
            if current_stamp != claims.stamp {
                return Err(AuthError::Invalid);
            }
            Ok(AuthUser {
                user_id: claims.sub,
                scopes: ScopeSet::All,
            })
        }
    }
}

/// Service-account principal extractor. Accepts ONLY `pmgr_sat_*`
/// bearer tokens; refuses interactive JWTs and PATs. Use this on
/// routes that should be callable by an org's machine identities
/// rather than by a user — today the only such route is the M2.5
/// "who am I" introspection at `/api/v1/service-accounts/me`; M6
/// adds the Secrets Manager surface.
#[derive(Debug, Clone)]
pub struct AuthService {
    pub token_id: String,
    pub service_account_id: String,
    pub org_id: String,
    pub scopes: ScopeSet,
}

impl AuthService {
    pub fn require(&self, scope: &str) -> Result<(), AuthError> {
        if self.scopes.permits(scope) {
            Ok(())
        } else {
            Err(AuthError::Forbidden(format!(
                "this service-account token lacks the `{scope}` scope"
            )))
        }
    }
}

impl FromRequestParts<AppState> for AuthService {
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let auth = parts
            .headers
            .get(header::AUTHORIZATION)
            .ok_or(AuthError::Missing)?
            .to_str()
            .map_err(|_| AuthError::Malformed)?;

        let token = auth
            .strip_prefix("Bearer ")
            .or_else(|| auth.strip_prefix("bearer "))
            .ok_or(AuthError::Malformed)?
            .trim();

        if !sat::looks_like_sat(token) {
            return Err(AuthError::Forbidden(
                "this endpoint requires a service-account token (pmgr_sat_*)".to_string(),
            ));
        }
        let verified = sat::verify(state.db.pool(), token)
            .await
            .map_err(|_| AuthError::Invalid)?
            .ok_or(AuthError::Invalid)?;
        Ok(AuthService {
            token_id: verified.token_id,
            service_account_id: verified.service_account_id,
            org_id: verified.org_id,
            scopes: ScopeSet::from_csv(&verified.scopes),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::get, Router};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    async fn whoami(user: AuthUser) -> String {
        user.user_id
    }

    fn app(state: AppState) -> Router {
        Router::new()
            .route("/whoami", get(whoami))
            .with_state(state)
    }

    #[tokio::test]
    async fn missing_token_returns_401() {
        let state = test_state().await;
        let resp = app(state)
            .oneshot(
                axum::http::Request::get("/whoami")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn valid_jwt_extracts_user_id() {
        let state = test_state().await;
        // Insert a minimal user row whose security_stamp matches the
        // claim we'll embed in the JWT. The extractor cross-checks.
        let stamp = "stamp-1";
        sqlx::query(
            "INSERT INTO users (
                id, email, kdf_params, kdf_salt, master_password_hash,
                protected_account_key, account_public_key, protected_account_private_key,
                revision_date, security_stamp
             ) VALUES ($1,$2,'{}','','','','','','2026-01-01T00:00:00Z',$3)",
        )
        .bind("user-abc")
        .bind("a@example.com")
        .bind(stamp)
        .execute(state.db.pool())
        .await
        .unwrap();

        let (token, _) = state.signer.issue_access_token("user-abc", stamp).unwrap();
        let resp = app(state)
            .oneshot(
                axum::http::Request::get("/whoami")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&bytes[..], b"user-abc");
    }

    #[tokio::test]
    async fn jwt_with_stale_stamp_rejected() {
        let state = test_state().await;
        sqlx::query(
            "INSERT INTO users (
                id, email, kdf_params, kdf_salt, master_password_hash,
                protected_account_key, account_public_key, protected_account_private_key,
                revision_date, security_stamp
             ) VALUES ($1,$2,'{}','','','','','','2026-01-01T00:00:00Z',$3)",
        )
        .bind("user-stale")
        .bind("stale@example.com")
        .bind("current-stamp")
        .execute(state.db.pool())
        .await
        .unwrap();

        let (token, _) = state
            .signer
            .issue_access_token("user-stale", "old-stamp")
            .unwrap();
        let resp = app(state)
            .oneshot(
                axum::http::Request::get("/whoami")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn malformed_header_returns_401() {
        let state = test_state().await;
        let resp = app(state)
            .oneshot(
                axum::http::Request::get("/whoami")
                    .header(header::AUTHORIZATION, "Token abc")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    async fn test_state() -> AppState {
        crate::bootstrap(crate::config::Config {
            listen: "0.0.0.0:0".into(),
            database_url: "sqlite::memory:".into(),
            fake_salt_pepper: vec![0u8; 32],
            ..Default::default()
        })
        .await
        .unwrap()
    }
}
