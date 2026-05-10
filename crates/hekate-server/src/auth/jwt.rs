//! JWT issuance for access tokens.
//!
//! HS256 with a 32-byte server secret stored in `signing_keys`. The kid
//! identifies the signing row so we can rotate without breaking outstanding
//! tokens. EdDSA upgrade is tracked for v1.0.

use std::sync::Arc;

use anyhow::{anyhow, Context};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sqlx::AnyPool;
use uuid::Uuid;

pub const ACCESS_TOKEN_TTL_SECS: u64 = 3600;
/// Lifetime of the 2FA challenge token returned mid-login. Five minutes
/// is enough for the user to fetch a TOTP code or recovery code; long
/// enough to allow normal UX hesitation, short enough that an
/// intercepted token is useless before it's expired.
pub const TFA_CHALLENGE_TTL_SECS: u64 = 300;
pub const ISSUER: &str = "hekate";

/// `purpose` claim values. Access tokens carry `"access"` (or empty for
/// pre-M2.22 issuers — the extractor accepts both). 2FA challenge tokens
/// carry `"tfa"` and the regular bearer extractor refuses them so they
/// can't be presented at any authenticated endpoint.
pub const PURPOSE_ACCESS: &str = "access";
pub const PURPOSE_TFA_CHALLENGE: &str = "tfa";

/// Loaded signing material. Cheap to clone (Arcs internally).
#[derive(Clone)]
pub struct Signer {
    pub kid: String,
    encoding: Arc<EncodingKey>,
    decoding: Arc<DecodingKey>,
}

impl std::fmt::Debug for Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Signer").field("kid", &self.kid).finish()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub sub: String, // user id (UUIDv7)
    pub iat: u64,
    pub exp: u64,
    pub jti: String, // unique token id (UUIDv7)
    /// Mirrors users.security_stamp at issue time. The extractor
    /// cross-checks against the current DB value on every request, so a
    /// password change or device revocation invalidates outstanding JWTs
    /// with a single UPDATE.
    #[serde(default)]
    pub stamp: String,
    /// `"access"` for normal bearer tokens, `"tfa"` for the short-lived
    /// 2FA challenge token. Defaults to empty string for pre-M2.22
    /// JWTs in the wild — those are treated as access tokens.
    #[serde(default)]
    pub purpose: String,
}

impl Signer {
    /// Load the active signing key, creating one if none exists.
    pub async fn bootstrap(pool: &AnyPool) -> anyhow::Result<Self> {
        if let Some(s) = Self::load_active(pool).await? {
            return Ok(s);
        }
        Self::generate_and_persist(pool).await
    }

    async fn load_active(pool: &AnyPool) -> anyhow::Result<Option<Self>> {
        let row: Option<(String, String)> = sqlx::query_as(
            "SELECT id, secret_b64 FROM signing_keys
             WHERE retired_at IS NULL
             ORDER BY created_at DESC LIMIT 1",
        )
        .fetch_optional(pool)
        .await?;
        match row {
            Some((id, secret_b64)) => {
                let secret = STANDARD_NO_PAD
                    .decode(secret_b64)
                    .context("decoding signing key")?;
                if secret.len() != 32 {
                    return Err(anyhow!(
                        "signing key {id} has wrong length {} (expected 32)",
                        secret.len()
                    ));
                }
                Ok(Some(Self::from_secret(id, &secret)))
            }
            None => Ok(None),
        }
    }

    async fn generate_and_persist(pool: &AnyPool) -> anyhow::Result<Self> {
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        let kid = Uuid::now_v7().to_string();
        let secret_b64 = STANDARD_NO_PAD.encode(secret);

        sqlx::query("INSERT INTO signing_keys (id, secret_b64) VALUES ($1, $2)")
            .bind(&kid)
            .bind(&secret_b64)
            .execute(pool)
            .await?;
        tracing::info!(kid, "generated new JWT signing key");
        Ok(Self::from_secret(kid, &secret))
    }

    fn from_secret(kid: String, secret: &[u8]) -> Self {
        Self {
            kid,
            encoding: Arc::new(EncodingKey::from_secret(secret)),
            decoding: Arc::new(DecodingKey::from_secret(secret)),
        }
    }

    pub fn issue_access_token(
        &self,
        user_id: &str,
        security_stamp: &str,
    ) -> anyhow::Result<(String, u64)> {
        self.issue_with_purpose(
            user_id,
            security_stamp,
            PURPOSE_ACCESS,
            ACCESS_TOKEN_TTL_SECS,
        )
        .map(|t| (t, ACCESS_TOKEN_TTL_SECS))
    }

    /// Mid-login 2FA challenge token. Carries `purpose="tfa"` so the
    /// regular bearer extractor refuses it; only the identity-token
    /// endpoint accepts it on the second leg of the login.
    pub fn issue_tfa_challenge_token(
        &self,
        user_id: &str,
        security_stamp: &str,
    ) -> anyhow::Result<String> {
        self.issue_with_purpose(
            user_id,
            security_stamp,
            PURPOSE_TFA_CHALLENGE,
            TFA_CHALLENGE_TTL_SECS,
        )
    }

    fn issue_with_purpose(
        &self,
        user_id: &str,
        security_stamp: &str,
        purpose: &str,
        ttl: u64,
    ) -> anyhow::Result<String> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock went backwards")
            .as_secs();
        let claims = Claims {
            iss: ISSUER.to_string(),
            sub: user_id.to_string(),
            iat: now,
            exp: now + ttl,
            jti: Uuid::now_v7().to_string(),
            stamp: security_stamp.to_string(),
            purpose: purpose.to_string(),
        };
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(self.kid.clone());
        let token = encode(&header, &claims, &self.encoding)?;
        Ok(token)
    }

    pub fn verify(&self, token: &str) -> anyhow::Result<Claims> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&[ISSUER]);
        validation.set_required_spec_claims(&["exp", "iat", "iss", "sub"]);
        let data = decode::<Claims>(token, &self.decoding, &validation)?;
        Ok(data.claims)
    }

    /// Verify a 2FA challenge token. Refuses anything whose `purpose`
    /// claim is not `"tfa"` so a stolen access token can't substitute.
    pub fn verify_tfa_challenge(&self, token: &str) -> anyhow::Result<Claims> {
        let claims = self.verify(token)?;
        if claims.purpose != PURPOSE_TFA_CHALLENGE {
            return Err(anyhow!("token purpose is not tfa"));
        }
        Ok(claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::any::{install_default_drivers, AnyPoolOptions};

    async fn pool() -> AnyPool {
        install_default_drivers();
        let pool = AnyPoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(
            "CREATE TABLE signing_keys (
                id TEXT PRIMARY KEY,
                secret_b64 TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                retired_at TEXT)",
        )
        .execute(&pool)
        .await
        .unwrap();
        pool
    }

    #[tokio::test]
    async fn bootstrap_generates_then_reloads() {
        let pool = pool().await;
        let s1 = Signer::bootstrap(&pool).await.unwrap();
        let s2 = Signer::bootstrap(&pool).await.unwrap();
        assert_eq!(
            s1.kid, s2.kid,
            "second bootstrap should reuse the existing key"
        );
    }

    #[tokio::test]
    async fn issue_and_verify_roundtrip() {
        let pool = pool().await;
        let signer = Signer::bootstrap(&pool).await.unwrap();
        let user_id = Uuid::now_v7().to_string();
        let stamp = Uuid::now_v7().to_string();
        let (token, ttl) = signer.issue_access_token(&user_id, &stamp).unwrap();
        assert_eq!(ttl, ACCESS_TOKEN_TTL_SECS);
        let claims = signer.verify(&token).unwrap();
        assert_eq!(claims.sub, user_id);
        assert_eq!(claims.iss, ISSUER);
        assert_eq!(claims.stamp, stamp);
    }

    #[tokio::test]
    async fn tampered_token_rejected() {
        let pool = pool().await;
        let signer = Signer::bootstrap(&pool).await.unwrap();
        let (mut token, _) = signer.issue_access_token("u", "stamp1").unwrap();
        // Flip a character in the signature segment.
        let last = token.len() - 1;
        let b = token.as_bytes()[last];
        let replacement = if b == b'A' { b'B' } else { b'A' };
        unsafe {
            token.as_bytes_mut()[last] = replacement;
        }
        assert!(signer.verify(&token).is_err());
    }
}
