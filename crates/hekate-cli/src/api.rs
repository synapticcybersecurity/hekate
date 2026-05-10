//! HTTP client over the hekate REST API. Handles auto-refresh on 401: when
//! an authenticated call fails with 401 and we have a refresh token, we
//! exchange it for a new access token and retry the original request once.
//! The refreshed tokens are surfaced to the caller via `take_refreshed()`
//! so they can persist them to the state file.

use std::cell::RefCell;

use anyhow::{anyhow, Context, Result};
use reqwest::blocking::{Client, RequestBuilder, Response};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub struct Api {
    client: Client,
    base_url: String,
    state: RefCell<TokenState>,
}

#[derive(Debug, Default, Clone)]
struct TokenState {
    access: Option<String>,
    refresh: Option<String>,
    expires_at: Option<String>,
    /// Set true the first time we successfully refresh; the caller checks
    /// this after a session ends and writes new tokens to the state file.
    refreshed: bool,
}

#[derive(Debug, Clone)]
pub struct RefreshedTokens {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: String,
}

impl Api {
    pub fn new(base_url: impl Into<String>) -> Result<Self> {
        let client = Client::builder()
            .user_agent(concat!("hekate-cli/", env!("CARGO_PKG_VERSION")))
            .timeout(std::time::Duration::from_secs(30))
            .build()?;
        Ok(Self {
            client,
            base_url: base_url.into().trim_end_matches('/').to_string(),
            state: RefCell::new(TokenState::default()),
        })
    }

    pub fn with_bearer(self, access_token: impl Into<String>) -> Self {
        self.state.borrow_mut().access = Some(access_token.into());
        self
    }

    /// Provide a refresh token so 401 responses can be auto-recovered.
    pub fn with_refresh(self, refresh_token: impl Into<String>) -> Self {
        self.state.borrow_mut().refresh = Some(refresh_token.into());
        self
    }

    /// If an auto-refresh happened during this Api's lifetime, return the
    /// new tokens so the caller can save them. Returns `None` otherwise.
    pub fn take_refreshed(&self) -> Option<RefreshedTokens> {
        let mut s = self.state.borrow_mut();
        if !s.refreshed {
            return None;
        }
        s.refreshed = false;
        Some(RefreshedTokens {
            access_token: s.access.clone()?,
            refresh_token: s.refresh.clone()?,
            expires_at: s.expires_at.clone()?,
        })
    }

    // ---- public endpoints ---------------------------------------------

    pub fn prelogin(&self, email: &str) -> Result<PreloginResponse> {
        let resp = self
            .client
            .post(format!("{}/api/v1/accounts/prelogin", self.base_url))
            .json(&serde_json::json!({"email": email}))
            .send()?;
        ok_json(resp)
    }

    pub fn register(&self, body: &RegisterRequest) -> Result<RegisterResponse> {
        let resp = self
            .client
            .post(format!("{}/api/v1/accounts/register", self.base_url))
            .json(body)
            .send()?;
        ok_json(resp)
    }

    pub fn token_password(
        &self,
        email: &str,
        master_password_hash_b64: &str,
    ) -> Result<PasswordGrantOutcome> {
        self.token_password_full(email, master_password_hash_b64, None)
    }

    /// Second leg of the M2.22 two-factor flow: replays the password
    /// grant with the challenge token + provider/value the user just
    /// supplied.
    pub fn token_password_with_2fa(
        &self,
        email: &str,
        master_password_hash_b64: &str,
        two_factor_token: &str,
        two_factor_provider: &str,
        two_factor_value: &str,
    ) -> Result<PasswordGrantOutcome> {
        self.token_password_full(
            email,
            master_password_hash_b64,
            Some(SecondFactor {
                token: two_factor_token,
                provider: two_factor_provider,
                value: two_factor_value,
            }),
        )
    }

    fn token_password_full(
        &self,
        email: &str,
        master_password_hash_b64: &str,
        second: Option<SecondFactor<'_>>,
    ) -> Result<PasswordGrantOutcome> {
        let mut form: Vec<(&str, &str)> = vec![
            ("grant_type", "password"),
            ("username", email),
            ("password", master_password_hash_b64),
        ];
        if let Some(s) = &second {
            form.push(("two_factor_token", s.token));
            form.push(("two_factor_provider", s.provider));
            form.push(("two_factor_value", s.value));
        }
        let resp = self
            .client
            .post(format!("{}/identity/connect/token", self.base_url))
            .form(&form)
            .send()?;
        let status = resp.status();
        if status.is_success() {
            return Ok(PasswordGrantOutcome::Tokens(resp.json()?));
        }
        // Try to parse the 401 body as a 2FA challenge before giving up.
        if status == StatusCode::UNAUTHORIZED {
            let body = resp.text().unwrap_or_default();
            if let Ok(ch) = serde_json::from_str::<TwoFactorChallenge>(&body) {
                if ch.error == "two_factor_required" {
                    return Ok(PasswordGrantOutcome::TwoFactorRequired(ch));
                }
            }
            return Err(anyhow!("server returned {status}: {body}"));
        }
        let body = resp.text().unwrap_or_default();
        Err(anyhow!("server returned {status}: {body}"))
    }

    // ---- authenticated endpoints -------------------------------------

    pub fn create_cipher(&self, body: &CipherInput) -> Result<CipherView> {
        let url = format!("{}/api/v1/ciphers", self.base_url);
        let resp = self.with_auth_retry(|| self.client.post(&url).json(body))?;
        ok_json(resp)
    }

    pub fn get_cipher(&self, id: &str) -> Result<CipherView> {
        let url = format!("{}/api/v1/ciphers/{id}", self.base_url);
        let resp = self.with_auth_retry(|| self.client.get(&url))?;
        ok_json(resp)
    }

    pub fn put_cipher(
        &self,
        id: &str,
        body: &CipherInput,
        if_match_revision: &str,
    ) -> Result<PutOutcome> {
        let url = format!("{}/api/v1/ciphers/{id}", self.base_url);
        let if_match = format!("\"{if_match_revision}\"");
        let resp = self.with_auth_retry(|| {
            self.client
                .put(&url)
                .header(reqwest::header::IF_MATCH, &if_match)
                .json(body)
        })?;
        match resp.status() {
            StatusCode::OK => Ok(PutOutcome::Ok(resp.json()?)),
            StatusCode::CONFLICT => {
                let v: Value = resp.json()?;
                let current: CipherView =
                    serde_json::from_value(v.get("current").cloned().unwrap_or(Value::Null))
                        .context("conflict body missing `current`")?;
                Ok(PutOutcome::Conflict(current))
            }
            _ => {
                let status = resp.status();
                let body = resp.text().unwrap_or_default();
                Err(anyhow!("server returned {status}: {body}"))
            }
        }
    }

    pub fn move_cipher_to_org(
        &self,
        id: &str,
        if_match_revision: &str,
        body: &MoveToOrgRequest,
    ) -> Result<CipherView> {
        let url = format!("{}/api/v1/ciphers/{id}/move-to-org", self.base_url);
        let if_match = format!("\"{if_match_revision}\"");
        let resp = self.with_auth_retry(|| {
            self.client
                .post(&url)
                .header(reqwest::header::IF_MATCH, &if_match)
                .json(body)
        })?;
        ok_json(resp)
    }

    pub fn move_cipher_to_personal(
        &self,
        id: &str,
        if_match_revision: &str,
        body: &MoveToPersonalRequest,
    ) -> Result<CipherView> {
        let url = format!("{}/api/v1/ciphers/{id}/move-to-personal", self.base_url);
        let if_match = format!("\"{if_match_revision}\"");
        let resp = self.with_auth_retry(|| {
            self.client
                .post(&url)
                .header(reqwest::header::IF_MATCH, &if_match)
                .json(body)
        })?;
        ok_json(resp)
    }

    pub fn soft_delete_cipher(&self, id: &str) -> Result<()> {
        let url = format!("{}/api/v1/ciphers/{id}", self.base_url);
        let resp = self.with_auth_retry(|| self.client.delete(&url))?;
        if !resp.status().is_success() {
            let body = resp.text().unwrap_or_default();
            return Err(anyhow!("delete failed: {body}"));
        }
        Ok(())
    }

    pub fn restore_cipher(&self, id: &str) -> Result<CipherView> {
        let url = format!("{}/api/v1/ciphers/{id}/restore", self.base_url);
        let resp = self.with_auth_retry(|| self.client.post(&url))?;
        ok_json(resp)
    }

    pub fn purge_cipher(&self, id: &str) -> Result<()> {
        let url = format!("{}/api/v1/ciphers/{id}/permanent", self.base_url);
        let resp = self.with_auth_retry(|| self.client.delete(&url))?;
        if !resp.status().is_success() {
            let body = resp.text().unwrap_or_default();
            return Err(anyhow!("purge failed: {body}"));
        }
        Ok(())
    }

    pub fn create_pat(&self, body: &CreatePatRequest) -> Result<CreatePatResponse> {
        let url = format!("{}/api/v1/account/tokens", self.base_url);
        let resp = self.with_auth_retry(|| self.client.post(&url).json(body))?;
        ok_json(resp)
    }

    pub fn list_pats(&self) -> Result<Vec<PatListItem>> {
        let url = format!("{}/api/v1/account/tokens", self.base_url);
        let resp = self.with_auth_retry(|| self.client.get(&url))?;
        ok_json(resp)
    }

    pub fn revoke_pat(&self, id: &str) -> Result<()> {
        let url = format!("{}/api/v1/account/tokens/{id}", self.base_url);
        let resp = self.with_auth_retry(|| self.client.delete(&url))?;
        if !resp.status().is_success() {
            let body = resp.text().unwrap_or_default();
            return Err(anyhow!("revoke failed: {body}"));
        }
        Ok(())
    }

    pub fn create_webhook(&self, body: &CreateWebhookRequest) -> Result<CreateWebhookResponse> {
        let url = format!("{}/api/v1/account/webhooks", self.base_url);
        let resp = self.with_auth_retry(|| self.client.post(&url).json(body))?;
        ok_json(resp)
    }

    pub fn list_webhooks(&self) -> Result<Vec<WebhookListItem>> {
        let url = format!("{}/api/v1/account/webhooks", self.base_url);
        let resp = self.with_auth_retry(|| self.client.get(&url))?;
        ok_json(resp)
    }

    pub fn delete_webhook(&self, id: &str) -> Result<()> {
        let url = format!("{}/api/v1/account/webhooks/{id}", self.base_url);
        let resp = self.with_auth_retry(|| self.client.delete(&url))?;
        if !resp.status().is_success() {
            let body = resp.text().unwrap_or_default();
            return Err(anyhow!("delete failed: {body}"));
        }
        Ok(())
    }

    pub fn list_deliveries(&self, webhook_id: &str) -> Result<Vec<DeliveryItem>> {
        let url = format!(
            "{}/api/v1/account/webhooks/{webhook_id}/deliveries",
            self.base_url
        );
        let resp = self.with_auth_retry(|| self.client.get(&url))?;
        ok_json(resp)
    }

    pub fn rotate_keys(&self, body: &RotateKeysRequest) -> Result<RotateKeysResponse> {
        let url = format!("{}/api/v1/account/rotate-keys", self.base_url);
        let resp = self.with_auth_retry(|| self.client.post(&url).json(body))?;
        ok_json(resp)
    }

    /// (M2.27) Create a folder; return the new folder id. Body shape
    /// mirrors the server's `FolderInput` — just an EncString of the
    /// plaintext name. Used by `hekate import bitwarden` to materialize
    /// folder rows before creating ciphers that point at them.
    pub fn create_folder(&self, name_encstring: &str) -> Result<String> {
        let url = format!("{}/api/v1/folders", self.base_url);
        let body = serde_json::json!({"name": name_encstring});
        let resp = self.with_auth_retry(|| self.client.post(&url).json(&body))?;
        let v: serde_json::Value = ok_json(resp)?;
        v.get("id")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow!("create_folder response missing `id` field"))
    }

    pub fn change_password(&self, body: &ChangePasswordRequest) -> Result<ChangePasswordResponse> {
        let url = format!("{}/api/v1/account/change-password", self.base_url);
        let resp = self.with_auth_retry(|| self.client.post(&url).json(body))?;
        ok_json(resp)
    }

    // ---- 2FA (M2.22) --------------------------------------------------

    pub fn tfa_status(&self) -> Result<TfaStatus> {
        let url = format!("{}/api/v1/account/2fa/status", self.base_url);
        let resp = self.with_auth_retry(|| self.client.get(&url))?;
        ok_json(resp)
    }

    pub fn tfa_totp_setup(&self, body: &TfaSetupRequest) -> Result<TfaSetupResponse> {
        let url = format!("{}/api/v1/account/2fa/totp/setup", self.base_url);
        let resp = self.with_auth_retry(|| self.client.post(&url).json(body))?;
        ok_json(resp)
    }

    pub fn tfa_totp_confirm(&self, totp_code: &str) -> Result<TfaConfirmResponse> {
        let url = format!("{}/api/v1/account/2fa/totp/confirm", self.base_url);
        let body = serde_json::json!({"totp_code": totp_code});
        let resp = self.with_auth_retry(|| self.client.post(&url).json(&body))?;
        ok_json(resp)
    }

    pub fn tfa_totp_disable(&self, master_password_hash_b64: &str) -> Result<()> {
        let url = format!("{}/api/v1/account/2fa/totp/disable", self.base_url);
        let body = serde_json::json!({"master_password_hash": master_password_hash_b64});
        let resp = self.with_auth_retry(|| self.client.post(&url).json(&body))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().unwrap_or_default();
            return Err(anyhow!("disable 2fa: {status}: {body}"));
        }
        Ok(())
    }

    // ---- service accounts (M2.5) -------------------------------------

    pub fn create_service_account(&self, org_id: &str, name: &str) -> Result<ServiceAccountView> {
        let url = format!(
            "{}/api/v1/orgs/{}/service-accounts",
            self.base_url,
            urlencoding(org_id)
        );
        let body = serde_json::json!({"name": name});
        let resp = self.with_auth_retry(|| self.client.post(&url).json(&body))?;
        ok_json(resp)
    }

    pub fn list_service_accounts(&self, org_id: &str) -> Result<Vec<ServiceAccountView>> {
        let url = format!(
            "{}/api/v1/orgs/{}/service-accounts",
            self.base_url,
            urlencoding(org_id)
        );
        let resp = self.with_auth_retry(|| self.client.get(&url))?;
        ok_json(resp)
    }

    pub fn disable_service_account(&self, org_id: &str, sa_id: &str) -> Result<()> {
        let url = format!(
            "{}/api/v1/orgs/{}/service-accounts/{}/disable",
            self.base_url,
            urlencoding(org_id),
            urlencoding(sa_id),
        );
        let resp = self.with_auth_retry(|| self.client.post(&url))?;
        if !resp.status().is_success() {
            return Err(anyhow!(
                "disable failed: {}: {}",
                resp.status(),
                resp.text().unwrap_or_default()
            ));
        }
        Ok(())
    }

    pub fn delete_service_account(&self, org_id: &str, sa_id: &str) -> Result<()> {
        let url = format!(
            "{}/api/v1/orgs/{}/service-accounts/{}",
            self.base_url,
            urlencoding(org_id),
            urlencoding(sa_id),
        );
        let resp = self.with_auth_retry(|| self.client.delete(&url))?;
        if !resp.status().is_success() {
            return Err(anyhow!(
                "delete failed: {}: {}",
                resp.status(),
                resp.text().unwrap_or_default()
            ));
        }
        Ok(())
    }

    pub fn create_sa_token(
        &self,
        org_id: &str,
        sa_id: &str,
        name: &str,
        scopes: &str,
        expires_in_days: Option<i64>,
    ) -> Result<CreateSaTokenResponse> {
        let url = format!(
            "{}/api/v1/orgs/{}/service-accounts/{}/tokens",
            self.base_url,
            urlencoding(org_id),
            urlencoding(sa_id),
        );
        let body = serde_json::json!({
            "name": name,
            "scopes": scopes,
            "expires_in_days": expires_in_days,
        });
        let resp = self.with_auth_retry(|| self.client.post(&url).json(&body))?;
        ok_json(resp)
    }

    pub fn list_sa_tokens(&self, org_id: &str, sa_id: &str) -> Result<Vec<SaTokenListItem>> {
        let url = format!(
            "{}/api/v1/orgs/{}/service-accounts/{}/tokens",
            self.base_url,
            urlencoding(org_id),
            urlencoding(sa_id),
        );
        let resp = self.with_auth_retry(|| self.client.get(&url))?;
        ok_json(resp)
    }

    pub fn revoke_sa_token(&self, org_id: &str, sa_id: &str, token_id: &str) -> Result<()> {
        let url = format!(
            "{}/api/v1/orgs/{}/service-accounts/{}/tokens/{}",
            self.base_url,
            urlencoding(org_id),
            urlencoding(sa_id),
            urlencoding(token_id),
        );
        let resp = self.with_auth_retry(|| self.client.delete(&url))?;
        if !resp.status().is_success() {
            return Err(anyhow!(
                "revoke failed: {}: {}",
                resp.status(),
                resp.text().unwrap_or_default()
            ));
        }
        Ok(())
    }

    pub fn tfa_recovery_regenerate(
        &self,
        master_password_hash_b64: &str,
    ) -> Result<TfaRecoveryRegenerateResponse> {
        let url = format!(
            "{}/api/v1/account/2fa/recovery-codes/regenerate",
            self.base_url
        );
        let body = serde_json::json!({"master_password_hash": master_password_hash_b64});
        let resp = self.with_auth_retry(|| self.client.post(&url).json(&body))?;
        ok_json(resp)
    }

    pub fn delete_account(&self, master_password_hash_b64: &str) -> Result<()> {
        let url = format!("{}/api/v1/account/delete", self.base_url);
        let body = serde_json::json!({"master_password_hash": master_password_hash_b64});
        let resp = self.with_auth_retry(|| self.client.post(&url).json(&body))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().unwrap_or_default();
            return Err(anyhow!("delete account failed: {status}: {body}"));
        }
        Ok(())
    }

    pub fn upload_manifest(&self, body: &ManifestUpload) -> Result<ManifestView> {
        let url = format!("{}/api/v1/vault/manifest", self.base_url);
        let resp = self.with_auth_retry(|| self.client.post(&url).json(body))?;
        ok_json(resp)
    }

    pub fn get_pubkeys(&self, user_id: &str) -> Result<PubkeyBundle> {
        let url = format!(
            "{}/api/v1/users/{}/pubkeys",
            self.base_url,
            urlencoding(user_id)
        );
        // Pubkey directory is unauthenticated by design (public keys are
        // public). We still go through the authed retry helper so the
        // refresh-token path stays consistent if we later switch.
        let resp = self.client.get(&url).send()?;
        ok_json(resp)
    }

    pub fn create_org(&self, body: &CreateOrgRequest) -> Result<OrgView> {
        let url = format!("{}/api/v1/orgs", self.base_url);
        let resp = self.with_auth_retry(|| self.client.post(&url).json(body))?;
        ok_json(resp)
    }

    pub fn list_my_orgs(&self) -> Result<Vec<OrgListItem>> {
        let url = format!("{}/api/v1/account/orgs", self.base_url);
        let resp = self.with_auth_retry(|| self.client.get(&url))?;
        ok_json(resp)
    }

    pub fn get_org(&self, org_id: &str) -> Result<OrgView> {
        let url = format!("{}/api/v1/orgs/{}", self.base_url, urlencoding(org_id));
        let resp = self.with_auth_retry(|| self.client.get(&url))?;
        ok_json(resp)
    }

    pub fn invite_member(&self, org_id: &str, body: &OrgInviteRequest) -> Result<()> {
        let url = format!(
            "{}/api/v1/orgs/{}/invites",
            self.base_url,
            urlencoding(org_id)
        );
        let resp = self.with_auth_retry(|| self.client.post(&url).json(body))?;
        if resp.status().is_success() {
            return Ok(());
        }
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        Err(anyhow!("invite failed: {status}: {body}"))
    }

    pub fn list_my_invites(&self) -> Result<Vec<OrgInviteView>> {
        let url = format!("{}/api/v1/account/invites", self.base_url);
        let resp = self.with_auth_retry(|| self.client.get(&url))?;
        ok_json(resp)
    }

    pub fn accept_org(&self, org_id: &str, body: &AcceptOrgRequest) -> Result<()> {
        let url = format!(
            "{}/api/v1/orgs/{}/accept",
            self.base_url,
            urlencoding(org_id)
        );
        let resp = self.with_auth_retry(|| self.client.post(&url).json(body))?;
        if resp.status().is_success() {
            return Ok(());
        }
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        Err(anyhow!("accept failed: {status}: {body}"))
    }

    pub fn create_collection(
        &self,
        org_id: &str,
        body: &CreateCollectionRequest,
    ) -> Result<CollectionView> {
        let url = format!(
            "{}/api/v1/orgs/{}/collections",
            self.base_url,
            urlencoding(org_id)
        );
        let resp = self.with_auth_retry(|| self.client.post(&url).json(body))?;
        ok_json(resp)
    }

    pub fn list_collections(&self, org_id: &str) -> Result<Vec<CollectionView>> {
        let url = format!(
            "{}/api/v1/orgs/{}/collections",
            self.base_url,
            urlencoding(org_id)
        );
        let resp = self.with_auth_retry(|| self.client.get(&url))?;
        ok_json(resp)
    }

    pub fn grant_permission(
        &self,
        org_id: &str,
        collection_id: &str,
        user_id: &str,
        permission: &str,
    ) -> Result<CollectionMemberView> {
        let url = format!(
            "{}/api/v1/orgs/{}/collections/{}/members/{}",
            self.base_url,
            urlencoding(org_id),
            urlencoding(collection_id),
            urlencoding(user_id),
        );
        let body = serde_json::json!({"permission": permission});
        let resp = self.with_auth_retry(|| self.client.put(&url).json(&body))?;
        ok_json(resp)
    }

    pub fn revoke_permission(
        &self,
        org_id: &str,
        collection_id: &str,
        user_id: &str,
    ) -> Result<()> {
        let url = format!(
            "{}/api/v1/orgs/{}/collections/{}/members/{}",
            self.base_url,
            urlencoding(org_id),
            urlencoding(collection_id),
            urlencoding(user_id),
        );
        let resp = self.with_auth_retry(|| self.client.delete(&url))?;
        if resp.status().is_success() {
            return Ok(());
        }
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        Err(anyhow!("revoke: {status}: {body}"))
    }

    pub fn list_collection_members(
        &self,
        org_id: &str,
        collection_id: &str,
    ) -> Result<Vec<CollectionMemberView>> {
        let url = format!(
            "{}/api/v1/orgs/{}/collections/{}/members",
            self.base_url,
            urlencoding(org_id),
            urlencoding(collection_id),
        );
        let resp = self.with_auth_retry(|| self.client.get(&url))?;
        ok_json(resp)
    }

    pub fn delete_collection(&self, org_id: &str, collection_id: &str) -> Result<()> {
        let url = format!(
            "{}/api/v1/orgs/{}/collections/{}",
            self.base_url,
            urlencoding(org_id),
            urlencoding(collection_id),
        );
        let resp = self.with_auth_retry(|| self.client.delete(&url))?;
        if resp.status().is_success() {
            return Ok(());
        }
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        Err(anyhow!("delete collection: {status}: {body}"))
    }

    pub fn revoke_member(
        &self,
        org_id: &str,
        user_id: &str,
        body: &RevokeMemberRequest,
    ) -> Result<()> {
        let url = format!(
            "{}/api/v1/orgs/{}/members/{}/revoke",
            self.base_url,
            urlencoding(org_id),
            urlencoding(user_id),
        );
        let resp = self.with_auth_retry(|| self.client.post(&url).json(body))?;
        if resp.status().is_success() {
            return Ok(());
        }
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        Err(anyhow!("revoke-member failed: {status}: {body}"))
    }

    pub fn rotate_confirm(&self, org_id: &str, body: &RotateConfirmRequest) -> Result<()> {
        let url = format!(
            "{}/api/v1/orgs/{}/rotate-confirm",
            self.base_url,
            urlencoding(org_id),
        );
        let resp = self.with_auth_retry(|| self.client.post(&url).json(body))?;
        if resp.status().is_success() {
            return Ok(());
        }
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        Err(anyhow!("rotate-confirm failed: {status}: {body}"))
    }

    pub fn upload_org_cipher_manifest(
        &self,
        org_id: &str,
        body: &OrgCipherManifestUpload,
    ) -> Result<OrgCipherManifestView> {
        let url = format!(
            "{}/api/v1/orgs/{}/cipher-manifest",
            self.base_url,
            urlencoding(org_id),
        );
        let resp = self.with_auth_retry(|| self.client.post(&url).json(body))?;
        ok_json(resp)
    }

    pub fn set_policy(
        &self,
        org_id: &str,
        policy_type: &str,
        body: &SetPolicyRequest,
    ) -> Result<PolicyView> {
        let url = format!(
            "{}/api/v1/orgs/{}/policies/{}",
            self.base_url,
            urlencoding(org_id),
            urlencoding(policy_type),
        );
        let resp = self.with_auth_retry(|| self.client.put(&url).json(body))?;
        ok_json(resp)
    }

    pub fn list_policies(&self, org_id: &str) -> Result<Vec<PolicyView>> {
        let url = format!(
            "{}/api/v1/orgs/{}/policies",
            self.base_url,
            urlencoding(org_id),
        );
        let resp = self.with_auth_retry(|| self.client.get(&url))?;
        ok_json(resp)
    }

    pub fn delete_policy(&self, org_id: &str, policy_type: &str) -> Result<()> {
        let url = format!(
            "{}/api/v1/orgs/{}/policies/{}",
            self.base_url,
            urlencoding(org_id),
            urlencoding(policy_type),
        );
        let resp = self.with_auth_retry(|| self.client.delete(&url))?;
        if resp.status().is_success() {
            return Ok(());
        }
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        Err(anyhow!("delete policy: {status}: {body}"))
    }

    pub fn cancel_invite(
        &self,
        org_id: &str,
        invitee_user_id: &str,
        body: &CancelInviteRequest,
    ) -> Result<()> {
        let url = format!(
            "{}/api/v1/orgs/{}/invites/{}",
            self.base_url,
            urlencoding(org_id),
            urlencoding(invitee_user_id),
        );
        let resp = self.with_auth_retry(|| self.client.delete(&url).json(body))?;
        if resp.status().is_success() {
            return Ok(());
        }
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        Err(anyhow!("cancel-invite failed: {status}: {body}"))
    }

    #[allow(dead_code)] // standalone GET; the embedded /sync field covers reads today.
    pub fn get_manifest(&self) -> Result<Option<ManifestView>> {
        let url = format!("{}/api/v1/vault/manifest", self.base_url);
        let resp = self.with_auth_retry(|| self.client.get(&url))?;
        ok_json(resp)
    }

    pub fn sync(&self, since: Option<&str>) -> Result<SyncResponse> {
        let mut url = format!("{}/api/v1/sync", self.base_url);
        if let Some(s) = since {
            url.push_str("?since=");
            url.push_str(&urlencoding(s));
        }
        let resp = self.with_auth_retry(|| self.client.get(&url))?;
        ok_json(resp)
    }

    // ---- M2.24 attachments (tus 1.0) ----------------------------------

    /// Create a tus upload resource. Returns the absolute URL the
    /// caller should PATCH to. The body may be empty (then PATCH the
    /// bytes), or carry the full ciphertext via `creation-with-upload`
    /// (saves a round trip on small files).
    pub fn tus_create(
        &self,
        upload_length: u64,
        upload_metadata: &str,
        first_chunk: Option<&[u8]>,
    ) -> Result<String> {
        let url = format!("{}/api/v1/attachments", self.base_url);
        let body_bytes = first_chunk.map(<[u8]>::to_vec).unwrap_or_default();
        let resp = self.with_auth_retry(|| {
            let mut b = self
                .client
                .post(&url)
                .header("Tus-Resumable", "1.0.0")
                .header("Upload-Length", upload_length.to_string())
                .header("Upload-Metadata", upload_metadata);
            if !body_bytes.is_empty() {
                b = b
                    .header("Content-Type", "application/offset+octet-stream")
                    .body(body_bytes.clone());
            }
            b
        })?;
        let status = resp.status();
        if status != StatusCode::CREATED {
            let body = resp.text().unwrap_or_default();
            return Err(anyhow!("tus create failed: {status}: {body}"));
        }
        let location = resp
            .headers()
            .get(reqwest::header::LOCATION)
            .ok_or_else(|| anyhow!("tus create returned no Location header"))?
            .to_str()
            .context("Location header not ASCII")?
            .to_string();
        // Server returns a relative URL; absolutize.
        Ok(if location.starts_with("http") {
            location
        } else {
            format!("{}{}", self.base_url, location)
        })
    }

    /// HEAD a tus upload to learn the current `Upload-Offset` (for resume).
    pub fn tus_head(&self, location: &str) -> Result<u64> {
        let resp = self.with_auth_retry(|| self.client.head(location))?;
        if !resp.status().is_success() {
            let s = resp.status();
            let b = resp.text().unwrap_or_default();
            return Err(anyhow!("tus head failed: {s}: {b}"));
        }
        let v = resp
            .headers()
            .get("upload-offset")
            .ok_or_else(|| anyhow!("tus head returned no Upload-Offset"))?
            .to_str()?;
        Ok(v.parse()?)
    }

    /// PATCH bytes to a tus upload at `offset`. Returns the new offset.
    pub fn tus_patch(&self, location: &str, offset: u64, bytes: Vec<u8>) -> Result<u64> {
        let resp = self.with_auth_retry(|| {
            self.client
                .patch(location)
                .header("Tus-Resumable", "1.0.0")
                .header("Upload-Offset", offset.to_string())
                .header("Content-Type", "application/offset+octet-stream")
                .body(bytes.clone())
        })?;
        let status = resp.status();
        if status != StatusCode::NO_CONTENT {
            let body = resp.text().unwrap_or_default();
            return Err(anyhow!("tus patch failed: {status}: {body}"));
        }
        let new_off = resp
            .headers()
            .get("upload-offset")
            .ok_or_else(|| anyhow!("tus patch returned no Upload-Offset"))?
            .to_str()?
            .parse()?;
        Ok(new_off)
    }

    /// GET an attachment's plaintext metadata view.
    pub fn get_attachment(&self, id: &str) -> Result<AttachmentView> {
        let url = format!("{}/api/v1/attachments/{}", self.base_url, urlencoding(id));
        let resp = self.with_auth_retry(|| self.client.get(&url))?;
        ok_json(resp)
    }

    /// GET the entire ciphertext blob for an attachment.
    pub fn download_attachment_blob(&self, id: &str) -> Result<Vec<u8>> {
        let url = format!(
            "{}/api/v1/attachments/{}/blob",
            self.base_url,
            urlencoding(id)
        );
        let resp = self.with_auth_retry(|| self.client.get(&url))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().unwrap_or_default();
            return Err(anyhow!("attachment download failed: {status}: {body}"));
        }
        Ok(resp.bytes()?.to_vec())
    }

    /// Hard-delete an attachment (writes a tombstone, queues blob cleanup).
    pub fn delete_attachment(&self, id: &str) -> Result<()> {
        let url = format!("{}/api/v1/attachments/{}", self.base_url, urlencoding(id));
        let resp = self.with_auth_retry(|| self.client.delete(&url))?;
        if !resp.status().is_success() {
            let s = resp.status();
            let b = resp.text().unwrap_or_default();
            return Err(anyhow!("attachment delete failed: {s}: {b}"));
        }
        Ok(())
    }

    // ---- M2.25 sends --------------------------------------------------

    pub fn create_send(&self, body: &Value) -> Result<SendView> {
        let url = format!("{}/api/v1/sends", self.base_url);
        let resp = self.with_auth_retry(|| self.client.post(&url).json(body))?;
        ok_json(resp)
    }

    pub fn list_sends(&self) -> Result<Vec<SendView>> {
        let url = format!("{}/api/v1/sends", self.base_url);
        let resp = self.with_auth_retry(|| self.client.get(&url))?;
        ok_json(resp)
    }

    pub fn delete_send(&self, id: &str) -> Result<()> {
        let url = format!("{}/api/v1/sends/{}", self.base_url, urlencoding(id));
        let resp = self.with_auth_retry(|| self.client.delete(&url))?;
        if !resp.status().is_success() {
            let s = resp.status();
            let b = resp.text().unwrap_or_default();
            return Err(anyhow!("send delete failed: {s}: {b}"));
        }
        Ok(())
    }

    pub fn set_send_disabled(&self, id: &str, disabled: bool) -> Result<SendView> {
        let suffix = if disabled { "disable" } else { "enable" };
        let url = format!(
            "{}/api/v1/sends/{}/{}",
            self.base_url,
            urlencoding(id),
            suffix
        );
        let resp = self.with_auth_retry(|| self.client.post(&url))?;
        ok_json(resp)
    }

    /// (M2.25a) Start a tus upload for a file Send body. Returns the
    /// absolute Location URL for subsequent PATCH calls. Body MAY
    /// carry the first chunk via `creation-with-upload`.
    pub fn send_upload_create(
        &self,
        send_id: &str,
        upload_length: u64,
        upload_metadata: &str,
        first_chunk: Option<&[u8]>,
    ) -> Result<String> {
        let url = format!(
            "{}/api/v1/sends/{}/upload",
            self.base_url,
            urlencoding(send_id)
        );
        let body_bytes = first_chunk.map(<[u8]>::to_vec).unwrap_or_default();
        let resp = self.with_auth_retry(|| {
            let mut b = self
                .client
                .post(&url)
                .header("Tus-Resumable", "1.0.0")
                .header("Upload-Length", upload_length.to_string())
                .header("Upload-Metadata", upload_metadata);
            if !body_bytes.is_empty() {
                b = b
                    .header("Content-Type", "application/offset+octet-stream")
                    .body(body_bytes.clone());
            }
            b
        })?;
        let status = resp.status();
        if status != StatusCode::CREATED {
            let body = resp.text().unwrap_or_default();
            return Err(anyhow!("send upload-create failed: {status}: {body}"));
        }
        let location = resp
            .headers()
            .get(reqwest::header::LOCATION)
            .ok_or_else(|| anyhow!("send upload-create returned no Location header"))?
            .to_str()
            .context("Location header not ASCII")?
            .to_string();
        Ok(if location.starts_with("http") {
            location
        } else {
            format!("{}{}", self.base_url, location)
        })
    }

    /// PATCH bytes to a send tus upload at `offset`. Returns the new offset.
    /// Same shape as `tus_patch` for attachments — the server distinguishes
    /// the route by URL prefix (`/api/v1/tus-send/{token}` vs
    /// `/api/v1/tus/{token}`).
    pub fn send_tus_patch(&self, location: &str, offset: u64, bytes: Vec<u8>) -> Result<u64> {
        let resp = self.with_auth_retry(|| {
            self.client
                .patch(location)
                .header("Tus-Resumable", "1.0.0")
                .header("Upload-Offset", offset.to_string())
                .header("Content-Type", "application/offset+octet-stream")
                .body(bytes.clone())
        })?;
        let status = resp.status();
        if status != StatusCode::NO_CONTENT {
            let body = resp.text().unwrap_or_default();
            return Err(anyhow!("send tus patch failed: {status}: {body}"));
        }
        let new_off = resp
            .headers()
            .get("upload-offset")
            .ok_or_else(|| anyhow!("send tus patch returned no Upload-Offset"))?
            .to_str()?
            .parse()?;
        Ok(new_off)
    }

    /// HEAD a send tus upload to learn its current offset (for resume).
    pub fn send_tus_head(&self, location: &str) -> Result<u64> {
        let resp = self.with_auth_retry(|| self.client.head(location))?;
        if !resp.status().is_success() {
            let s = resp.status();
            let b = resp.text().unwrap_or_default();
            return Err(anyhow!("send tus head failed: {s}: {b}"));
        }
        let v = resp
            .headers()
            .get("upload-offset")
            .ok_or_else(|| anyhow!("send tus head returned no Upload-Offset"))?
            .to_str()?;
        Ok(v.parse()?)
    }

    /// Anonymous public-blob download via a token granted by /access.
    /// No bearer required.
    pub fn public_send_blob_download(
        &self,
        base_url: &str,
        send_id: &str,
        token: &str,
    ) -> Result<Vec<u8>> {
        let url = format!(
            "{}/api/v1/public/sends/{}/blob/{}",
            base_url.trim_end_matches('/'),
            urlencoding(send_id),
            urlencoding(token)
        );
        let resp = self
            .client
            .get(&url)
            .send()
            .map_err(|e| anyhow!("blob download HTTP error: {e}"))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().unwrap_or_default();
            return Err(anyhow!("blob download failed: {status}: {body}"));
        }
        Ok(resp.bytes()?.to_vec())
    }

    /// Anonymous public access. No bearer token. Returns the
    /// untouched JSON envelope so the CLI can render
    /// metadata + decrypted payload.
    pub fn public_access_send(
        &self,
        base_url: &str,
        id: &str,
        password: Option<&str>,
    ) -> Result<PublicAccessResponse> {
        let url = format!(
            "{}/api/v1/public/sends/{}/access",
            base_url.trim_end_matches('/'),
            urlencoding(id)
        );
        let body = serde_json::json!({"password": password});
        let resp = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .map_err(|e| anyhow!("send access HTTP error: {e}"))?;
        let status = resp.status();
        if status == StatusCode::OK {
            return Ok(resp.json()?);
        }
        let body = resp.text().unwrap_or_default();
        if status == StatusCode::UNAUTHORIZED {
            return Err(anyhow!("send password required or incorrect"));
        }
        if status == StatusCode::CONFLICT {
            return Err(anyhow!("send is unavailable: {body}"));
        }
        if status == StatusCode::NOT_FOUND {
            return Err(anyhow!("send not found"));
        }
        Err(anyhow!("send access failed: {status}: {body}"))
    }

    // ---- internals ----------------------------------------------------

    fn current_access(&self) -> Result<String> {
        self.state
            .borrow()
            .access
            .clone()
            .ok_or_else(|| anyhow!("API call requires authentication; run `hekate login`"))
    }

    fn with_auth_retry(&self, build: impl Fn() -> RequestBuilder) -> Result<Response> {
        let token = self.current_access()?;
        let resp = build().bearer_auth(&token).send()?;
        if resp.status() != StatusCode::UNAUTHORIZED {
            return Ok(resp);
        }
        // Try once to refresh.
        let refresh_token = self.state.borrow().refresh.clone();
        let Some(refresh_token) = refresh_token else {
            return Err(anyhow!(
                "session expired (401) and no refresh token available; run `hekate login`"
            ));
        };
        let new = self.do_refresh(&refresh_token)?;
        {
            let mut s = self.state.borrow_mut();
            s.access = Some(new.access_token.clone());
            s.refresh = Some(new.refresh_token);
            s.expires_at = Some(new.expires_at);
            s.refreshed = true;
        }
        Ok(build().bearer_auth(&new.access_token).send()?)
    }

    fn do_refresh(&self, refresh_token: &str) -> Result<RefreshedTokens> {
        let resp = self
            .client
            .post(format!("{}/identity/connect/token", self.base_url))
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
            ])
            .send()?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().unwrap_or_default();
            return Err(anyhow!(
                "refresh failed: {status}: {body}. Run `hekate login` again."
            ));
        }
        let tr: TokenResponse = resp.json()?;
        let expires_at =
            (chrono::Utc::now() + chrono::Duration::seconds(tr.expires_in as i64)).to_rfc3339();
        Ok(RefreshedTokens {
            access_token: tr.access_token,
            refresh_token: tr.refresh_token,
            expires_at,
        })
    }
}

fn ok_json<T: serde::de::DeserializeOwned>(resp: Response) -> Result<T> {
    let status = resp.status();
    if status.is_success() {
        Ok(resp.json()?)
    } else {
        let body = resp.text().unwrap_or_default();
        Err(anyhow!("server returned {status}: {body}"))
    }
}

fn urlencoding(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

// ---- wire types ------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct PreloginResponse {
    pub kdf_params: Value,
    pub kdf_salt: String,
    pub kdf_params_mac: String,
}

#[derive(Debug, Serialize)]
pub struct RegisterRequest {
    pub email: String,
    pub kdf_params: Value,
    pub kdf_salt: String,
    pub kdf_params_mac: String,
    pub master_password_hash: String,
    pub protected_account_key: String,
    pub account_public_key: String,
    pub protected_account_private_key: String,
    pub account_signing_pubkey: String,
    /// Client-supplied UUIDv7 (since M2.19) so it can be bound into the
    /// pubkey-bundle signature below.
    pub user_id: Option<String>,
    /// 64-byte Ed25519 signature over canonical
    /// (user_id || signing_pk || x25519_pk). See
    /// `hekate-core::signcrypt::sign_pubkey_bundle`.
    pub account_pubkey_bundle_sig: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // user_id is logged in future flows
pub struct RegisterResponse {
    pub user_id: String,
}

#[derive(Debug, Serialize)]
pub struct CipherInput {
    /// UUIDv7 generated client-side; bound into the AAD of every encrypted
    /// field on this cipher.
    pub id: String,
    #[serde(rename = "type")]
    pub cipher_type: i32,
    pub folder_id: Option<String>,
    pub protected_cipher_key: String,
    pub name: String,
    pub notes: Option<String>,
    pub data: String,
    pub favorite: bool,
    /// (M4.3) Org-owned cipher. When set, `protected_cipher_key` is
    /// wrapped under the org sym key, not the account key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub collection_ids: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CipherView {
    pub id: String,
    #[serde(rename = "type")]
    pub cipher_type: i32,
    pub folder_id: Option<String>,
    pub protected_cipher_key: String,
    pub name: String,
    pub notes: Option<String>,
    pub data: String,
    #[allow(dead_code)]
    pub favorite: bool,
    pub revision_date: String,
    #[allow(dead_code)]
    pub creation_date: String,
    pub deleted_date: Option<String>,
    /// `Some` for org-owned ciphers (M4.3), `None` for personal.
    /// Drives which key the client uses to unwrap.
    #[serde(default)]
    pub org_id: Option<String>,
    #[serde(default)]
    pub collection_ids: Vec<String>,
    /// (M4.4) The caller's effective permission on this cipher:
    /// "manage" | "read" | "read_hide_passwords". Personal ciphers
    /// always come back as "manage". `None` only on personal-vault
    /// rows from older server builds.
    #[serde(default)]
    pub permission: Option<String>,
}

#[derive(Debug)]
pub enum PutOutcome {
    Ok(CipherView),
    Conflict(CipherView),
}

#[derive(Debug, Serialize)]
pub struct ManifestUpload {
    pub version: i64,
    pub canonical_b64: String,
    pub signature_b64: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ManifestView {
    pub version: i64,
    pub canonical_b64: String,
    pub signature_b64: String,
    #[allow(dead_code)]
    pub updated_at: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PubkeyBundle {
    pub user_id: String,
    pub account_signing_pubkey: String,
    pub account_public_key: String,
    pub account_pubkey_bundle_sig: String,
}

#[derive(Debug, Serialize)]
pub struct CreateOrgRequest {
    pub id: String,
    pub name: String,
    pub signing_pubkey: String,
    pub bundle_sig: String,
    pub protected_signing_seed: String,
    pub org_sym_key_id: String,
    pub owner_protected_org_key: String,
    pub roster: SignedOrgRosterWire,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SignedOrgRosterWire {
    pub canonical_b64: String,
    pub signature_b64: String,
}

#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)] // many fields surface in M4.2+
pub struct OrgView {
    pub id: String,
    pub name: String,
    pub signing_pubkey: String,
    pub bundle_sig: String,
    pub owner_user_id: String,
    pub org_sym_key_id: String,
    pub roster: SignedOrgRosterWire,
    pub roster_version: i64,
    pub roster_updated_at: String,
    pub my_role: String,
    pub my_protected_org_key: String,
    /// Owner-only — wrapped signing seed under the OWNER's account_key.
    /// `None` for non-owners.
    #[serde(default)]
    pub owner_protected_signing_seed: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct OrgInviteRequest {
    pub invitee_user_id: String,
    pub role: String,
    pub envelope: serde_json::Value,
    pub next_roster: SignedOrgRosterWire,
}

#[derive(Debug, Serialize)]
pub struct AcceptOrgRequest {
    pub protected_org_key: String,
    pub org_sym_key_id: String,
}

#[derive(Debug, Serialize)]
pub struct CancelInviteRequest {
    pub next_roster: SignedOrgRosterWire,
}

#[derive(Debug, Serialize)]
pub struct RewrapEnvelope {
    pub user_id: String,
    pub envelope: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct CipherRewrap {
    pub cipher_id: String,
    pub protected_cipher_key: String,
}

#[derive(Debug, Serialize)]
pub struct CollectionRewrap {
    pub collection_id: String,
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct RevokeMemberRequest {
    pub next_roster: SignedOrgRosterWire,
    pub next_org_sym_key_id: String,
    pub owner_protected_org_key: String,
    pub rewrap_envelopes: Vec<RewrapEnvelope>,
    pub cipher_rewraps: Vec<CipherRewrap>,
    pub collection_rewraps: Vec<CollectionRewrap>,
}

#[derive(Debug, Serialize)]
pub struct RotateConfirmRequest {
    pub protected_org_key: String,
    pub org_sym_key_id: String,
}

#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)] // some fields informational
pub struct OrgInviteView {
    pub org_id: String,
    pub org_name: String,
    pub inviter_user_id: String,
    pub role: String,
    pub envelope: serde_json::Value,
    pub invited_at: String,
    pub roster_version: i64,
    /// Latest signed roster from the server, attached so invitees can
    /// verify membership before they have a `get_org` JOIN-able row.
    pub roster: SignedOrgRosterWire,
}

#[derive(Debug, Deserialize, Clone)]
pub struct OrgListItem {
    pub id: String,
    pub name: String,
    pub role: String,
    #[allow(dead_code)] // surfaced when M4.2 sync verification lands
    pub roster_version: i64,
    pub member_count: i64,
}

#[derive(Debug, Deserialize)]
pub struct SyncResponse {
    pub changes: SyncChanges,
    pub high_water: String,
    pub server_time: String,
    #[allow(dead_code)]
    pub complete: bool,
    #[serde(default)]
    pub manifest: Option<ManifestView>,
    /// One per org the user belongs to (M4.2). Empty for accounts with
    /// no org memberships.
    #[serde(default)]
    pub orgs: Vec<OrgSyncView>,
}

#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)] // some fields are pass-through context for future milestones
pub struct OrgSyncView {
    pub org_id: String,
    pub name: String,
    pub role: String,
    pub org_sym_key_id: String,
    pub roster_version: i64,
    pub roster_updated_at: String,
    pub roster: SignedOrgRosterWire,
    /// (M4.5b) Set when an org-key rotation is awaiting client pickup.
    /// Carries a SealedEnvelope JSON; client signcryption-decrypts it,
    /// re-wraps under their own account_key, and POSTs
    /// `/rotate-confirm` to clear.
    #[serde(default)]
    pub pending_envelope: Option<serde_json::Value>,
    /// (M4.6) Active policies for this org. Clients filter by
    /// `enabled` and apply max-strictness across orgs.
    #[serde(default)]
    pub policies: Vec<PolicyView>,
    /// (M2.21 / M4.5 follow-up) Latest signed org cipher manifest.
    /// `None` until the owner uploads the genesis. Members verify
    /// under the pinned org signing pubkey + cross-check every
    /// org-owned cipher in `changes.ciphers`.
    #[serde(default)]
    pub cipher_manifest: Option<OrgCipherManifestView>,
}

#[derive(Debug, Serialize)]
pub struct OrgCipherManifestUpload {
    pub version: i64,
    pub canonical_b64: String,
    pub signature_b64: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct OrgCipherManifestView {
    pub version: i64,
    pub canonical_b64: String,
    pub signature_b64: String,
    #[allow(dead_code)] // surfaced by future audit commands
    pub updated_at: String,
}

#[derive(Debug, Serialize)]
pub struct SetPolicyRequest {
    pub enabled: bool,
    pub config: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PolicyView {
    pub policy_type: String,
    pub enabled: bool,
    pub config: serde_json::Value,
    #[allow(dead_code)] // surfaced by `hekate org policy list` for audit
    pub updated_at: String,
}

#[derive(Debug, Deserialize)]
pub struct SyncChanges {
    pub ciphers: Vec<CipherView>,
    #[allow(dead_code)]
    pub folders: Vec<serde_json::Value>,
    pub tombstones: Vec<Tombstone>,
    /// (M4.3) Surfaced once we add a `hekate collection list-all` view;
    /// for now we expose collections via `hekate org collection list`
    /// per-org, but the field needs to be present here because the
    /// server includes it in the /sync payload.
    #[serde(default)]
    #[allow(dead_code)]
    pub collections: Vec<CollectionView>,
    /// (M2.24) Attachments delta. The CLI manifest builder uses these
    /// to compute the per-cipher `attachments_root` BW04 binding.
    #[serde(default)]
    pub attachments: Vec<AttachmentView>,
    /// (M2.25) Sender-owned Sends delta. Recipients don't /sync —
    /// they go through `/api/v1/public/sends/{id}/access`. Surfaced
    /// once `hekate send list` grows a `--all` watch mode; today the
    /// authenticated /api/v1/sends GET covers ad-hoc lookups.
    #[serde(default)]
    #[allow(dead_code)]
    pub sends: Vec<SendView>,
}

/// (M2.25) Send metadata returned to the owner via /sync and the
/// authenticated CRUD endpoints. `data` carries the encrypted payload;
/// `protected_send_key` carries the 32-byte send_key wrapped under the
/// account key (so the owner can edit/list without re-typing the URL
/// fragment).
#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
pub struct SendView {
    pub id: String,
    pub send_type: i32,
    pub name: String,
    #[serde(default)]
    pub notes: Option<String>,
    pub protected_send_key: String,
    pub data: String,
    pub has_password: bool,
    #[serde(default)]
    pub max_access_count: Option<i64>,
    pub access_count: i64,
    #[serde(default)]
    pub expiration_date: Option<String>,
    pub deletion_date: String,
    pub disabled: bool,
    pub revision_date: String,
    pub creation_date: String,
}

/// (M2.25) Anonymous public-access response. Recipient extracts the
/// send_key from the URL fragment, derives content_key via HKDF, and
/// decrypts `data` client-side. For file Sends (`send_type=2`) the
/// response additionally carries a `download_token` good for the
/// `/blob/{token}` GET (5-minute TTL) and the server-known
/// ciphertext size.
#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
pub struct PublicAccessResponse {
    pub id: String,
    pub send_type: i32,
    pub data: String,
    pub access_count: i64,
    pub max_access_count: Option<i64>,
    pub expiration_date: Option<String>,
    #[serde(default)]
    pub download_token: Option<String>,
    #[serde(default)]
    pub size_ct: Option<i64>,
}

/// (M2.24) Attachment metadata returned in /sync. Plaintext fields:
/// `id`, `cipher_id`, `revision_date`, `creation_date`, `size_pt`,
/// `size_ct`, `content_hash_b3`. Encrypted (under cipher key):
/// `filename`, `content_key`. `deleted_date` non-null when the row is
/// soft-deleted (currently always `None` — attachments hard-delete to
/// a tombstone — but reserved for future trash semantics).
#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
pub struct AttachmentView {
    pub id: String,
    pub cipher_id: String,
    pub filename: String,
    pub content_key: String,
    pub size_pt: i64,
    pub size_ct: i64,
    pub content_hash_b3: String,
    pub revision_date: String,
    pub creation_date: String,
    #[serde(default)]
    pub deleted_date: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CollectionView {
    pub id: String,
    pub org_id: String,
    pub name: String,
    #[allow(dead_code)]
    pub revision_date: String,
    #[allow(dead_code)]
    pub creation_date: String,
}

#[derive(Debug, Serialize)]
pub struct CreateCollectionRequest {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct MoveToOrgRequest {
    pub org_id: String,
    pub collection_ids: Vec<String>,
    pub protected_cipher_key: String,
    pub name: String,
    pub notes: Option<String>,
    pub data: String,
    pub favorite: bool,
}

#[derive(Debug, Serialize)]
pub struct MoveToPersonalRequest {
    pub protected_cipher_key: String,
    pub name: String,
    pub notes: Option<String>,
    pub data: String,
    pub favorite: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CollectionMemberView {
    #[allow(dead_code)] // surfaced by `hekate org collection members <org_id> <coll_id>`
    pub collection_id: String,
    pub user_id: String,
    pub permission: String,
}

#[derive(Debug, Deserialize)]
pub struct Tombstone {
    pub kind: String,
    pub id: String,
    pub deleted_at: String,
}

#[derive(Debug, Serialize)]
pub struct CreatePatRequest {
    pub name: String,
    pub scopes: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in_days: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct CreatePatResponse {
    pub id: String,
    pub token: String,
    pub name: String,
    pub scopes: String,
    pub expires_at: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct PatListItem {
    pub id: String,
    pub name: String,
    pub scopes: String,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub revoked_at: Option<String>,
    pub last_used_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CreateWebhookRequest {
    pub name: String,
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub events: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateWebhookResponse {
    pub id: String,
    pub name: String,
    pub url: String,
    pub events: String,
    pub secret: String,
}

#[derive(Debug, Serialize)]
pub struct ChangePasswordRequest {
    pub current_master_password_hash: String,
    pub new_master_password_hash: String,
    pub new_kdf_params: Value,
    pub new_kdf_salt: String,
    pub new_kdf_params_mac: String,
    pub new_protected_account_key: String,
    pub new_account_signing_pubkey: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct ChangePasswordResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub refresh_token: String,
}

// Distinct from `CipherRewrap` above (M4.5b — new wrap under the org
// sym key after member removal). These ride on the M2.26
// rotate-account-key flow and use different JSON field names.
#[derive(Debug, Serialize)]
pub struct AccountCipherRewrap {
    pub cipher_id: String,
    pub new_protected_cipher_key: String,
}

#[derive(Debug, Serialize)]
pub struct AccountSendRewrap {
    pub send_id: String,
    pub new_protected_send_key: String,
    pub new_name: String,
}

#[derive(Debug, Serialize)]
pub struct AccountOrgMemberRewrap {
    pub org_id: String,
    pub new_protected_org_key: String,
}

/// (M2.26) Body for `POST /api/v1/account/rotate-keys`. Master
/// password is unchanged; only the `account_key` (and the wrap of the
/// X25519 private key under it) rotates, plus all dependent re-wraps.
#[derive(Debug, Serialize)]
pub struct RotateKeysRequest {
    pub master_password_hash: String,
    pub new_protected_account_key: String,
    pub new_protected_account_private_key: String,
    pub cipher_rewraps: Vec<AccountCipherRewrap>,
    pub send_rewraps: Vec<AccountSendRewrap>,
    pub org_member_rewraps: Vec<AccountOrgMemberRewrap>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct RotateKeysResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub refresh_token: String,
    pub rewrote_ciphers: i64,
    pub rewrote_sends: i64,
    pub rewrote_org_memberships: i64,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct DeliveryItem {
    pub id: String,
    pub event_id: String,
    pub event_type: String,
    pub created_at: String,
    pub attempts: i32,
    pub next_attempt_at: String,
    pub last_status: Option<i32>,
    pub last_error: Option<String>,
    pub delivered_at: Option<String>,
    pub failed_permanently_at: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct WebhookListItem {
    pub id: String,
    pub name: String,
    pub url: String,
    pub events: String,
    pub created_at: String,
    pub disabled_at: Option<String>,
}

// ---- service accounts (M2.5) ----------------------------------------------

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // created_by_user_id surfaces in audit views
pub struct ServiceAccountView {
    pub id: String,
    pub org_id: String,
    pub name: String,
    pub created_by_user_id: String,
    pub created_at: String,
    pub disabled_at: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct CreateSaTokenResponse {
    pub id: String,
    pub token: String,
    pub name: String,
    pub scopes: String,
    pub expires_at: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct SaTokenListItem {
    pub id: String,
    pub name: String,
    pub scopes: String,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub revoked_at: Option<String>,
    pub last_used_at: Option<String>,
}

// ---- 2FA (M2.22) ----------------------------------------------------------

/// Either real tokens, or a "second factor required" prompt the caller
/// must satisfy by re-issuing the password grant with the supplied
/// challenge token.
#[derive(Debug)]
pub enum PasswordGrantOutcome {
    Tokens(TokenResponse),
    TwoFactorRequired(TwoFactorChallenge),
}

#[derive(Debug, Deserialize, Clone)]
pub struct TwoFactorChallenge {
    pub error: String,
    pub two_factor_providers: Vec<String>,
    pub two_factor_token: String,
}

struct SecondFactor<'a> {
    token: &'a str,
    provider: &'a str,
    value: &'a str,
}

#[derive(Debug, Serialize)]
pub struct TfaSetupRequest {
    pub master_password_hash: String,
    /// otpauth label (typically the account email). Empty → server uses "hekate".
    pub account_label: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // secret_b32 and otpauth_url surface to the user
pub struct TfaSetupResponse {
    pub secret_b32: String,
    pub otpauth_url: String,
    pub recovery_codes: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // tokens land in the local state file on confirm
pub struct TfaConfirmResponse {
    pub recovery_codes_count: u32,
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub refresh_token: String,
}

#[derive(Debug, Deserialize)]
pub struct TfaRecoveryRegenerateResponse {
    pub recovery_codes: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct TfaStatus {
    pub enabled: bool,
    pub recovery_codes_remaining: u32,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // some fields are reserved for future commands
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub refresh_token: String,

    #[serde(default)]
    pub kdf_params: Option<Value>,
    #[serde(default)]
    pub kdf_salt: Option<String>,
    #[serde(default)]
    pub kdf_params_mac: Option<String>,
    #[serde(default)]
    pub protected_account_key: Option<String>,
    #[serde(default)]
    pub account_public_key: Option<String>,
    #[serde(default)]
    pub protected_account_private_key: Option<String>,
    /// Server-stable user_id (UUIDv7). Populated on initial password
    /// grant; absent on refresh.
    #[serde(default)]
    pub user_id: Option<String>,
}
