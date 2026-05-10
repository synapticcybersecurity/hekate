//! OpenAPI 3.1 spec assembled from utoipa-annotated handlers and types.
//!
//! Add new endpoints to `paths(...)` and new wire types to
//! `components(schemas(...))` as they ship. Drift between spec and
//! handlers is impossible — the spec is built from handler signatures.

use utoipa::{
    openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme},
    Modify, OpenApi,
};

#[derive(OpenApi)]
#[openapi(
    info(
        title = "hekate",
        version = env!("CARGO_PKG_VERSION"),
        description = "High-performance open-source password manager.\n\n\
            All authenticated endpoints accept `Authorization: Bearer <token>` \
            with either an interactive access JWT or a Personal Access Token \
            (`pmgr_pat_<id>.<secret>`). Scopes: `vault:read`, `vault:write`, \
            `account:admin`. Interactive JWTs implicitly carry every scope; \
            PATs only carry the scopes declared at issue time."
    ),
    paths(
        // accounts
        crate::routes::accounts::register,
        crate::routes::accounts::prelogin,
        crate::routes::account::change_password,
        crate::routes::account::delete_account,
        crate::routes::account::rotate_keys,
        // identity
        crate::routes::identity::token,
        // ciphers
        crate::routes::ciphers::create,
        crate::routes::ciphers::read,
        crate::routes::ciphers::update,
        crate::routes::ciphers::soft_delete,
        crate::routes::ciphers::restore,
        crate::routes::ciphers::purge,
        // folders
        crate::routes::folders::create,
        crate::routes::folders::read,
        crate::routes::folders::update,
        crate::routes::folders::purge,
        // sync
        crate::routes::sync::sync,
        // pubkey directory (BW09/LP07/DL02 cryptographic trust path)
        crate::routes::pubkeys::get_pubkeys,
        // vault manifest (BW04 set-level integrity)
        crate::routes::vault_manifest::upload,
        crate::routes::vault_manifest::get_manifest,
        // account/tokens (PATs)
        crate::routes::account_tokens::create,
        crate::routes::account_tokens::list,
        crate::routes::account_tokens::revoke,
        // account/webhooks
        crate::routes::account_webhooks::create,
        crate::routes::account_webhooks::list,
        crate::routes::account_webhooks::delete,
        crate::routes::account_webhooks::deliveries,
        // two-factor (M2.22)
        crate::routes::two_factor::totp_setup,
        crate::routes::two_factor::totp_confirm,
        crate::routes::two_factor::totp_disable,
        crate::routes::two_factor::recovery_regenerate,
        crate::routes::two_factor::status,
        // two-factor — WebAuthn (M2.23)
        crate::routes::two_factor_webauthn::register_start,
        crate::routes::two_factor_webauthn::register_finish,
        crate::routes::two_factor_webauthn::list_credentials,
        crate::routes::two_factor_webauthn::delete_credential,
        crate::routes::two_factor_webauthn::rename_credential,
        // service accounts (M2.5)
        crate::routes::service_accounts::create_sa,
        crate::routes::service_accounts::list_sa,
        crate::routes::service_accounts::disable_sa,
        crate::routes::service_accounts::delete_sa,
        crate::routes::service_accounts::create_token,
        crate::routes::service_accounts::list_tokens,
        crate::routes::service_accounts::revoke_token,
        crate::routes::service_accounts::me,
    ),
    components(schemas(
        crate::routes::accounts::ErrorResponse,
        crate::routes::accounts::RegisterRequest,
        crate::routes::accounts::RegisterResponse,
        crate::routes::accounts::PreloginRequest,
        crate::routes::accounts::PreloginResponse,
        crate::routes::account::ChangePasswordRequest,
        crate::routes::account::ChangePasswordResponse,
        crate::routes::account::DeleteAccountRequest,
        crate::routes::account::RotateKeysRequest,
        crate::routes::account::RotateKeysResponse,
        crate::routes::account::CipherRewrap,
        crate::routes::account::SendRewrap,
        crate::routes::account::OrgMemberRewrap,
        crate::routes::identity::TokenRequest,
        crate::routes::identity::TokenResponse,
        crate::routes::identity::TwoFactorChallenge,
        crate::routes::ciphers::CipherInput,
        crate::routes::ciphers::CipherView,
        crate::routes::folders::FolderInput,
        crate::routes::folders::FolderView,
        crate::routes::sync::SyncResponse,
        crate::routes::sync::Changes,
        crate::routes::sync::Tombstone,
        crate::routes::vault_manifest::ManifestUpload,
        crate::routes::vault_manifest::ManifestView,
        crate::routes::pubkeys::PubkeyBundle,
        crate::routes::account_tokens::CreateRequest,
        crate::routes::account_tokens::CreateResponse,
        crate::routes::account_tokens::ListItem,
        crate::routes::account_webhooks::CreateRequest,
        crate::routes::account_webhooks::CreateResponse,
        crate::routes::account_webhooks::WebhookListItem,
        crate::routes::account_webhooks::DeliveryItem,
        crate::routes::two_factor::TotpSetupRequest,
        crate::routes::two_factor::TotpSetupResponse,
        crate::routes::two_factor::TotpConfirmRequest,
        crate::routes::two_factor::TotpConfirmResponse,
        crate::routes::two_factor::TotpDisableRequest,
        crate::routes::two_factor::RecoveryRegenerateRequest,
        crate::routes::two_factor::RecoveryRegenerateResponse,
        crate::routes::two_factor::StatusResponse,
        crate::routes::two_factor_webauthn::RegisterStartRequest,
        crate::routes::two_factor_webauthn::RegisterStartResponse,
        crate::routes::two_factor_webauthn::RegisterFinishRequest,
        crate::routes::two_factor_webauthn::RegisterFinishResponse,
        crate::routes::two_factor_webauthn::CredentialListItem,
        crate::routes::two_factor_webauthn::RenameRequest,
        crate::routes::service_accounts::CreateServiceAccountRequest,
        crate::routes::service_accounts::ServiceAccountView,
        crate::routes::service_accounts::CreateTokenRequest,
        crate::routes::service_accounts::CreateTokenResponse,
        crate::routes::service_accounts::TokenListItem,
        crate::routes::service_accounts::MeResponse,
    )),
    tags(
        (name = "accounts", description = "Account lifecycle"),
        (name = "identity", description = "OAuth 2.0 token issuance"),
        (name = "vault", description = "Ciphers, folders, sync"),
        (name = "tokens", description = "Personal Access Tokens"),
        (name = "webhooks", description = "Outbound event subscriptions"),
        (name = "two-factor", description = "TOTP 2FA + recovery codes (M2.22)"),
        (name = "service-accounts", description = "Org-scoped machine identities (M2.5)"),
    ),
    modifiers(&SecurityAddon),
)]
pub struct ApiDoc;

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi
            .components
            .get_or_insert_with(utoipa::openapi::Components::default);
        components.add_security_scheme(
            "bearerAuth",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("JWT or pmgr_pat_<id>.<secret>")
                    .description(Some(
                        "Either an interactive access JWT (1-hour TTL, all scopes) or a \
                         Personal Access Token (long-lived, scope-limited).",
                    ))
                    .build(),
            ),
        );
    }
}
