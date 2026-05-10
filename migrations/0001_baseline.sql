-- Hekate baseline schema. Portable across SQLite and Postgres via sqlx's
-- `Any` driver. New deployments start here; this file replaces the
-- pre-public migration sequence (0001_initial through
-- 0023_pending_invite_roster) which is preserved in development history
-- only.
--
-- Conventions:
-- * UUIDv7 string ids in TEXT primary keys.
-- * RFC3339 / ISO-8601 timestamps stored as TEXT.
-- * Booleans stored as INTEGER 0/1 (SQLite has no native BOOLEAN).
-- * EncString columns hold ciphertext; key wrapping and AAD layout are
--   defined in `hekate-core` (see `aad_*` helpers).
--
-- See docs/design.md for the architecture overview and
-- docs/threat-model-gaps.md for the protocol-level integrity story.

-- =============================================================================
-- M0/M1 — users, devices, auth state
-- =============================================================================

CREATE TABLE users (
    id                              TEXT PRIMARY KEY NOT NULL,
    email                           TEXT NOT NULL UNIQUE,
    kdf_params                      TEXT NOT NULL,
    -- Client-side KDF salt, base64-no-pad. Bound to kdf_params via
    -- kdf_params_mac (BW07/LP04 mitigation: server cannot downgrade
    -- KDF parameters between registration and login).
    kdf_salt                        TEXT NOT NULL DEFAULT '',
    kdf_params_mac                  TEXT NOT NULL DEFAULT '',
    master_password_hash            TEXT NOT NULL,
    protected_account_key           TEXT NOT NULL,
    account_public_key              TEXT NOT NULL,
    protected_account_private_key   TEXT NOT NULL,
    -- Ed25519 signing pubkey (BW04 set-level integrity; manifest sigs).
    account_signing_pubkey_b64      TEXT NOT NULL DEFAULT '',
    -- Self-signed pubkey bundle (BW09/LP07/DL02 trust path).
    account_pubkey_bundle_sig_b64   TEXT NOT NULL DEFAULT '',
    revision_date                   TEXT NOT NULL,
    account_revision_date           TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    security_stamp                  TEXT NOT NULL,
    created_at                      TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_users_email ON users(email);

CREATE TABLE devices (
    id              TEXT PRIMARY KEY NOT NULL,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    device_type     TEXT NOT NULL,
    push_token      TEXT,
    public_key      TEXT NOT NULL,
    last_seen       TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at      TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_devices_user ON devices(user_id);

-- Server's symmetric secret for HS256 JWT signing. Multiple rows allow
-- key rotation; only the most recent non-retired row is used to sign,
-- and all non-retired rows are tried for verification.
CREATE TABLE signing_keys (
    id          TEXT PRIMARY KEY NOT NULL,
    secret_b64  TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    retired_at  TEXT
);

CREATE INDEX idx_signing_keys_active ON signing_keys(retired_at, created_at);

-- Refresh tokens: opaque random 256-bit values, stored as Argon2id PHC
-- strings. family_id groups tokens descended from the same login event so
-- we can revoke a whole chain on rotation reuse (token-replay defense).
CREATE TABLE refresh_tokens (
    id          TEXT PRIMARY KEY NOT NULL,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    family_id   TEXT NOT NULL,
    token_hash  TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at  TEXT NOT NULL,
    revoked_at  TEXT
);

CREATE INDEX idx_refresh_tokens_user   ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_family ON refresh_tokens(family_id);

-- =============================================================================
-- Vault — folders, ciphers, tombstones
-- =============================================================================

CREATE TABLE folders (
    id              TEXT PRIMARY KEY NOT NULL,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    revision_date   TEXT NOT NULL,
    creation_date   TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_folders_user ON folders(user_id, revision_date);

-- BW04: server-controlled metadata that affects security policy must not
-- live in plaintext. The `reprompt` flag is therefore *not* a column —
-- when re-introduced it lives inside the encrypted `data` blob, AAD-bound
-- to cipher_id and cipher_type.
CREATE TABLE ciphers (
    id                      TEXT PRIMARY KEY NOT NULL,
    user_id                 TEXT REFERENCES users(id) ON DELETE CASCADE,
    org_id                  TEXT,
    folder_id               TEXT REFERENCES folders(id) ON DELETE SET NULL,
    cipher_type             INTEGER NOT NULL,
    protected_cipher_key    TEXT NOT NULL,
    name                    TEXT NOT NULL,
    notes                   TEXT,
    data                    TEXT NOT NULL,
    favorite                INTEGER NOT NULL DEFAULT 0,
    revision_date           TEXT NOT NULL,
    creation_date           TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_date            TEXT,
    CHECK ((user_id IS NOT NULL AND org_id IS NULL)
        OR (user_id IS NULL AND org_id IS NOT NULL))
);

CREATE INDEX idx_ciphers_user_revision ON ciphers(user_id, revision_date);
CREATE INDEX idx_ciphers_folder        ON ciphers(folder_id);

-- Hard-delete tombstones for delta sync. Soft-deletes stay in `ciphers`
-- with `deleted_date`; only purges (or org/user deletion) create rows here.
CREATE TABLE tombstones (
    kind        TEXT NOT NULL,
    id          TEXT NOT NULL,
    user_id     TEXT NOT NULL,
    deleted_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (kind, id)
);

CREATE INDEX idx_tombstones_user ON tombstones(user_id, deleted_at);

-- =============================================================================
-- Long-lived bearer tokens (PATs)
-- =============================================================================

CREATE TABLE personal_access_tokens (
    id              TEXT PRIMARY KEY NOT NULL,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    token_hash      TEXT NOT NULL,
    scopes          TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at      TEXT,
    revoked_at      TEXT,
    last_used_at    TEXT
);

CREATE INDEX idx_pats_user ON personal_access_tokens(user_id, revoked_at);

-- =============================================================================
-- Webhooks + delivery queue
-- =============================================================================

CREATE TABLE webhooks (
    id          TEXT PRIMARY KEY NOT NULL,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    url         TEXT NOT NULL,
    secret_b64  TEXT NOT NULL,
    events      TEXT NOT NULL DEFAULT '*',
    created_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    disabled_at TEXT
);

CREATE INDEX idx_webhooks_user ON webhooks(user_id, disabled_at);

CREATE TABLE webhook_deliveries (
    id                      TEXT PRIMARY KEY NOT NULL,
    webhook_id              TEXT NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
    user_id                 TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    event_id                TEXT NOT NULL,
    event_type              TEXT NOT NULL,
    payload                 TEXT NOT NULL,
    created_at              TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    attempts                INTEGER NOT NULL DEFAULT 0,
    next_attempt_at         TEXT NOT NULL,
    last_status             INTEGER,
    last_error              TEXT,
    delivered_at            TEXT,
    failed_permanently_at   TEXT
);

CREATE INDEX idx_deliveries_due     ON webhook_deliveries(delivered_at, failed_permanently_at, next_attempt_at);
CREATE INDEX idx_deliveries_webhook ON webhook_deliveries(webhook_id, created_at);

-- =============================================================================
-- Vault manifest (BW04 set-level integrity, v3 layout)
-- =============================================================================

-- v3 canonical bytes embed `parent_canonical_sha256` and the per-entry
-- `attachments_root` (BLAKE3 over each cipher's attachment list).
CREATE TABLE vault_manifests (
    user_id        TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    version        BIGINT NOT NULL,
    canonical_b64  TEXT NOT NULL,
    signature_b64  TEXT NOT NULL,
    updated_at     TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- =============================================================================
-- Organizations (M4)
-- =============================================================================

CREATE TABLE organizations (
    id                     TEXT PRIMARY KEY,
    name                   TEXT NOT NULL,
    signing_pubkey_b64     TEXT NOT NULL,
    bundle_sig_b64         TEXT NOT NULL,
    owner_user_id          TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_sym_key_id         TEXT NOT NULL,
    roster_version         BIGINT NOT NULL DEFAULT 0,
    roster_canonical_b64   TEXT NOT NULL DEFAULT '',
    roster_signature_b64   TEXT NOT NULL DEFAULT '',
    roster_updated_at      TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at             TEXT NOT NULL,
    revision_date          TEXT NOT NULL
);

-- Owner's wrapped Ed25519 signing seed for the org. Owner-only.
CREATE TABLE organization_owner_keys (
    org_id                  TEXT PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    protected_signing_seed  TEXT NOT NULL
);

-- Pending invites: `pending_roster_*` carries the would-be-after-accept
-- roster; the live roster on `organizations` is only advanced on accept.
CREATE TABLE organization_invites (
    org_id                          TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    invitee_user_id                 TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    envelope_json                   TEXT NOT NULL,
    invited_role                    TEXT NOT NULL,
    invited_at                      TEXT NOT NULL,
    pending_roster_canonical_b64    TEXT NOT NULL DEFAULT '',
    pending_roster_signature_b64    TEXT NOT NULL DEFAULT '',
    pending_roster_version          BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (org_id, invitee_user_id)
);

-- `pending_org_key_envelope_json` carries the new wrapped org key
-- mid-rotation (M4.5b); cleared by /rotate-confirm.
CREATE TABLE organization_members (
    org_id                          TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id                         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role                            TEXT NOT NULL,
    protected_org_key               TEXT NOT NULL,
    org_sym_key_id                  TEXT NOT NULL,
    pending_org_key_envelope_json   TEXT,
    joined_at                       TEXT NOT NULL,
    PRIMARY KEY (org_id, user_id)
);

CREATE TABLE organization_collections (
    id              TEXT PRIMARY KEY,
    org_id          TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    revision_date   TEXT NOT NULL,
    creation_date   TEXT NOT NULL
);

CREATE TABLE collection_members (
    collection_id   TEXT NOT NULL REFERENCES organization_collections(id) ON DELETE CASCADE,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    permissions     TEXT NOT NULL,
    PRIMARY KEY (collection_id, user_id)
);

CREATE TABLE cipher_collections (
    cipher_id       TEXT NOT NULL REFERENCES ciphers(id) ON DELETE CASCADE,
    collection_id   TEXT NOT NULL REFERENCES organization_collections(id) ON DELETE CASCADE,
    PRIMARY KEY (cipher_id, collection_id)
);

-- Owner-set policies (M4.6). config_json schema is policy-type-specific
-- and validated at the API layer.
CREATE TABLE org_policies (
    org_id        TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    policy_type   TEXT NOT NULL,
    config_json   TEXT NOT NULL,
    enabled       INTEGER NOT NULL DEFAULT 1,
    updated_at    TEXT NOT NULL,
    PRIMARY KEY (org_id, policy_type)
);

-- Per-org signed cipher manifest (BW04 set-level integrity at org scope).
CREATE TABLE org_cipher_manifests (
    org_id          TEXT PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    version         BIGINT NOT NULL,
    canonical_b64   TEXT NOT NULL,
    signature_b64   TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

-- =============================================================================
-- Two-factor authentication (TOTP + WebAuthn)
-- =============================================================================

CREATE TABLE two_factor_totp (
    user_id           TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    secret_b32        TEXT NOT NULL,
    enabled_at        TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_period  BIGINT
);

CREATE TABLE two_factor_totp_pending (
    user_id     TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    secret_b32  TEXT NOT NULL,
    code_phcs   TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at  TEXT NOT NULL
);

-- Recovery codes are an authentication-only 2FA bypass, NOT a vault
-- recovery mechanism. See docs/threat-model-gaps.md.
CREATE TABLE two_factor_recovery_codes (
    id           TEXT PRIMARY KEY NOT NULL,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_phc     TEXT NOT NULL,
    created_at   TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    consumed_at  TEXT
);

CREATE INDEX idx_2fa_recovery_user ON two_factor_recovery_codes(user_id, consumed_at);

CREATE TABLE two_factor_webauthn_credentials (
    id              TEXT PRIMARY KEY NOT NULL,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id   TEXT NOT NULL,
    passkey_json    TEXT NOT NULL,
    name            TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at    TEXT,
    UNIQUE (user_id, credential_id)
);

CREATE INDEX idx_2fa_webauthn_user ON two_factor_webauthn_credentials(user_id);

CREATE TABLE two_factor_webauthn_pending (
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ceremony    TEXT NOT NULL,
    state_json  TEXT NOT NULL,
    name        TEXT,
    created_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at  TEXT NOT NULL,
    PRIMARY KEY (user_id, ceremony)
);

-- =============================================================================
-- Service accounts (machine identities)
-- =============================================================================

CREATE TABLE service_accounts (
    id                   TEXT PRIMARY KEY NOT NULL,
    org_id               TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name                 TEXT NOT NULL,
    created_by_user_id   TEXT NOT NULL REFERENCES users(id),
    created_at           TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    disabled_at          TEXT
);

CREATE INDEX idx_service_accounts_org ON service_accounts(org_id);

CREATE TABLE service_account_tokens (
    id                   TEXT PRIMARY KEY NOT NULL,
    service_account_id   TEXT NOT NULL REFERENCES service_accounts(id) ON DELETE CASCADE,
    name                 TEXT NOT NULL,
    token_hash           TEXT NOT NULL,
    scopes               TEXT NOT NULL,
    created_at           TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at           TEXT,
    revoked_at           TEXT,
    last_used_at         TEXT
);

CREATE INDEX idx_sat_service_account ON service_account_tokens(service_account_id);

-- =============================================================================
-- Attachments
-- =============================================================================

CREATE TABLE attachments (
    id              TEXT PRIMARY KEY NOT NULL,
    cipher_id       TEXT NOT NULL REFERENCES ciphers(id) ON DELETE CASCADE,
    user_id         TEXT REFERENCES users(id) ON DELETE SET NULL,
    org_id          TEXT,
    filename        TEXT NOT NULL,
    content_key     TEXT NOT NULL,
    size_ct         BIGINT NOT NULL,
    size_pt         BIGINT NOT NULL,
    storage_key     TEXT NOT NULL,
    content_hash_b3 TEXT NOT NULL,
    status          INTEGER NOT NULL DEFAULT 0,
    revision_date   TEXT NOT NULL,
    creation_date   TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_attachments_cipher      ON attachments(cipher_id);
CREATE INDEX idx_attachments_user_status ON attachments(user_id, status);
CREATE INDEX idx_attachments_revision    ON attachments(revision_date);

-- tus 1.0 state machine. One row per in-progress upload; deleted on
-- completion or termination. Background GC drops rows past `expires_at`.
CREATE TABLE attachment_uploads (
    id                TEXT PRIMARY KEY NOT NULL,
    upload_token      TEXT UNIQUE NOT NULL,
    bytes_received    BIGINT NOT NULL DEFAULT 0,
    expected_size     BIGINT NOT NULL,
    expires_at        TEXT NOT NULL,
    upload_metadata   TEXT NOT NULL DEFAULT ''
);

CREATE INDEX idx_attachment_uploads_token   ON attachment_uploads(upload_token);
CREATE INDEX idx_attachment_uploads_expires ON attachment_uploads(expires_at);

-- Durable signal that a blob's bytes can be removed. Survives restart so
-- a crash between row delete and blob delete doesn't orphan the file.
CREATE TABLE attachment_blob_tombstones (
    storage_key  TEXT PRIMARY KEY NOT NULL,
    enqueued_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- =============================================================================
-- Sends (ephemeral encrypted shares)
-- =============================================================================

-- Recipients are anonymous; the URL fragment carries `send_key` which the
-- server never sees. Server can revoke (delete/disable/expire/cap access)
-- but cannot decrypt.
CREATE TABLE sends (
    id                  TEXT PRIMARY KEY NOT NULL,
    user_id             TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    send_type           INTEGER NOT NULL,
    name                TEXT NOT NULL,
    notes               TEXT,
    protected_send_key  TEXT NOT NULL,
    data                TEXT NOT NULL,
    password_phc        TEXT,
    max_access_count    INTEGER,
    access_count        INTEGER NOT NULL DEFAULT 0,
    expiration_date     TEXT,
    deletion_date       TEXT NOT NULL,
    disabled            INTEGER NOT NULL DEFAULT 0,
    -- File-Send body lives in the BlobStore. NULL until tus finalize.
    storage_key         TEXT,
    size_ct             BIGINT,
    content_hash_b3     TEXT,
    -- 0 = no body / awaiting upload, 1 = body finalized.
    body_status         INTEGER NOT NULL DEFAULT 0,
    revision_date       TEXT NOT NULL,
    creation_date       TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_sends_user     ON sends(user_id, revision_date);
CREATE INDEX idx_sends_deletion ON sends(deletion_date);

-- tus state machine for file Sends; mirrors `attachment_uploads`.
CREATE TABLE send_uploads (
    id                TEXT PRIMARY KEY NOT NULL,
    upload_token      TEXT UNIQUE NOT NULL,
    bytes_received    BIGINT NOT NULL DEFAULT 0,
    expected_size     BIGINT NOT NULL,
    expires_at        TEXT NOT NULL,
    upload_metadata   TEXT NOT NULL DEFAULT ''
);

CREATE INDEX idx_send_uploads_token   ON send_uploads(upload_token);
CREATE INDEX idx_send_uploads_expires ON send_uploads(expires_at);

-- Anonymous bearer capabilities for /blob downloads of file Sends.
-- Minted by /access; consumed by TTL, not by first GET.
CREATE TABLE send_download_tokens (
    token       TEXT PRIMARY KEY NOT NULL,
    send_id     TEXT NOT NULL REFERENCES sends(id) ON DELETE CASCADE,
    expires_at  TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_send_download_tokens_send    ON send_download_tokens(send_id);
CREATE INDEX idx_send_download_tokens_expires ON send_download_tokens(expires_at);
