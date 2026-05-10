//! `hekate org {create,list}` — M4.0.
//!
//! `create`:
//!   1. Generate a fresh Ed25519 signing keypair for the org.
//!   2. Sign the org bundle (binds owner's identity to org_id, name,
//!      signing_pubkey) with the owner's account signing key.
//!   3. Wrap the org signing seed under the owner's account_key.
//!   4. Generate a fresh org symmetric key (32 random bytes) and wrap
//!      it under the owner's account_key.
//!   5. Build the genesis roster (version=1, parent=zeros, single
//!      owner entry) and sign it with the org signing key.
//!   6. POST /api/v1/orgs.
//!
//! `list`: GET /api/v1/account/orgs and pretty-print.

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use hekate_core::{
    encstring::EncString,
    keypair::random_key_32,
    manifest::signing_key_from_seed,
    org_roster::{
        decode_canonical as decode_roster_canonical, hash_canonical, OrgRoster, OrgRosterEntry,
        NO_PARENT_HASH,
    },
    signcrypt::{self, SealedEnvelope},
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    api::{
        AcceptOrgRequest, Api, CancelInviteRequest, CreateCollectionRequest, CreateOrgRequest,
        OrgInviteRequest, OrgView, SignedOrgRosterWire,
    },
    commands::{persist_refreshed_tokens, unlock_session},
    crypto::{Unlocked, AAD_PROTECTED_ACCOUNT_KEY},
    state::{self, OrgPin},
};
use zeroize::Zeroizing;

#[derive(Debug, Parser)]
pub struct Args {
    #[command(subcommand)]
    pub action: Action,
}

#[derive(Debug, Subcommand)]
pub enum Action {
    /// Create a new organization. The caller becomes the sole owner;
    /// they hold the org Ed25519 signing key (wrapped under their
    /// account key) and start with a single-member roster.
    Create {
        #[arg(long)]
        name: String,
    },
    /// List orgs the caller is a member of.
    List,
    /// (owner-only) Invite a peer to an org. The peer must already be
    /// pinned via `hekate peer fetch <peer_user_id>` so the invitation
    /// is wrapped to a TOFU-verified pubkey.
    Invite {
        /// Org UUID.
        org_id: String,
        /// Peer's user UUID. Must already be in `hekate peer pins`.
        peer_user_id: String,
        /// Role to grant. "admin" | "user".
        #[arg(long, default_value = "user")]
        role: String,
    },
    /// List invitations the current user has received and not yet accepted.
    Invites,
    /// Accept a pending invitation. Verifies the inviter's signcryption
    /// envelope, the org's self-signed bundle, and the latest signed
    /// roster — then TOFU-pins the org's signing pubkey and records
    /// membership locally.
    Accept { org_id: String },
    /// (owner-only) Cancel an outstanding invitation that hasn't been
    /// accepted yet. Re-signs the roster without the invitee.
    CancelInvite {
        org_id: String,
        peer_user_id: String,
    },
    /// (owner-only, M4.5b) Remove a member from the org. Triggers a
    /// mandatory rotation of the org symmetric key: a fresh key is
    /// generated, signcrypted to every remaining non-owner member's
    /// TOFU-pinned X25519 pubkey, and every org-owned cipher is
    /// re-wrapped under the new key in one atomic POST. The revoked
    /// member's rows are dropped server-side; their old wrap of the
    /// org sym key becomes useless against new ciphers (plaintext
    /// they already decrypted is still theirs — that's a fundamental
    /// cryptographic limit, see threat-model-gaps).
    RemoveMember { org_id: String, user_id: String },
    /// Collection management (M4.3). Names are encrypted under the
    /// org symmetric key; only members can decrypt them.
    #[command(subcommand)]
    Collection(CollectionAction),
    /// Policy management (M4.6). Owner-set knobs that constrain
    /// member clients (master-password complexity, vault timeout,
    /// password-generator rules, single-org, restrict-send).
    #[command(subcommand)]
    Policy(PolicyAction),
    /// Per-org signed cipher manifest (M2.21 / M4.5 follow-up).
    /// BW04 set-level integrity at org scope.
    #[command(subcommand)]
    CipherManifest(CipherManifestAction),
    /// Service-account management (M2.5). Org-owner-only.
    #[command(subcommand, name = "service-account")]
    ServiceAccount(ServiceAccountAction),
}

#[derive(Debug, Subcommand)]
pub enum ServiceAccountAction {
    /// (owner-only) Create a new service account in this org.
    Create {
        org_id: String,
        #[arg(long)]
        name: String,
    },
    /// (owner-only) List service accounts in this org.
    List { org_id: String },
    /// (owner-only) Disable an SA. Every existing AND future token
    /// against it is immediately rejected at verify time.
    Disable { org_id: String, sa_id: String },
    /// (owner-only) Permanently delete an SA + cascade its tokens.
    Delete {
        org_id: String,
        sa_id: String,
        /// Skip the typed confirmation prompt.
        #[arg(long)]
        yes: bool,
    },
    /// Token management for an SA (subcommand).
    #[command(subcommand)]
    Token(ServiceAccountTokenAction),
}

#[derive(Debug, Subcommand)]
pub enum ServiceAccountTokenAction {
    /// (owner-only) Issue a fresh token. The wire token is printed
    /// ONCE; store it now.
    Create {
        org_id: String,
        sa_id: String,
        #[arg(long)]
        name: String,
        /// Comma-separated scopes. M2.5 ships `org:read`. Future M6
        /// adds `secrets:read` / `secrets:write`.
        #[arg(long, default_value = "org:read")]
        scopes: String,
        /// Days until the token expires. Omit for never-expires.
        #[arg(long)]
        expires_in_days: Option<i64>,
    },
    /// (owner-only) List tokens issued for an SA (metadata only).
    List { org_id: String, sa_id: String },
    /// (owner-only) Revoke a single token.
    Revoke {
        org_id: String,
        sa_id: String,
        token_id: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum CollectionAction {
    /// (owner-only for M4.3) Create a new collection.
    Create {
        org_id: String,
        #[arg(long)]
        name: String,
    },
    /// List collections in an org. Member-only.
    List { org_id: String },
    /// (owner-only) Delete a collection. Member ciphers stay (just
    /// lose the assignment); they can be removed separately.
    Delete {
        org_id: String,
        collection_id: String,
    },
    /// (owner-only, M4.4) Grant a user a permission on this collection.
    /// Idempotent: replaces any existing row for `(collection, user)`.
    Grant {
        org_id: String,
        collection_id: String,
        user_id: String,
        /// "manage" | "read" | "read_hide_passwords"
        #[arg(long, default_value = "read")]
        permission: String,
    },
    /// (owner-only, M4.4) Revoke a user's permission on this collection.
    /// Idempotent: succeeds even if the row is already absent.
    Revoke {
        org_id: String,
        collection_id: String,
        user_id: String,
    },
    /// List the (user_id, permission) pairs on a collection. Visible to
    /// the org owner and to members with `manage` on the collection.
    Members {
        org_id: String,
        collection_id: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum PolicyAction {
    /// (owner-only) Set or replace a policy on this org. Idempotent.
    Set {
        org_id: String,
        /// One of: master_password_complexity | vault_timeout |
        /// password_generator_rules | single_org | restrict_send.
        policy_type: String,
        /// Whether the policy is active. Defaults to enabled so the
        /// common path ("set this policy") needs no flag. Pass
        /// `--enabled false` to pre-stage / disable.
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        enabled: bool,
        /// Opaque JSON config. Schema depends on policy_type; see
        /// docs/m4-organizations.md §8 (M4.6). Empty object for
        /// policies that take no config (single_org / restrict_send).
        #[arg(long, default_value = "{}")]
        config: String,
    },
    /// Get a single policy by type (any member can read).
    Get { org_id: String, policy_type: String },
    /// List every policy on this org (any member can read).
    List { org_id: String },
    /// (owner-only) Delete a policy outright. Idempotent.
    Unset { org_id: String, policy_type: String },
}

#[derive(Debug, Subcommand)]
pub enum CipherManifestAction {
    /// (owner-only) Rebuild + sign + upload the org's cipher manifest
    /// from the current /sync state. Use after non-owner writes have
    /// left the manifest stale.
    Refresh { org_id: String },
}

pub fn run(args: Args) -> Result<()> {
    match args.action {
        Action::Create { name } => create_org(&name),
        Action::List => list_orgs(),
        Action::Invite {
            org_id,
            peer_user_id,
            role,
        } => invite_member(&org_id, &peer_user_id, &role),
        Action::Invites => list_invites(),
        Action::Accept { org_id } => accept_invite(&org_id),
        Action::CancelInvite {
            org_id,
            peer_user_id,
        } => cancel_invite(&org_id, &peer_user_id),
        Action::RemoveMember { org_id, user_id } => remove_member(&org_id, &user_id),
        Action::Collection(action) => match action {
            CollectionAction::Create { org_id, name } => create_collection(&org_id, &name),
            CollectionAction::List { org_id } => list_collections(&org_id),
            CollectionAction::Delete {
                org_id,
                collection_id,
            } => delete_collection(&org_id, &collection_id),
            CollectionAction::Grant {
                org_id,
                collection_id,
                user_id,
                permission,
            } => grant_permission(&org_id, &collection_id, &user_id, &permission),
            CollectionAction::Revoke {
                org_id,
                collection_id,
                user_id,
            } => revoke_permission(&org_id, &collection_id, &user_id),
            CollectionAction::Members {
                org_id,
                collection_id,
            } => list_collection_members(&org_id, &collection_id),
        },
        Action::Policy(action) => match action {
            PolicyAction::Set {
                org_id,
                policy_type,
                enabled,
                config,
            } => set_policy(&org_id, &policy_type, enabled, &config),
            PolicyAction::Get {
                org_id,
                policy_type,
            } => get_policy(&org_id, &policy_type),
            PolicyAction::List { org_id } => list_policies(&org_id),
            PolicyAction::Unset {
                org_id,
                policy_type,
            } => unset_policy(&org_id, &policy_type),
        },
        Action::CipherManifest(action) => match action {
            CipherManifestAction::Refresh { org_id } => refresh_cipher_manifest(&org_id),
        },
        Action::ServiceAccount(action) => match action {
            ServiceAccountAction::Create { org_id, name } => create_service_account(&org_id, &name),
            ServiceAccountAction::List { org_id } => list_service_accounts(&org_id),
            ServiceAccountAction::Disable { org_id, sa_id } => {
                disable_service_account(&org_id, &sa_id)
            }
            ServiceAccountAction::Delete { org_id, sa_id, yes } => {
                delete_service_account(&org_id, &sa_id, yes)
            }
            ServiceAccountAction::Token(t) => match t {
                ServiceAccountTokenAction::Create {
                    org_id,
                    sa_id,
                    name,
                    scopes,
                    expires_in_days,
                } => create_sa_token(&org_id, &sa_id, &name, &scopes, expires_in_days),
                ServiceAccountTokenAction::List { org_id, sa_id } => {
                    list_sa_tokens(&org_id, &sa_id)
                }
                ServiceAccountTokenAction::Revoke {
                    org_id,
                    sa_id,
                    token_id,
                } => revoke_sa_token(&org_id, &sa_id, &token_id),
            },
        },
    }
}

fn create_org(name: &str) -> Result<()> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("--name must not be empty"));
    }

    let (mut state, api, unlocked) = unlock_session()?;
    if state.user.user_id.is_empty() {
        return Err(anyhow!(
            "local state has no user_id — re-run `hekate login` to refresh \
             (M2.20+ persists user_id from the token-grant response)."
        ));
    }

    // 1. Org Ed25519 signing keypair.
    let org_signing_seed = random_key_32();
    let org_signing_key = SigningKey::from_bytes(&org_signing_seed);
    let org_signing_pubkey = org_signing_key.verifying_key();
    let org_signing_pubkey_bytes = org_signing_pubkey.to_bytes();

    // 2. IDs.
    let org_id = Uuid::now_v7().to_string();
    let org_sym_key_id = Uuid::now_v7().to_string();

    // 3. Owner Ed25519-signs the org bundle (binds owner identity to
    //    org_id, name, signing_pubkey). Same canonical-bytes layout
    //    as the server's build_bundle_canonical().
    let owner_signing_key = signing_key_from_seed(&unlocked.signing_seed);
    let bundle_canonical = bundle_canonical_bytes(
        &org_id,
        trimmed,
        &org_signing_pubkey_bytes,
        &state.user.user_id,
    );
    let bundle_sig = owner_signing_key.sign(&bundle_canonical);

    // 4. Wrap the org signing seed under the owner's account_key.
    let protected_signing_seed = EncString::encrypt_xc20p(
        "ak:1",
        &unlocked.account_key,
        &org_signing_seed[..],
        b"pmgr-org-signing-seed",
    )
    .map_err(|e| anyhow!("wrap org signing seed: {e}"))?
    .to_wire();

    // 5. Generate the org symmetric key and wrap it under the owner's
    //    account_key. (At M4.1, the same key gets wrapped to invitees
    //    via signcryption envelopes.)
    let org_sym_key = random_key_32();
    let owner_protected_org_key = EncString::encrypt_xc20p(
        "ak:1",
        &unlocked.account_key,
        &org_sym_key[..],
        AAD_PROTECTED_ACCOUNT_KEY, // re-use the well-trodden AAD; safe because key_id namespaces it
    )
    .map_err(|e| anyhow!("wrap org sym key: {e}"))?
    .to_wire();

    // 6. Genesis roster.
    let genesis = OrgRoster {
        org_id: org_id.clone(),
        version: 1,
        parent_canonical_sha256: NO_PARENT_HASH,
        timestamp: chrono::Utc::now().to_rfc3339(),
        entries: vec![OrgRosterEntry {
            user_id: state.user.user_id.clone(),
            role: "owner".into(),
        }],
        org_sym_key_id: org_sym_key_id.clone(),
    };
    let signed_roster = genesis.sign(&org_signing_key);

    // 7. POST.
    let view = api
        .create_org(&CreateOrgRequest {
            id: org_id.clone(),
            name: trimmed.to_string(),
            signing_pubkey: STANDARD_NO_PAD.encode(org_signing_pubkey_bytes),
            bundle_sig: STANDARD_NO_PAD.encode(bundle_sig.to_bytes()),
            protected_signing_seed,
            org_sym_key_id,
            owner_protected_org_key,
            roster: SignedOrgRosterWire {
                canonical_b64: signed_roster.canonical_b64.clone(),
                signature_b64: signed_roster.signature_b64,
            },
        })
        .context("create org")?;

    // Pin our own org so M4.2 /sync verification has a trust anchor.
    // The owner trusts the signing key absolutely (they generated it),
    // so the fingerprint here is over the bundle_canonical we just
    // signed — same shape `hekate peer fingerprint` uses for accounts.
    let fingerprint = format!(
        "SHA256:{}",
        STANDARD_NO_PAD.encode(Sha256::digest(&bundle_canonical))
    );
    state.org_pins.insert(
        org_id.clone(),
        OrgPin {
            org_id: org_id.clone(),
            signing_pubkey_b64: STANDARD_NO_PAD.encode(org_signing_pubkey_bytes),
            fingerprint,
            first_seen_at: chrono::Utc::now().to_rfc3339(),
            last_roster_version: 1,
            last_roster_canonical_b64: signed_roster.canonical_b64,
        },
    );
    crate::state::save(&state)?;
    persist_refreshed_tokens(&api, state)?;

    println!("✓ Created org \"{}\" ({})", view.name, view.id);
    println!("  role: {}", view.my_role);
    println!("  roster version: {}", view.roster_version);
    Ok(())
}

fn list_orgs() -> Result<()> {
    let st = crate::state::load()?
        .ok_or_else(|| anyhow!("not logged in. Run `hekate login` or `hekate register` first."))?;
    let api = Api::new(&st.server_url)?
        .with_bearer(st.tokens.access_token.clone())
        .with_refresh(st.tokens.refresh_token.clone());

    let orgs = api.list_my_orgs().context("list orgs")?;
    if orgs.is_empty() {
        println!("(no orgs)");
        return Ok(());
    }
    println!(
        "{:<40}  {:<24}  {:<8}  {:<8}  members",
        "ID", "NAME", "ROLE", "VERSION"
    );
    for o in &orgs {
        println!(
            "{:<40}  {:<24}  {:<8}  {:<8}  {}",
            o.id, o.name, o.role, o.roster_version, o.member_count,
        );
    }
    persist_refreshed_tokens(&api, st)?;
    Ok(())
}

// --- helpers --------------------------------------------------------------

/// Thin alias over the canonical `hekate-core::org_roster::
/// org_bundle_canonical_bytes` so existing call-sites here keep
/// their short name. Single source of truth lives in hekate-core.
fn bundle_canonical_bytes(
    org_id: &str,
    name: &str,
    signing_pubkey: &[u8; 32],
    owner_user_id: &str,
) -> Vec<u8> {
    hekate_core::org_roster::org_bundle_canonical_bytes(org_id, name, signing_pubkey, owner_user_id)
}

// ===========================================================================
// M4.1 — invite, invites (list), accept, cancel-invite
// ===========================================================================

fn invite_member(org_id: &str, peer_user_id: &str, role: &str) -> Result<()> {
    if role != "admin" && role != "user" {
        return Err(anyhow!("--role must be \"admin\" or \"user\""));
    }
    let (state, api, unlocked) = unlock_session()?;
    if state.user.user_id.is_empty() {
        return Err(anyhow!(
            "local state has no user_id — re-run `hekate login` to refresh."
        ));
    }

    // Owner-only check is enforced server-side via 404, but we surface a
    // clearer error here by fetching the org first.
    let org = api.get_org(org_id).context("fetch org")?;
    if org.owner_user_id != state.user.user_id {
        return Err(anyhow!(
            "only the org owner can invite members (single-signer model in M4.1)"
        ));
    }
    let protected_signing_seed = org
        .owner_protected_signing_seed
        .as_deref()
        .ok_or_else(|| anyhow!("server omitted owner_protected_signing_seed"))?;

    // Pinned peer required — the BW09 trust path comes from the
    // out-of-band TOFU verification on the peer's bundle, not
    // server-supplied pubkeys.
    let peer = state.peer_pins.get(peer_user_id).ok_or_else(|| {
        anyhow!(
            "peer {peer_user_id} is not pinned — run `hekate peer fetch {peer_user_id}` \
             first and verify the fingerprint out of band before inviting them."
        )
    })?;
    let peer_x25519_pk = decode_pubkey(&peer.account_public_key_b64, "peer x25519")?;

    // Unwrap the org symmetric key (cached as `my_protected_org_key`)
    // and the org signing seed.
    let org_sym_key = unwrap_under_account_key(
        &unlocked.account_key,
        &org.my_protected_org_key,
        AAD_PROTECTED_ACCOUNT_KEY,
        "org symmetric key",
    )?;
    let org_signing_seed = unwrap_under_account_key(
        &unlocked.account_key,
        protected_signing_seed,
        b"pmgr-org-signing-seed",
        "org signing seed",
    )?;
    let org_signing_key = SigningKey::from_bytes(&org_signing_seed);

    // Build + sign the next roster (current + invitee).
    let current = parse_current_roster(&org)?;
    let mut next_entries = current.entries.clone();
    next_entries.push(OrgRosterEntry {
        user_id: peer_user_id.to_string(),
        role: role.to_string(),
    });
    let cur_canonical = STANDARD_NO_PAD
        .decode(&org.roster.canonical_b64)
        .context("decode current canonical")?;
    let next = OrgRoster {
        org_id: org.id.clone(),
        version: current.version + 1,
        parent_canonical_sha256: hash_canonical(&cur_canonical),
        timestamp: chrono::Utc::now().to_rfc3339(),
        entries: next_entries,
        org_sym_key_id: org.org_sym_key_id.clone(),
    };
    let signed_next = next.sign(&org_signing_key);

    // Build + signcrypt the invite payload to the invitee.
    let owner_signing_key = signing_key_from_seed(&unlocked.signing_seed);
    let payload = serde_json::json!({
        "org_id": org.id,
        "org_signing_pubkey_b64": org.signing_pubkey,
        "org_bundle_sig_b64": org.bundle_sig,
        "org_name": org.name,
        "org_sym_key_id": org.org_sym_key_id,
        "org_sym_key_b64": STANDARD_NO_PAD.encode(&org_sym_key[..]),
        "role": role,
    });
    let envelope = signcrypt::sign_encrypt(
        &owner_signing_key,
        &state.user.user_id,
        peer_user_id,
        &peer_x25519_pk,
        payload.to_string().as_bytes(),
    )
    .map_err(|e| anyhow!("signcrypt: {e}"))?;
    let envelope_value = serde_json::to_value(&envelope)?;

    api.invite_member(
        org_id,
        &OrgInviteRequest {
            invitee_user_id: peer_user_id.to_string(),
            role: role.to_string(),
            envelope: envelope_value,
            next_roster: SignedOrgRosterWire {
                canonical_b64: signed_next.canonical_b64,
                signature_b64: signed_next.signature_b64,
            },
        },
    )?;
    persist_refreshed_tokens(&api, state)?;
    println!("✓ Invited {peer_user_id} to \"{}\" as {role}.", org.name);
    println!("  Roster bumped to v{}.", current.version + 1);
    Ok(())
}

fn list_invites() -> Result<()> {
    let st = crate::state::load()?.ok_or_else(|| anyhow!("not logged in"))?;
    let api = Api::new(&st.server_url)?
        .with_bearer(st.tokens.access_token.clone())
        .with_refresh(st.tokens.refresh_token.clone());
    let invites = api.list_my_invites()?;
    if invites.is_empty() {
        println!("(no pending invitations)");
        return Ok(());
    }
    println!(
        "{:<40}  {:<24}  {:<8}  {:<40}  invited",
        "ORG", "NAME", "ROLE", "INVITER"
    );
    for inv in &invites {
        println!(
            "{:<40}  {:<24}  {:<8}  {:<40}  {}",
            inv.org_id, inv.org_name, inv.role, inv.inviter_user_id, inv.invited_at,
        );
    }
    persist_refreshed_tokens(&api, st)?;
    Ok(())
}

fn accept_invite(org_id: &str) -> Result<()> {
    let (mut state, api, unlocked) = unlock_session()?;
    if state.user.user_id.is_empty() {
        return Err(anyhow!(
            "local state has no user_id — re-run `hekate login` to refresh."
        ));
    }

    // Find our pending invite for this org.
    let invites = api.list_my_invites()?;
    let invite = invites
        .into_iter()
        .find(|i| i.org_id == org_id)
        .ok_or_else(|| anyhow!("no pending invitation for org {org_id}"))?;

    // Inviter MUST already be in our peer pins. Verifying the envelope
    // requires their TOFU-pinned signing pubkey; without that, the
    // server could substitute the entire envelope.
    let inviter_pin = state
        .peer_pins
        .get(&invite.inviter_user_id)
        .ok_or_else(|| {
            anyhow!(
                "inviter {} is not pinned — run `hekate peer fetch {}` first \
             and verify the fingerprint out of band before accepting.",
                invite.inviter_user_id,
                invite.inviter_user_id,
            )
        })?;
    let inviter_signing_pk =
        decode_pubkey(&inviter_pin.account_signing_pubkey_b64, "inviter signing")?;
    let inviter_vk = VerifyingKey::from_bytes(&inviter_signing_pk)
        .map_err(|_| anyhow!("inviter signing pubkey not Ed25519"))?;

    // Decode our own X25519 private key from protected_account_private_key.
    let my_x25519_priv = decrypt_x25519_priv(
        &unlocked.account_key,
        &state.account_material.protected_account_private_key,
    )?;

    // Verify + decrypt the envelope.
    let envelope: SealedEnvelope =
        serde_json::from_value(invite.envelope.clone()).context("envelope shape")?;
    let plaintext =
        signcrypt::verify_decrypt(&envelope, &inviter_vk, &state.user.user_id, &my_x25519_priv)
            .map_err(|e| {
                anyhow!(
                    "invite envelope did not verify: {e} — server may be attempting substitution"
                )
            })?;
    let payload: serde_json::Value =
        serde_json::from_slice(&plaintext).context("envelope payload")?;

    // Cross-check the payload's org_id matches the invite we're accepting.
    if payload["org_id"].as_str() != Some(org_id) {
        return Err(anyhow!(
            "envelope org_id does not match invitation — server tampering?"
        ));
    }
    let claimed_role = payload["role"]
        .as_str()
        .ok_or_else(|| anyhow!("envelope payload missing role"))?;
    if claimed_role != invite.role {
        return Err(anyhow!(
            "envelope role ({claimed_role}) does not match invitation role ({}) — \
             server tampering?",
            invite.role
        ));
    }
    let org_signing_pk_b64 = payload["org_signing_pubkey_b64"]
        .as_str()
        .ok_or_else(|| anyhow!("envelope payload missing org_signing_pubkey_b64"))?;
    let org_bundle_sig_b64 = payload["org_bundle_sig_b64"]
        .as_str()
        .ok_or_else(|| anyhow!("envelope payload missing org_bundle_sig_b64"))?;
    let org_name = payload["org_name"].as_str().unwrap_or("");
    let org_sym_key_id = payload["org_sym_key_id"]
        .as_str()
        .ok_or_else(|| anyhow!("envelope payload missing org_sym_key_id"))?
        .to_string();
    let org_sym_key_b64 = payload["org_sym_key_b64"]
        .as_str()
        .ok_or_else(|| anyhow!("envelope payload missing org_sym_key_b64"))?;
    let org_signing_pk = decode_pubkey(org_signing_pk_b64, "org signing")?;

    // Verify the org bundle sig under the inviter's pinned signing key
    // — this binds (org_id, org_name, org_signing_pk, owner_user_id)
    // and proves the inviter created this org.
    let bundle_canonical =
        bundle_canonical_bytes(org_id, org_name, &org_signing_pk, &invite.inviter_user_id);
    let bundle_sig_bytes = STANDARD_NO_PAD
        .decode(org_bundle_sig_b64)
        .context("decode org_bundle_sig")?;
    let bundle_sig = ed25519_dalek::Signature::from_slice(&bundle_sig_bytes)
        .map_err(|_| anyhow!("bundle sig has wrong length"))?;
    inviter_vk
        .verify_strict(&bundle_canonical, &bundle_sig)
        .map_err(|_| anyhow!("org bundle sig did not verify under inviter's pinned key"))?;

    // Verify the latest roster signature under the (now-trusted) org
    // signing pubkey; confirm we're listed in it with the claimed role.
    // Roster comes from the InviteView itself — we don't have a member
    // row yet, so `GET /api/v1/orgs/:id` would 404.
    let roster_canonical = STANDARD_NO_PAD
        .decode(&invite.roster.canonical_b64)
        .context("decode roster canonical")?;
    let roster_sig_bytes = STANDARD_NO_PAD
        .decode(&invite.roster.signature_b64)
        .context("decode roster signature")?;
    let org_vk = VerifyingKey::from_bytes(&org_signing_pk)
        .map_err(|_| anyhow!("org signing pubkey not Ed25519"))?;
    let roster_sig = ed25519_dalek::Signature::from_slice(&roster_sig_bytes)
        .map_err(|_| anyhow!("roster sig has wrong length"))?;
    org_vk
        .verify_strict(&roster_canonical, &roster_sig)
        .map_err(|_| anyhow!("server roster sig did not verify under org signing key"))?;
    let roster = decode_roster_canonical(&roster_canonical).context("decode roster canonical")?;
    if !roster
        .entries
        .iter()
        .any(|e| e.user_id == state.user.user_id && e.role == claimed_role)
    {
        return Err(anyhow!(
            "server's signed roster does not list me at the claimed role — refuse to accept."
        ));
    }

    // Decode the org symmetric key and re-wrap it under MY account_key.
    let org_sym_key_bytes = STANDARD_NO_PAD
        .decode(org_sym_key_b64)
        .context("decode org_sym_key")?;
    if org_sym_key_bytes.len() != 32 {
        return Err(anyhow!("org_sym_key has wrong length"));
    }
    let protected_org_key = EncString::encrypt_xc20p(
        "ak:1",
        &unlocked.account_key,
        &org_sym_key_bytes,
        AAD_PROTECTED_ACCOUNT_KEY,
    )
    .map_err(|e| anyhow!("wrap org sym key: {e}"))?
    .to_wire();

    api.accept_org(
        org_id,
        &AcceptOrgRequest {
            protected_org_key,
            org_sym_key_id,
        },
    )?;

    // TOFU-pin the org's signing pubkey.
    let fingerprint = format!(
        "SHA256:{}",
        STANDARD_NO_PAD.encode(Sha256::digest(&bundle_canonical))
    );
    state.org_pins.insert(
        org_id.to_string(),
        OrgPin {
            org_id: org_id.to_string(),
            signing_pubkey_b64: org_signing_pk_b64.to_string(),
            fingerprint: fingerprint.clone(),
            first_seen_at: chrono::Utc::now().to_rfc3339(),
            // Seed the M4.2 forward-progress cache from the roster we
            // just verified. The next /sync's roster_version must be
            // >= roster.version, and parent_canonical_sha256 must
            // chain to SHA256 of these canonical bytes.
            last_roster_version: roster.version as i64,
            last_roster_canonical_b64: invite.roster.canonical_b64.clone(),
        },
    );
    crate::state::save(&state)?;
    persist_refreshed_tokens(&api, state)?;
    println!("✓ Joined org \"{org_name}\" as {claimed_role}.");
    println!("  org signing pubkey pinned: {fingerprint}");
    Ok(())
}

fn cancel_invite(org_id: &str, peer_user_id: &str) -> Result<()> {
    let (state, api, unlocked) = unlock_session()?;
    let org = api.get_org(org_id).context("fetch org")?;
    if org.owner_user_id != state.user.user_id {
        return Err(anyhow!("only the org owner can cancel invites"));
    }
    let protected_signing_seed = org
        .owner_protected_signing_seed
        .as_deref()
        .ok_or_else(|| anyhow!("server omitted owner_protected_signing_seed"))?;
    let org_signing_seed = unwrap_under_account_key(
        &unlocked.account_key,
        protected_signing_seed,
        b"pmgr-org-signing-seed",
        "org signing seed",
    )?;
    let org_signing_key = SigningKey::from_bytes(&org_signing_seed);

    let current = parse_current_roster(&org)?;
    let next_entries: Vec<OrgRosterEntry> = current
        .entries
        .iter()
        .filter(|e| e.user_id != peer_user_id)
        .cloned()
        .collect();
    if next_entries.len() == current.entries.len() {
        return Err(anyhow!("{peer_user_id} is not in the current roster"));
    }
    let cur_canonical = STANDARD_NO_PAD
        .decode(&org.roster.canonical_b64)
        .context("decode current canonical")?;
    let next = OrgRoster {
        org_id: org.id.clone(),
        version: current.version + 1,
        parent_canonical_sha256: hash_canonical(&cur_canonical),
        timestamp: chrono::Utc::now().to_rfc3339(),
        entries: next_entries,
        org_sym_key_id: org.org_sym_key_id.clone(),
    };
    let signed_next = next.sign(&org_signing_key);

    api.cancel_invite(
        org_id,
        peer_user_id,
        &CancelInviteRequest {
            next_roster: SignedOrgRosterWire {
                canonical_b64: signed_next.canonical_b64,
                signature_b64: signed_next.signature_b64,
            },
        },
    )?;
    persist_refreshed_tokens(&api, state)?;
    println!("✓ Cancelled invitation for {peer_user_id}.");
    Ok(())
}

// ===========================================================================
// M4.5b — remove member + org-key rotation
// ===========================================================================

fn remove_member(org_id: &str, target_user_id: &str) -> Result<()> {
    use crate::api::{CipherRewrap, CollectionRewrap, RevokeMemberRequest, RewrapEnvelope};

    let (state, api, unlocked) = unlock_session()?;
    if state.user.user_id.is_empty() {
        return Err(anyhow!(
            "local state has no user_id — re-run `hekate login` to refresh."
        ));
    }
    if target_user_id == state.user.user_id {
        return Err(anyhow!(
            "the owner cannot revoke themselves; transfer ownership first \
             (M4 v2)"
        ));
    }

    let org = api.get_org(org_id).context("fetch org")?;
    if org.owner_user_id != state.user.user_id {
        return Err(anyhow!(
            "only the org owner can remove members (single-signer model in M4 v1)"
        ));
    }
    let protected_signing_seed = org
        .owner_protected_signing_seed
        .as_deref()
        .ok_or_else(|| anyhow!("server omitted owner_protected_signing_seed"))?;

    // 1. Unwrap the org signing seed and the OLD org sym key.
    let org_signing_seed = unwrap_under_account_key(
        &unlocked.account_key,
        protected_signing_seed,
        b"pmgr-org-signing-seed",
        "org signing seed",
    )?;
    let org_signing_key = SigningKey::from_bytes(&org_signing_seed);
    let old_org_sym_key = unwrap_under_account_key(
        &unlocked.account_key,
        &org.my_protected_org_key,
        AAD_PROTECTED_ACCOUNT_KEY,
        "old org symmetric key",
    )?;

    // 2. Parse the current roster + confirm the target is in it.
    let current = parse_current_roster(&org)?;
    if !current.entries.iter().any(|e| e.user_id == target_user_id) {
        return Err(anyhow!(
            "{target_user_id} is not in the current roster — nothing to revoke"
        ));
    }
    if current
        .entries
        .iter()
        .find(|e| e.user_id == target_user_id)
        .map(|e| e.role.as_str())
        == Some("owner")
    {
        return Err(anyhow!("cannot revoke the org owner"));
    }

    // 3. Generate the NEW org sym key + new key_id.
    let new_org_sym_key = random_key_32();
    let new_org_sym_key_id = Uuid::now_v7().to_string();

    // 4. Build + sign the next roster (drop the revoked member, bump
    //    version, chain parent hash, swap key_id).
    let next_entries: Vec<OrgRosterEntry> = current
        .entries
        .iter()
        .filter(|e| e.user_id != target_user_id)
        .cloned()
        .collect();
    let cur_canonical = STANDARD_NO_PAD
        .decode(&org.roster.canonical_b64)
        .context("decode current canonical")?;
    let next = OrgRoster {
        org_id: org.id.clone(),
        version: current.version + 1,
        parent_canonical_sha256: hash_canonical(&cur_canonical),
        timestamp: chrono::Utc::now().to_rfc3339(),
        entries: next_entries.clone(),
        org_sym_key_id: new_org_sym_key_id.clone(),
    };
    let signed_next = next.sign(&org_signing_key);

    // 5. Owner's new EncString of the new sym key (under account_key).
    let owner_protected_org_key = EncString::encrypt_xc20p(
        "ak:1",
        &unlocked.account_key,
        &new_org_sym_key[..],
        AAD_PROTECTED_ACCOUNT_KEY,
    )
    .map_err(|e| anyhow!("wrap new org sym key: {e}"))?
    .to_wire();

    // 6. Signcrypt the new sym key for every remaining non-owner.
    //    Each must be TOFU-pinned; if not, fail loudly so the owner
    //    can verify out of band.
    let owner_signing_key = signing_key_from_seed(&unlocked.signing_seed);
    let mut rewrap_envelopes: Vec<RewrapEnvelope> = Vec::new();
    for entry in &next_entries {
        if entry.user_id == state.user.user_id {
            continue; // owner uses owner_protected_org_key
        }
        let pin = state.peer_pins.get(&entry.user_id).ok_or_else(|| {
            anyhow!(
                "remaining member {} is not pinned — run `hekate peer fetch {}` \
                 and verify the fingerprint out of band before rotating, or \
                 they cannot be re-wrapped to.",
                entry.user_id,
                entry.user_id,
            )
        })?;

        // Verify the live directory bundle still matches the pin.
        // Refusing the rotation if the server has diverged from our
        // pin keeps a malicious server from substituting a key under
        // the rotation flow.
        let live = api
            .get_pubkeys(&entry.user_id)
            .with_context(|| format!("fetch pubkeys for {}", entry.user_id))?;
        if live.account_signing_pubkey != pin.account_signing_pubkey_b64
            || live.account_public_key != pin.account_public_key_b64
            || live.account_pubkey_bundle_sig != pin.account_pubkey_bundle_sig_b64
        {
            return Err(anyhow!(
                "server-returned pubkey bundle for {} does not match TOFU pin \
                 — refusing to wrap the new org key. Investigate before \
                 retrying.",
                entry.user_id,
            ));
        }
        let peer_x25519_pk = decode_pubkey(&pin.account_public_key_b64, "peer x25519")?;

        let payload = serde_json::json!({
            "kind": "pmgr-org-key-rotation-v1",
            "org_id": org.id,
            "org_sym_key_id": new_org_sym_key_id,
            "org_sym_key_b64": STANDARD_NO_PAD.encode(&new_org_sym_key[..]),
        });
        let envelope = signcrypt::sign_encrypt(
            &owner_signing_key,
            &state.user.user_id,
            &entry.user_id,
            &peer_x25519_pk,
            payload.to_string().as_bytes(),
        )
        .map_err(|e| anyhow!("signcrypt for {}: {e}", entry.user_id))?;
        rewrap_envelopes.push(RewrapEnvelope {
            user_id: entry.user_id.clone(),
            envelope: serde_json::to_value(&envelope)?,
        });
    }

    // 7. Re-wrap every org-owned cipher under the new sym key.
    //    Pull the full cipher list via /sync (the owner sees every
    //    org-owned cipher, including soft-deleted ones, since the
    //    server query doesn't filter on deleted_date).
    let sync = api.sync(None).context("sync to enumerate org ciphers")?;
    let mut cipher_rewraps: Vec<CipherRewrap> = Vec::new();
    for c in &sync.changes.ciphers {
        if c.org_id.as_deref() != Some(org_id) {
            continue;
        }
        // Re-wrap the *existing* per-cipher key under the new org sym
        // key. Don't generate a new per-cipher key — that would
        // require re-encrypting every field. AAD on the wrap binds
        // cipher_id, so the (cipher_id, key_id) layout stays valid.
        let cipher_key_bytes = crate::crypto::unwrap_cipher_key_under(
            &old_org_sym_key,
            &c.protected_cipher_key,
            &c.id,
        )
        .with_context(|| format!("unwrap cipher key for {}", c.id))?;
        let aad = crate::crypto::aad_protected_cipher_key(&c.id);
        let new_protected =
            EncString::encrypt_xc20p("ok:1", &new_org_sym_key, &cipher_key_bytes[..], &aad)
                .map_err(|e| anyhow!("wrap cipher key for {}: {e}", c.id))?
                .to_wire();
        cipher_rewraps.push(CipherRewrap {
            cipher_id: c.id.clone(),
            protected_cipher_key: new_protected,
        });
    }

    // 7b. Re-encrypt every collection name under the new sym key.
    //     Same 1:1 enumeration contract as cipher_rewraps; without it
    //     the server (correctly) rejects the revoke. Collection names
    //     use collection_name_aad(id, org_id) which is independent of
    //     the sym key, so we decrypt under old + re-encrypt under new
    //     with the same AAD.
    let collections = api
        .list_collections(org_id)
        .context("list collections for rotation")?;
    let mut collection_rewraps: Vec<CollectionRewrap> = Vec::new();
    for c in &collections {
        let aad = hekate_core::org_roster::collection_name_aad(&c.id, &c.org_id);
        let parsed = EncString::parse(&c.name)
            .with_context(|| format!("parse collection name encstring for {}", c.id))?;
        let name_bytes = parsed
            .decrypt_xc20p(&old_org_sym_key, Some(&aad))
            .map_err(|e| {
                anyhow!(
                    "failed to decrypt collection {} name under the old org sym key: {e}",
                    c.id
                )
            })?;
        let new_name = EncString::encrypt_xc20p("ok:1", &new_org_sym_key, &name_bytes, &aad)
            .map_err(|e| anyhow!("re-encrypt collection name for {}: {e}", c.id))?
            .to_wire();
        collection_rewraps.push(CollectionRewrap {
            collection_id: c.id.clone(),
            name: new_name,
        });
    }

    // 8. POST.
    api.revoke_member(
        org_id,
        target_user_id,
        &RevokeMemberRequest {
            next_roster: SignedOrgRosterWire {
                canonical_b64: signed_next.canonical_b64,
                signature_b64: signed_next.signature_b64,
            },
            next_org_sym_key_id: new_org_sym_key_id.clone(),
            owner_protected_org_key,
            rewrap_envelopes,
            cipher_rewraps,
            collection_rewraps,
        },
    )?;
    println!(
        "✓ Removed {target_user_id} from \"{}\". Rotated org sym key.",
        org.name
    );
    println!("  Roster bumped to v{}.", current.version + 1);
    println!("  New org_sym_key_id: {new_org_sym_key_id}");
    // Every org-owned cipher's revision_date just bumped server-side.
    // Refresh the per-org signed cipher manifest (M2.21) so member
    // /sync continues to verify cleanly post-rotation.
    if let Err(e) = crate::org_cipher_manifest::maybe_refresh_owner(&api, &unlocked, org_id) {
        eprintln!("warning: org cipher manifest refresh failed: {e}");
    }
    persist_refreshed_tokens(&api, state)?;
    Ok(())
}

// ---------------- helpers --------------------------------------------------

fn parse_current_roster(org: &OrgView) -> Result<OrgRoster> {
    let canonical = STANDARD_NO_PAD
        .decode(&org.roster.canonical_b64)
        .context("decode current canonical")?;
    decode_roster_canonical(&canonical).map_err(|e| anyhow!("decode roster: {e}"))
}

pub(crate) fn unwrap_under_account_key(
    account_key: &[u8; 32],
    wire: &str,
    aad: &[u8],
    label: &str,
) -> Result<[u8; 32]> {
    let s = EncString::parse(wire).with_context(|| format!("parse {label}"))?;
    let bytes = s
        .decrypt_xc20p(account_key, Some(aad))
        .map_err(|e| anyhow!("decrypt {label}: {e}"))?;
    if bytes.len() != 32 {
        return Err(anyhow!("{label} has wrong length"));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn decrypt_x25519_priv(account_key: &[u8; 32], wire: &str) -> Result<[u8; 32]> {
    unwrap_under_account_key(
        account_key,
        wire,
        b"pmgr-account-x25519-priv",
        "x25519 priv",
    )
}

fn decode_pubkey(b64: &str, label: &str) -> Result<[u8; 32]> {
    let bytes = STANDARD_NO_PAD
        .decode(b64)
        .with_context(|| format!("{label} not base64-no-pad"))?;
    if bytes.len() != 32 {
        return Err(anyhow!("{label} has wrong length"));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

// ===========================================================================
// M4.3 — collections (encrypted names under the org sym key)
// ===========================================================================

/// Fetch the caller's view of an org and unwrap the org symmetric
/// key under their account_key. Returns the org metadata + the
/// unwrapped 32-byte org sym key. Used by collection commands and
/// by the org-cipher creation path in `hekate add`.
pub(crate) fn fetch_org_and_unwrap(
    api: &Api,
    unlocked: &Unlocked,
    org_id: &str,
) -> Result<(OrgView, Zeroizing<[u8; 32]>)> {
    let org = api.get_org(org_id).context("fetch org")?;
    let unwrapped = unwrap_under_account_key(
        &unlocked.account_key,
        &org.my_protected_org_key,
        AAD_PROTECTED_ACCOUNT_KEY,
        "org symmetric key",
    )?;
    let mut k = Zeroizing::new([0u8; 32]);
    k.copy_from_slice(&unwrapped);
    Ok((org, k))
}

fn create_collection(org_id: &str, plaintext_name: &str) -> Result<()> {
    let trimmed = plaintext_name.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("--name must not be empty"));
    }
    let (state, api, unlocked) = unlock_session()?;
    let (_org, org_sym_key) = fetch_org_and_unwrap(&api, &unlocked, org_id)?;

    let collection_id = Uuid::now_v7().to_string();
    // AAD binds the encrypted name to (collection_id, org_id) so the
    // server cannot move a name across collections or orgs.
    let aad = collection_name_aad(&collection_id, org_id);
    let name_wire = EncString::encrypt_xc20p("ok:1", &org_sym_key, trimmed.as_bytes(), &aad)
        .map_err(|e| anyhow!("encrypt collection name: {e}"))?
        .to_wire();

    let view = api
        .create_collection(
            org_id,
            &CreateCollectionRequest {
                id: collection_id,
                name: name_wire,
            },
        )
        .context("create collection")?;
    persist_refreshed_tokens(&api, state)?;
    println!("✓ Created collection \"{}\" ({})", trimmed, view.id);
    Ok(())
}

fn list_collections(org_id: &str) -> Result<()> {
    let (state, api, unlocked) = unlock_session()?;
    let (_org, org_sym_key) = fetch_org_and_unwrap(&api, &unlocked, org_id)?;
    let collections = api.list_collections(org_id).context("list collections")?;
    if collections.is_empty() {
        println!("(no collections)");
        return Ok(());
    }
    println!("{:<40}  NAME", "ID");
    for c in &collections {
        let name = decrypt_collection_name(&c.id, &c.org_id, &c.name, &org_sym_key)
            .unwrap_or_else(|e| format!("<decrypt failed: {e}>"));
        println!("{:<40}  {}", c.id, name);
    }
    persist_refreshed_tokens(&api, state)?;
    Ok(())
}

fn delete_collection(org_id: &str, collection_id: &str) -> Result<()> {
    let (state, api, _unlocked) = unlock_session()?;
    api.delete_collection(org_id, collection_id)
        .context("delete collection")?;
    persist_refreshed_tokens(&api, state)?;
    println!("✓ Deleted collection {collection_id}");
    Ok(())
}

fn grant_permission(
    org_id: &str,
    collection_id: &str,
    user_id: &str,
    permission: &str,
) -> Result<()> {
    if !matches!(permission, "manage" | "read" | "read_hide_passwords") {
        return Err(anyhow!(
            "--permission must be one of: manage, read, read_hide_passwords"
        ));
    }
    let (state, api, _unlocked) = unlock_session()?;
    let view = api
        .grant_permission(org_id, collection_id, user_id, permission)
        .context("grant permission")?;
    persist_refreshed_tokens(&api, state)?;
    println!(
        "✓ Granted {} to {} on collection {}",
        view.permission, view.user_id, collection_id
    );
    Ok(())
}

fn revoke_permission(org_id: &str, collection_id: &str, user_id: &str) -> Result<()> {
    let (state, api, _unlocked) = unlock_session()?;
    api.revoke_permission(org_id, collection_id, user_id)
        .context("revoke permission")?;
    persist_refreshed_tokens(&api, state)?;
    println!("✓ Revoked {user_id} on collection {collection_id}");
    Ok(())
}

fn list_collection_members(org_id: &str, collection_id: &str) -> Result<()> {
    let (state, api, _unlocked) = unlock_session()?;
    let members = api
        .list_collection_members(org_id, collection_id)
        .context("list collection members")?;
    if members.is_empty() {
        println!("(no members)");
        return Ok(());
    }
    println!("{:<40}  PERMISSION", "USER");
    for m in &members {
        println!("{:<40}  {}", m.user_id, m.permission);
    }
    persist_refreshed_tokens(&api, state)?;
    Ok(())
}

/// Thin alias over the canonical `hekate-core::org_roster::
/// collection_name_aad` so existing call-sites in this file keep
/// their short name. Single source of truth lives in hekate-core.
pub(crate) fn collection_name_aad(collection_id: &str, org_id: &str) -> Vec<u8> {
    hekate_core::org_roster::collection_name_aad(collection_id, org_id)
}

pub(crate) fn decrypt_collection_name(
    collection_id: &str,
    org_id: &str,
    wire: &str,
    org_sym_key: &[u8; 32],
) -> Result<String> {
    let s = EncString::parse(wire).context("malformed collection name")?;
    let aad = collection_name_aad(collection_id, org_id);
    let bytes = s
        .decrypt_xc20p(org_sym_key, Some(&aad))
        .map_err(|e| anyhow!("decrypt: {e}"))?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

// ===========================================================================
// M4.6 — policies
// ===========================================================================

const POLICY_TYPES: &[&str] = &[
    "master_password_complexity",
    "vault_timeout",
    "password_generator_rules",
    "single_org",
    "restrict_send",
];

fn set_policy(org_id: &str, policy_type: &str, enabled: bool, config_json: &str) -> Result<()> {
    use crate::api::SetPolicyRequest;

    if !POLICY_TYPES.contains(&policy_type) {
        return Err(anyhow!(
            "unknown policy_type {policy_type:?}; supported: {}",
            POLICY_TYPES.join(", ")
        ));
    }
    let config: serde_json::Value = serde_json::from_str(config_json)
        .with_context(|| format!("--config is not valid JSON: {config_json}"))?;
    if !config.is_object() {
        return Err(anyhow!("--config must be a JSON object"));
    }
    let (state, api, _unlocked) = unlock_session()?;
    let view = api
        .set_policy(
            org_id,
            policy_type,
            &SetPolicyRequest {
                enabled,
                config: config.clone(),
            },
        )
        .context("set policy")?;
    persist_refreshed_tokens(&api, state)?;
    println!(
        "✓ Set policy {} (enabled={}) on {org_id}",
        view.policy_type, view.enabled
    );
    println!("  config: {}", view.config);
    Ok(())
}

fn get_policy(org_id: &str, policy_type: &str) -> Result<()> {
    let st = crate::state::load()?.ok_or_else(|| anyhow!("not logged in"))?;
    let api = Api::new(&st.server_url)?
        .with_bearer(st.tokens.access_token.clone())
        .with_refresh(st.tokens.refresh_token.clone());
    let policies = api.list_policies(org_id).context("list policies")?;
    let p = policies
        .into_iter()
        .find(|p| p.policy_type == policy_type)
        .ok_or_else(|| anyhow!("policy {policy_type} is not set on this org"))?;
    println!("type:       {}", p.policy_type);
    println!("enabled:    {}", p.enabled);
    println!("config:     {}", p.config);
    println!("updated_at: {}", p.updated_at);
    persist_refreshed_tokens(&api, st)?;
    Ok(())
}

fn list_policies(org_id: &str) -> Result<()> {
    let st = crate::state::load()?.ok_or_else(|| anyhow!("not logged in"))?;
    let api = Api::new(&st.server_url)?
        .with_bearer(st.tokens.access_token.clone())
        .with_refresh(st.tokens.refresh_token.clone());
    let policies = api.list_policies(org_id).context("list policies")?;
    if policies.is_empty() {
        println!("(no policies)");
        return Ok(());
    }
    println!("{:<32}  {:<8}  CONFIG", "TYPE", "ENABLED");
    for p in &policies {
        println!(
            "{:<32}  {:<8}  {}",
            p.policy_type,
            if p.enabled { "yes" } else { "no" },
            p.config,
        );
    }
    persist_refreshed_tokens(&api, st)?;
    Ok(())
}

fn unset_policy(org_id: &str, policy_type: &str) -> Result<()> {
    if !POLICY_TYPES.contains(&policy_type) {
        return Err(anyhow!(
            "unknown policy_type {policy_type:?}; supported: {}",
            POLICY_TYPES.join(", ")
        ));
    }
    let (state, api, _unlocked) = unlock_session()?;
    api.delete_policy(org_id, policy_type)
        .context("delete policy")?;
    persist_refreshed_tokens(&api, state)?;
    println!("✓ Unset policy {policy_type} on {org_id}");
    Ok(())
}

// ===========================================================================
// M2.21 / M4.5 follow-up — per-org signed cipher manifest
// ===========================================================================

fn refresh_cipher_manifest(org_id: &str) -> Result<()> {
    let (state, api, unlocked) = unlock_session()?;
    crate::org_cipher_manifest::refresh_explicit(&api, &unlocked, org_id)?;
    persist_refreshed_tokens(&api, state)?;
    println!("✓ Refreshed signed cipher manifest for {org_id}");
    Ok(())
}

// ---- service accounts (M2.5) ------------------------------------------

fn org_api() -> Result<(state::State, Api)> {
    let st = state::load()?.ok_or_else(|| anyhow!("not logged in. Run `hekate login` first."))?;
    let api = Api::new(&st.server_url)?
        .with_bearer(st.tokens.access_token.clone())
        .with_refresh(st.tokens.refresh_token.clone());
    Ok((st, api))
}

fn create_service_account(org_id: &str, name: &str) -> Result<()> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("--name must not be empty"));
    }
    let (st, api) = org_api()?;
    let sa = api.create_service_account(org_id, trimmed)?;
    persist_refreshed_tokens(&api, st)?;
    println!("✓ Created service account {} ({})", sa.name, sa.id);
    println!("  Issue tokens with:");
    println!(
        "    hekate org service-account token create {} {} --name <label>",
        org_id, sa.id
    );
    Ok(())
}

fn list_service_accounts(org_id: &str) -> Result<()> {
    let (st, api) = org_api()?;
    let rows = api.list_service_accounts(org_id)?;
    persist_refreshed_tokens(&api, st)?;
    if rows.is_empty() {
        println!("(no service accounts in this org)");
        return Ok(());
    }
    for sa in rows {
        let status = if sa.disabled_at.is_some() {
            "disabled"
        } else {
            "active"
        };
        println!(
            "{}  {}  [{}]  created {}",
            sa.id, sa.name, status, sa.created_at
        );
    }
    Ok(())
}

fn disable_service_account(org_id: &str, sa_id: &str) -> Result<()> {
    let (st, api) = org_api()?;
    api.disable_service_account(org_id, sa_id)?;
    persist_refreshed_tokens(&api, st)?;
    println!("✓ Disabled. All existing and future tokens are now invalid.");
    Ok(())
}

fn delete_service_account(org_id: &str, sa_id: &str, yes: bool) -> Result<()> {
    if !yes {
        eprint!(
            "PERMANENTLY delete service account {sa_id} and all its tokens? \
             Type 'yes' to confirm: "
        );
        std::io::Write::flush(&mut std::io::stderr())?;
        let mut typed = String::new();
        std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut typed)?;
        if typed.trim() != "yes" {
            return Err(anyhow!("aborted"));
        }
    }
    let (st, api) = org_api()?;
    api.delete_service_account(org_id, sa_id)?;
    persist_refreshed_tokens(&api, st)?;
    println!("✓ Deleted.");
    Ok(())
}

fn create_sa_token(
    org_id: &str,
    sa_id: &str,
    name: &str,
    scopes: &str,
    expires_in_days: Option<i64>,
) -> Result<()> {
    let (st, api) = org_api()?;
    let resp = api.create_sa_token(org_id, sa_id, name.trim(), scopes, expires_in_days)?;
    persist_refreshed_tokens(&api, st)?;
    println!();
    println!("================================================================");
    println!(" Service-account token created. SHOWN ONCE — store it now.");
    println!("================================================================");
    println!("  Name:    {}", resp.name);
    println!("  Scopes:  {}", resp.scopes);
    if let Some(exp) = &resp.expires_at {
        println!("  Expires: {}", exp);
    } else {
        println!("  Expires: never");
    }
    println!();
    println!("  Token:   {}", resp.token);
    println!();
    println!("  Use as: Authorization: Bearer {}", resp.token);
    println!("================================================================");
    Ok(())
}

fn list_sa_tokens(org_id: &str, sa_id: &str) -> Result<()> {
    let (st, api) = org_api()?;
    let rows = api.list_sa_tokens(org_id, sa_id)?;
    persist_refreshed_tokens(&api, st)?;
    if rows.is_empty() {
        println!("(no tokens issued for this service account)");
        return Ok(());
    }
    for t in rows {
        let status = if t.revoked_at.is_some() {
            "revoked"
        } else {
            "active"
        };
        let expires = t.expires_at.unwrap_or_else(|| "never".to_string());
        let last = t.last_used_at.unwrap_or_else(|| "—".to_string());
        println!(
            "{}  {}  [{}]  scopes={}  expires={}  last_used={}",
            t.id, t.name, status, t.scopes, expires, last
        );
    }
    Ok(())
}

fn revoke_sa_token(org_id: &str, sa_id: &str, token_id: &str) -> Result<()> {
    let (st, api) = org_api()?;
    api.revoke_sa_token(org_id, sa_id, token_id)?;
    persist_refreshed_tokens(&api, st)?;
    println!("✓ Revoked.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bundle canonical bytes the CLI signs MUST match exactly what
    /// the server validates. Drift here would silently fail to verify
    /// on create.
    #[test]
    fn bundle_canonical_layout_is_stable() {
        let signing_pk = [0xa5u8; 32];
        let bytes = bundle_canonical_bytes(
            "0192e0a0-0000-7000-8000-000000000001",
            "ACME",
            &signing_pk,
            "0192e0a0-0000-7000-8000-aaaaaaaaaaaa",
        );
        assert!(bytes.starts_with(b"pmgr-org-bundle-v1\x00"));
        let after_dst = &bytes[b"pmgr-org-bundle-v1\x00".len()..];
        assert_eq!(&after_dst[..4], &36u32.to_le_bytes());
    }
}
