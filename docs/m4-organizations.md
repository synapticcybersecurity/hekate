# M4 — Organizations, sharing, collections

**Status**: design / planning. None of this is implemented.
**Prereqs (all shipped):** M2.18 signcryption envelope · M2.19 self-signed
pubkey bundle · M2.20 TOFU pubkey pinning. The cryptographic trust path
for sharing is now complete; M4 is the *consumer* of that work.

---

## 1. Why this needs a design doc

M4 is the biggest single track on the roadmap. Bitwarden took multiple
years building it, ships it across 4 surfaces (web vault, browser ext,
desktop, mobile), and its enterprise tier (SSO/SCIM/Provider Portal)
piles on top of M4's foundation. Even an MVP is **6–10 sessions of
work**.

More importantly: M4 introduces the first feature Hekate has where the
*correctness of the cryptographic model* is non-obvious. Personal-vault
crypto is "encrypt to yourself"; sharing is "encrypt to *them* and
prove it". The hardest question — **how does a client verify that
"Bob is in my org" without trusting the server's bare assertion** —
is BW08 from Scarlata et al. (USENIX Security 2026), and it is the
attack Hekate has been building toward defending against from M0.

This doc settles BW08, sketches the schema, defines the wire formats,
and breaks the implementation into bounded milestones with concrete
acceptance criteria each.

---

## 2. Threat model — what M4 must defend against

### 2.1 BW08 — organisation injection

**Attack:** Server tells Alice "your org has members Alice, Bob,
Mallory". Alice trusts the assertion, encrypts the next shared key
to Mallory's pubkey, server walks away with plaintext.

**Defense (this doc):** *Every org membership claim is signed by the
org's own Ed25519 signing key.* Members fetch a signed roster on every
sync; mismatch against the local TOFU-pinned org signing pubkey → loud
error, no shared secret derived.

### 2.2 BW09 / LP07 / DL02 — recipient-pubkey substitution

Already mitigated end-to-end by **M2.18 + M2.19 + M2.20**. Every
sharing wrap in M4 is a `signcrypt::sign_encrypt` envelope to a TOFU-
pinned recipient pubkey. **No raw `x25519_sealed_box` ever appears
in the M4 wire protocol.**

### 2.3 Insider-abuse — removed member retains access

**Attack:** Alice removes Bob from the org but never rotates the org
symmetric key. Bob's local copy still works; he can decrypt anything
he had access to.

**Defense:** "Remove member" triggers a **mandatory org-key rotation**:
generate a fresh org symmetric key, re-wrap to every remaining member
(via signcryption), bump roster version, sign. Old org-owned ciphers
re-encrypted in the background. Bob's old wrap is now useless against
new ciphers. He still holds plaintext for whatever he saw before
removal — that's a fundamental cryptographic limit, no design fixes
it.

### 2.4 Server-controlled metadata

Cipher rows in an org context carry `org_id` and a list of
`collection_id`s. These are server-controlled. Per BW04's lesson, we
must not trust any of them at face value. Defense:

- **`org_id`** binds into the cipher's AAD (already done in M2.13's
  AAD v2: `pmgr-cipher-data-v2:<id>:<type>`). M4 extends the AAD
  to include `<org_id>` so a server can't move a cipher between
  orgs by rewriting the column.
- **Collection assignment** is signed as part of the cipher's
  collection-membership claim, parallel to the org roster pattern.

---

## 3. The "single-signer" trust model (M4 v1)

For M4 v1, **each org has exactly one signing key**, held by the org
owner. Other admins help with day-to-day ops (UI), but only the owner
can issue / revoke memberships and rotate keys.

**Why single-signer in v1:**
- Simplest cryptographic model. One signing key = one trust root per
  org. Members TOFU-pin it on accept.
- Avoids the multi-admin signing-quorum-or-CA design, which is real
  work and not needed for the personal-team usage pattern Hekate
  initially targets.
- Upgrade path is clean (see §11).

**Where the owner's signing private key lives:**
- Generated client-side at `hekate org create`, never seen by the server.
- Wrapped under the owner's `account_key` (the same key that wraps
  per-cipher keys today) and stored as an EncString in the
  `organization_owner_keys` table. Server can't decrypt.
- Owner unlocks → derives account_key → unwraps signing seed. Same
  pattern as everything else.

**What other admins can do without signing:**
- Read all collections (with `manage` permission)
- Add ciphers to collections
- Move ciphers between collections
- Cannot invite, remove, or rotate keys — those require the owner

**Multi-admin in v2:** see §11. The schema is forward-compatible
(roster sigs become a list of sigs from any active admin).

---

## 4. BW08 mitigation: the signed org roster

Modeled exactly on the M2.15a/c **signed vault manifest**. Same DST
pattern, same canonical-bytes layout, same parent-hash chain across
versions, same "verify on every sync" client logic.

### 4.1 Canonical bytes (what the owner signs)

```text
DST            := "pmgr-org-roster-v1\x00"
canonical      := DST
               || u64(version)
               || [32 bytes parent_canonical_sha256]    // zeros for genesis
               || u32(org_id.len)         || org_id_bytes
               || u32(timestamp.len)      || timestamp_bytes
               || u32(entries.len)
               || entry × N
               || u32(org_sym_key_id.len) || org_sym_key_id_bytes
entry          := u32(user_id.len) || user_id
               || u32(role.len)    || role           // "owner" | "admin" | "user"
```

### 4.2 Wire form (`SignedRoster`)

```json
{
  "org_id": "<uuid>",
  "version": 7,
  "canonical_b64": "<base64>",
  "signature_b64": "<base64>",   // Ed25519 by the org's signing key
  "updated_at": "<rfc3339>"
}
```

### 4.3 Why a roster (not per-membership signatures)

Symmetric to the vault-manifest design (M2.15) and for the same reason:
the *set* matters. A per-membership sig protects each member's row
from substitution but says nothing about the *list*. A signed roster
covers both: any change to membership → version bumps, parent-hash
chains forward, server can't fork the list silently.

### 4.4 `org_sym_key_id`

Bumps every time the owner rotates the org symmetric key (e.g. after
removing a member). Members observe the new key_id, fetch their fresh
`protected_org_key`, and re-derive. Old `protected_org_key` rows
referencing the previous key_id become invalid; ciphers under the
previous key are re-encrypted in the background.

### 4.5 Genesis verification

When a user accepts an org invite, the invite envelope (signcryption
from the owner — see §6) carries the org's signing pubkey. The
invitee verifies the envelope under the owner's signing pubkey
(already TOFU-pinned via `hekate peer fetch <owner_id>`), then **TOFU-
pins the org's signing pubkey** keyed by `org_id`. Subsequent roster
verifications use this pin, not the value the server hands back.

---

## 5. Schema

Migration `0012_organizations.sql`:

```sql
-- Top-level org row. Plaintext fields (name, signing_pubkey, owner_user_id)
-- are non-secret; the only secrets are wrapped under owner_keys and
-- protected_org_key per-member.
CREATE TABLE organizations (
    id TEXT PRIMARY KEY,                   -- UUIDv7, client-supplied
    name TEXT NOT NULL,                    -- plaintext, for display
    signing_pubkey_b64 TEXT NOT NULL,      -- 32-byte Ed25519
    bundle_sig_b64 TEXT NOT NULL,          -- owner Ed25519-signs (org_id, name, signing_pubkey, owner_user_id)
    owner_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_sym_key_id TEXT NOT NULL,          -- bumps each rotation; bound into roster sig
    -- BW08 signed roster (latest version). Parent-hash chain enforced
    -- exactly like the vault manifest in M2.15c.
    roster_version BIGINT NOT NULL DEFAULT 0,
    roster_canonical_b64 TEXT NOT NULL DEFAULT '',
    roster_signature_b64 TEXT NOT NULL DEFAULT '',
    roster_updated_at TEXT NOT NULL DEFAULT (CURRENT_TIMESTAMP),
    created_at TEXT NOT NULL,
    revision_date TEXT NOT NULL
);

-- Owner's wrapped copy of the org SIGNING private seed. Only the owner
-- has this. Decrypted under the owner's account_key; never seen plaintext
-- by the server.
CREATE TABLE organization_owner_keys (
    org_id TEXT PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    protected_signing_seed TEXT NOT NULL   -- EncString v3 under account_key
);

-- Pending invites — set at invite time, deleted at accept (or revoke).
CREATE TABLE organization_invites (
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    invitee_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- SealedEnvelope JSON (M2.18). Carries the org symmetric key + role +
    -- org signing pubkey. Verified+decrypted by the invitee on accept.
    envelope_json TEXT NOT NULL,
    invited_role TEXT NOT NULL,            -- "admin" | "user" (owner can't re-invite themselves)
    invited_at TEXT NOT NULL,
    PRIMARY KEY (org_id, invitee_user_id)
);

-- Accepted members. Joined invites become rows here; invites get DELETEd.
CREATE TABLE organization_members (
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL,                    -- "owner" | "admin" | "user"
    -- Org symmetric key wrapped under the member's account_key, NOT a
    -- signcryption envelope: by accept time the member already verified
    -- the envelope and re-wrapped under their own account key for
    -- cheap unwrap on every sync.
    protected_org_key TEXT NOT NULL,       -- EncString v3 under account_key
    -- Which org_sym_key_id this protected_org_key wraps. After a key
    -- rotation, members refetch and replace.
    org_sym_key_id TEXT NOT NULL,
    joined_at TEXT NOT NULL,
    PRIMARY KEY (org_id, user_id)
);

-- Logical groupings within an org.
CREATE TABLE organization_collections (
    id TEXT PRIMARY KEY,                   -- UUIDv7
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name TEXT NOT NULL,                    -- EncString under org symmetric key
    revision_date TEXT NOT NULL,
    creation_date TEXT NOT NULL
);

-- Per-collection per-member permissions.
CREATE TABLE collection_members (
    collection_id TEXT NOT NULL REFERENCES organization_collections(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- "read" | "read_hide_passwords" | "manage"
    permissions TEXT NOT NULL,
    PRIMARY KEY (collection_id, user_id)
);

-- Many-to-many: which org-owned ciphers belong to which collection.
CREATE TABLE cipher_collections (
    cipher_id TEXT NOT NULL REFERENCES ciphers(id) ON DELETE CASCADE,
    collection_id TEXT NOT NULL REFERENCES organization_collections(id) ON DELETE CASCADE,
    PRIMARY KEY (cipher_id, collection_id)
);
```

### 5.1 Cipher-table extension

Already present from earlier milestones: `ciphers.user_id` (NULLABLE)
and `ciphers.org_id` (NULLABLE), with the existing constraint that
exactly one is set. M4 just starts populating `org_id`. The
`protected_cipher_key` is wrapped:

- Personal cipher (`user_id` set): under the user's `account_key`.
  Today's behavior.
- Org cipher (`org_id` set): under the org's symmetric key.

The cipher's AAD must include `org_id` to prevent a server from
moving a cipher between orgs. Migration `0013_cipher_aad_v3.sql`
bumps the AAD format if/when this lands.

---

## 6. Wire flows

### 6.1 Create org (M4.0)

```
POST /api/v1/orgs
{
  "id": "<client-supplied UUIDv7>",
  "name": "ACME",
  "signing_pubkey": "<32B base64>",
  "bundle_sig": "<64B Ed25519 over canonical(org_id, name, signing_pubkey, owner_user_id)>",
  "protected_signing_seed": "<EncString of seed under owner's account_key>",
  "org_sym_key_id": "<UUIDv7>",
  "owner_protected_org_key": "<EncString of fresh org_sym_key under owner's account_key>",
  "roster": {            // genesis roster, version=1, parent=zeros, single entry
    "version": 1,
    "canonical_b64": "...",
    "signature_b64": "...",
    "updated_at": "..."
  }
}
→ 201 { org: {…}, member: {…} }
```

Server validates:
- `id` is a UUID
- `bundle_sig` verifies under the owner's signing pubkey (looked up via
  the M2.19 directory) over canonical bytes
- `roster.signature_b64` verifies under the supplied `signing_pubkey`
- Roster version = 1 and parent = all-zeros (genesis)
- The single entry is `(owner_user_id, "owner")`

### 6.2 Invite a member (M4.1)

```
POST /api/v1/orgs/{org_id}/invites
{
  "invitee_user_id": "<bob>",
  "role": "user",
  "envelope": <SealedEnvelope JSON from signcrypt::sign_encrypt>,
  "next_roster": {       // pre-signed roster v(n+1) including the invitee
    "version": ...,
    "canonical_b64": ...,
    "signature_b64": ...,
    "updated_at": ...
  }
}
→ 201
```

The envelope is `signcrypt::sign_encrypt(owner_signing, owner_id, bob_id, bob_x25519_pk_from_TOFU_pin, payload)` where `payload` is:

```json
{
  "org_id": "<uuid>",
  "org_signing_pubkey_b64": "...",
  "org_bundle_sig_b64": "...",
  "org_sym_key_id": "<uuid>",
  "org_sym_key_b64": "<32B>",
  "role": "user"
}
```

Server validates:
- The envelope's `recipient_id` matches `invitee_user_id`
- The envelope's `sender_id` matches the authenticated owner
- `next_roster.signature_b64` verifies under the org signing pubkey
- `next_roster.version == current.version + 1` and parent matches

The server CANNOT validate the envelope contents (it's encrypted); but
the recipient does, on accept (§6.3). Server stores the envelope
in `organization_invites` and applies the new roster.

### 6.3 Accept an invite (M4.1)

Client side (Bob):

1. `GET /api/v1/account/invites` returns pending invites for Bob.
2. For each, fetch the inviter's pubkey bundle (TOFU-pin if new).
3. `signcrypt::verify_decrypt(envelope, inviter_signing_pk, my_id, my_x25519_priv)`
   → fails loudly if the inviter wasn't the claimed user, or if the
   server tampered.
4. From the decrypted payload:
   - Verify `org_bundle_sig` under `org_signing_pubkey` over canonical
     `(org_id, name, signing_pubkey, owner_user_id)` from the org's
     directory entry.
   - TOFU-pin `(org_id, org_signing_pubkey, fingerprint)` locally.
   - Verify the latest roster signature on `GET /api/v1/orgs/{org_id}` under
     the same pubkey. Confirm Bob is in it with the claimed role.
5. Generate `protected_org_key = EncString(my_account_key, org_sym_key)`
   so subsequent unwraps don't need re-running signcryption.
6. `POST /api/v1/orgs/{org_id}/accept` with `{protected_org_key, org_sym_key_id}`.
7. Server moves the invite row → membership row.

### 6.4 Roster verification on sync (M4.2)

`/api/v1/sync` response gains:

```json
{
  "changes": { … as today … },
  "manifest": { … vault manifest as today … },
  "orgs": [
    {
      "org_id": "...",
      "name": "...",
      "role": "user",
      "org_sym_key_id": "...",
      "roster": { version, canonical_b64, signature_b64, updated_at }
    }
  ]
}
```

Client per-org:
1. Look up the locally-pinned org signing pubkey by `org_id`. If
   missing → error (we never accepted; server is making things up).
2. Verify `roster.signature_b64` over `roster.canonical_b64` under
   the pinned pubkey.
3. Parse the canonical bytes; check `roster_version >= prior_seen`
   and `parent_canonical_sha256 = SHA256(prior_canonical)`.
4. Confirm I'm in the roster with the claimed role.
5. Pin the new roster locally. Cipher decryption proceeds as today.

Mismatch → loud warning identical in shape to the vault-manifest one.

### 6.5 Move cipher into / out of an org (M4.5)

```
POST /api/v1/ciphers/{id}/move-to-org
{
  "org_id": "<uuid>",
  "collection_ids": ["<uuid>", ...],
  "protected_cipher_key": "<EncString under org_sym_key>",
  "name": "<EncString re-encrypted under new cipher_key>",  // optional re-keying
  "data": "<EncString>",
  "notes": "<EncString>",
  "if_match": "<rfc3339>"
}
→ 200 cipher view
```

Server validates the user has `manage` on every target collection and
the cipher's AAD (which now includes `org_id`) parses cleanly.

Reverse direction: `POST /api/v1/ciphers/{id}/move-to-personal` with
`protected_cipher_key` re-wrapped under the user's account key. Removed
from all collections.

### 6.6 Remove a member + key rotation (M4.5)

```
POST /api/v1/orgs/{org_id}/members/{user_id}/revoke
{
  "next_roster": {…},                 // version+=1, member absent
  "next_org_sym_key_id": "<uuid>",
  "rewraps": [                        // owner re-wraps the new org key for everyone remaining
    { "user_id": "owner", "protected_org_key": "<EncString under owner's account_key>", "org_sym_key_id": "<new>" },
    { "user_id": "alice", "envelope": <SealedEnvelope to alice for new org_sym_key> },
    …
  ]
}
→ 200
```

Server enforces:
- `next_roster` valid + chains forward
- `next_org_sym_key_id` differs from current
- `rewraps` covers every member in `next_roster` (no skipped members)

Background job re-encrypts org-owned ciphers under the new
`protected_cipher_key` (wrapped under the new `org_sym_key`). Ciphers
under the old key remain readable by the revoked member only via
plaintext they already decrypted — that's the cryptographic limit
called out in §2.3.

---

## 7. Permissions enforcement (M4.4)

| Permission | Reads cipher? | Edits cipher? | Sees password? | Notes |
|---|---|---|---|---|
| `read` | ✓ | ✗ | ✓ | Server enforces edit denial via 403 on PUT |
| `read_hide_passwords` | ✓ | ✗ | UX hides | Server can't redact (E2EE); client honors hint |
| `manage` | ✓ | ✓ | ✓ | Server allows full CRUD |

Implementation: `/sync` returns each cipher with the requesting
user's effective permission for it (intersection of org membership
+ collection memberships). Server enforces by 403'ing `PUT` /
`DELETE` against the cipher when permission is `read`. Client honors
`read_hide_passwords` by masking the password field in lists and
not exposing it in `Copy`. Same trust model as Bitwarden — a
malicious *client* could ignore the hint, but a malicious *server*
cannot decrypt to peek.

---

## 8. Milestone breakdown

Each milestone is **session-sized** (compatible with the rhythm of
M2.13–M2.20) and gates on the previous one passing all tests + the
`make smoke` extension that covers it.

### M4.0 — Schema + create-org

- Migration `0012_organizations.sql` (the schema in §5)
- Server: `POST /api/v1/orgs`, `GET /api/v1/account/orgs`,
  `GET /api/v1/orgs/{id}` (returns name + roster + my role)
- New hekate-core module `org_roster.rs` mirroring `manifest.rs`:
  canonical bytes, sign, verify, parent-hash chain
- CLI: `hekate org create --name "X"`, `hekate org list`
- Tests: server integration + hekate-core unit
- **Acceptance**: a single user can create an org, the genesis roster
  signs and verifies, `hekate sync` reports the org membership.
- **Estimated**: 1 session.

### M4.1 — Invite + accept (signcryption first consumer)

- Server: `POST /api/v1/orgs/{id}/invites`, `GET /api/v1/account/invites`,
  `POST /api/v1/orgs/{id}/accept`, `DELETE /api/v1/orgs/{id}/invites/{user_id}` (revoke)
- CLI: `hekate org invite <org> <peer_user_id> --role admin|user`,
  `hekate org invites`, `hekate org accept <org_id>`,
  `hekate org cancel-invite <org> <peer_user_id>`
- Reuses M2.18 `signcrypt::sign_encrypt` / `verify_decrypt`. **First
  call sites** for the primitive — proves the trust path works in
  anger.
- TOFU-pin the org signing pubkey on accept (parallel to peer pinning)
- Tests including end-to-end: alice creates org → invites bob → bob
  accepts → roster shows both, signed by org → server-substitution
  attempt rejected
- **Acceptance**: smoke test that simulates a server attempting to
  fabricate a membership entry → client refuses, citing the roster
  sig mismatch (parallel to the BW09 smoke from M2.20).
- **Estimated**: 2 sessions.

### M4.2 — Roster verification on sync

- `/api/v1/sync` response gains `orgs: [{org_id, role, roster}]`
- CLI client: verify every org's roster on sync; warn on mismatch
- Browser extension: same (small popup change)
- Tests for the verification path including drop / replay / forked
  chain attacks, mirroring the M2.15c manifest tests
- **Acceptance**: drop a member from the DB by hand, re-sync, watch
  client surface the mismatch
- **Estimated**: 1 session.

### M4.3 — Collections

- Server: collection CRUD endpoints + `cipher_collections` join
- CLI: `hekate collection create/list/rename/delete`,
  `hekate move <cipher> --to-collection <id>`
- Org-owned cipher AAD bumped to include `org_id` (migration
  `0013_cipher_aad_v3.sql`)
- Cipher data field encrypts under org_sym_key for org ciphers
- Tests including cipher move + collection assignment
- **Acceptance**: alice creates a collection, moves a cipher into it,
  bob (org member) can sync and decrypt the cipher.
- **Estimated**: 2 sessions.

### M4.4 — Permissions matrix + role enforcement

- Server stores collection_members rows
- Server enforces `read` (deny `PUT`/`DELETE` with 403)
- `/sync` returns each cipher with the requesting user's effective
  permission
- CLI honors `read_hide_passwords` by masking (popup too)
- Tests for every cell in §7
- **Acceptance**: bob with `read` on a collection can sync but his
  edit returns 403; bob with `read_hide_passwords` doesn't see the
  password in `hekate show`
- **Estimated**: 1 session.

### M4.5 — Cipher org-ownership + key rotation

- `POST /move-to-org`, `POST /move-to-personal`
- `POST /revoke` (member removal) with required key rotation
- Background re-encryption job
- CLI: `hekate org remove-member <org> <user_id>`,
  `hekate move-to-org <cipher> <org> --collection <id>`
- Tests: revoked member gets 403 on every endpoint, including
  `/api/v1/orgs/{id}` (their membership row is gone)
- **Acceptance**: smoke test for full add/remove cycle: alice invites
  bob, bob syncs an org cipher, alice revokes bob, alice's next
  cipher is unreadable to bob (but bob's already-decrypted plaintext
  remains — call it out)
- **Estimated**: 2 sessions.

### M4.6 — Policies (basic)

- Server: `policies` table (JSONB) keyed by `org_id` + policy_type
- Server returns active policies in `/sync`
- Client enforces policies that are client-side by nature
  (master-password-complexity check, vault-timeout, password-generator
  rules)
- Server enforces server-side policies (single_org, restrict-send)
- CLI: `hekate org policy {get,set} <org> <type> [params]`
- Tests for each shipped policy type
- **Estimated**: 1–2 sessions depending on how many policy types ship.

**Total**: ~10 sessions for M4 to be useful for a real team.

---

## 9. What's deferred to v2 (out of scope for M4)

- **Multi-admin signing** (Option C in §3) — single owner signs in v1.
- **Auditable membership log** (AKD-style Merkle log of roster history).
- **Org policies depending on 2FA** (`two_factor_required`) — gated
  on 2FA which is a separate M-track.
- **Org SSO / SCIM / Directory Connector** — M5.
- **Provider Portal (MSP cross-org admin)** — M5.
- **Org-level event log + SIEM webhook** — M2/M5 backlog.
- **Vault health reports across the whole org** — M4 polish.
- **Send within an org** — gated on Send subsystem (separate M-track).
- **Attachments on org-owned ciphers** — gated on attachments subsystem.
- **Emergency access** — M5.

---

## 10. Open design questions (please decide before M4.0 implementation starts)

### 10.1 Org bundle sig: who signs it?

Two candidates:

| | Owner signs | Server fabrication |
|---|---|---|
| Owner's Ed25519 (account signing key) | ✓ verifiable from M2.19 directory | server can't forge — owner has the key |
| Org's own Ed25519 | bootstrap problem — chicken/egg | server could swap pubkey |

**Recommendation**: owner signs. The org bundle row stores
`bundle_sig_b64` = `owner_signing.sign(canonical(org_id, name, signing_pubkey, owner_user_id))`. New members verify under the owner's
M2.19-pinned pubkey on accept, then TOFU-pin the org's signing pubkey
for future roster verification. Settles the bootstrap.

### 10.2 What about ownership transfer?

In v1, the owner is fixed at create time. To transfer:
- New owner accepts an `admin` role first (so they have the org_sym_key)
- Current owner exports the org signing seed (NOT WRAPPED — plaintext
  one-time export) over a signcryption envelope to the new owner
- New owner imports, then signs a new roster with their user_id as
  `owner` and the old owner as either removed or demoted to `admin`
- Server validates the new roster under the *org's* signing pubkey
  (which doesn't change), and updates `organizations.owner_user_id`

**Recommendation for M4.0–M4.5**: don't ship transfer. Single owner
forever in v1. Transfer is a future enhancement after multi-admin
lands.

### 10.3 Role naming

Bitwarden uses `owner / admin / manager / user / custom`. We can ship
a smaller set:

**Recommendation for v1**: `owner / admin / user`. Manager and custom
are M5.

### 10.4 Collection name encryption

Bitwarden encrypts collection names under the org symmetric key. That
means the server can't list collections by name in admin tooling.
Decision aligns with E2EE; ship it. Server uses opaque IDs everywhere.

### 10.5 Org member listing permissions

Two regimes:
- **All members can list all members** (Bitwarden default; same as
  Slack workspace member list).
- **Only admins/owner can list** (more privacy).

**Recommendation**: regime 1 (all members can list) for simplicity.
This is metadata anyway; the server already knows the membership.
Privacy regime can be a future policy.

---

## 11. Upgrade path to multi-admin (v2)

When demand for multi-admin signing arrives:

1. **Org CA**: replace single signing key with a CA root key + per-admin
   signing keys. Owner generates the CA at create time.
2. **Admin certificates**: each admin has an Ed25519 keypair; owner
   signs `(admin_user_id, admin_signing_pubkey, valid_from, valid_until)`
   under the CA. Stored on the org row.
3. **Roster sigs become a list** — any active admin can sign a roster
   update; clients verify against any admin cert that's valid at the
   roster's `updated_at`.
4. **Migration**: existing M4-v1 single-signer orgs add a CA root that
   delegates to the existing signing key (one-time admin cert
   issuance), without rotating member wraps.

Schema-compatible: just additional rows in a new `organization_admin_certs`
table. The roster format adds a `signed_by_admin_user_id` field. Old
clients reading new rosters need to upgrade to handle the cert chain.

This is genuinely v2 work and shouldn't influence M4-v1 implementation.

---

## 12. Acceptance criteria for "M4 v1 is done"

- [ ] M4.0 schema + create + list ships and is tested
- [ ] M4.1 invite + accept exercises `signcrypt::sign_encrypt` /
      `verify_decrypt` end-to-end with a smoke test that demonstrates
      the BW09 server-substitution attack being detected
- [ ] M4.2 roster verification rejects drop / replay / forked chain
- [ ] M4.3 collections + cipher org-ownership: a member can sync and
      decrypt a shared cipher
- [ ] M4.4 permissions: `read` member is server-side-blocked from
      editing; `read_hide_passwords` member's CLI/popup masks the
      password
- [ ] M4.5 member removal triggers org-key rotation; revoked
      member's `/sync` returns 401
- [ ] `make smoke` extended to cover the org/invite/accept/sync/
      revoke cycle
- [ ] `threat-model-gaps.md` row 3 of "Open: Authenticated public
      keys" struck through

When all of those pass, M4 v1 is shipped and Hekate has feature
parity with Bitwarden's "team plan" personal-vault sharing.

---

## References

- Scarlata, M., Torrisi, G., Backendal, M., Paterson, K. G. *"Zero
  Knowledge (About) Encryption."* USENIX Security 2026. Threat
  categories BW04–BW12 and LP01–LP07 referenced throughout.
- M2.18 — `crates/hekate-core/src/signcrypt.rs`
- M2.19 — `crates/hekate-server/src/routes/pubkeys.rs`
- M2.20 — `crates/hekate-cli/src/commands/peer.rs`
- M2.15c — `crates/hekate-core/src/manifest.rs` (the design pattern
  this doc reuses for org rosters)
