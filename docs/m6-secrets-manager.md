# M6 — Secrets Manager (kickoff plan)

Per `docs/design.md` §10 + §13: ~8 weeks total across M6.0–M6.4.
This doc kicks off **M6.0** (server schema + routes + `pms` CLI +
Rust SDK), with later sub-milestones outlined for context.

All identifiers below use the current `hekate-*` naming.
Protocol-frozen byte literals (AAD strings, signature DSTs,
token prefixes, magic numbers) retain their original `pmgr-`
form because they're baked into ciphertexts on disk; see
`threat-model-gaps.md` for the enumerated set.

## Decisions locked

(From the M6 strategy discussion in the prior session.)

| # | Decision | Choice |
|---|---|---|
| Q1 | Crypto model | **Per-project sym key.** Each project has one symmetric key wrapped to each authorized principal. Reuses the M4.5b rotate-on-revoke pattern. |
| Q2 | Principal model | **Polymorphic principal access from day one, SA-only at first.** Schema admits both `service_account` and `user` principals; M6.0 only wires SA. Human read/write deferred. |
| Q3 | URL prefix + crate split | **`/api/v1/secrets/`** (consistent with §7 unified-API contract). **Inline in `hekate-server`** until first SDK; lift wire types into `hekate-secrets-types` at M6.1. |
| Q4 | Audit log destination | **Own `sm_audit_events` table now**, with shape compatible with future merge into M5's global `events` table. |
| Q5 | Versioning + retention | Soft-delete + tombstone. Per-project retention policy (`prune_after_days`, `keep_last_n`). Pruning rides the existing GC worker pattern (`hekate-server/src/attachments_gc.rs`). |
| Q6 | SDK languages | **Rust → Python → Node** at M6.1. Go bundled with Terraform at M6.3. Skip .NET. Ruby on demand. |
| Q7 | `pms` distribution | GitHub releases (static binaries) + `ghcr.io/hekate/pms:<v>` Docker image at M6.0. Homebrew at M6.1. apt later if asked. |
| Q8 | Integrations | M6.2 = GitHub Actions + K8s operator. M6.3 = Terraform + Go SDK. Ansible deferred. |

## Reuse inventory (already shipped)

- **`AuthService` extractor** + `pmgr_sat_*` token wire format —
  `hekate-server/src/routes/service_accounts.rs`. M6 adds the
  `secrets:read` / `secrets:write` scope-validation call sites
  flagged in that file's M2.5 comment.
- **M4.5b rotate-on-revoke pattern** — owner picks new sym key,
  signcrypts to every authorized principal's X25519 pubkey,
  re-encrypts every project secret atomically. Reference
  implementation: `hekate-server/src/routes/orgs.rs` `revoke_member`
  + the three client rewrap loops (CLI / popup / web).
- **Signed-roster pattern (BW08)** — projects don't need a roster
  since access is per-principal not per-collection, but the
  `signing_seed_protected` per-project pattern lets us add a
  per-project audit-signed manifest if we want one later.
- **TOFU peer-pin requirement on signcrypt** — same gate as M4.5b:
  caller must have the recipient SA's pubkey pinned before
  granting it project access. Cross-store with the M4 peer-pin
  registries.
- **GC worker pattern** —
  `hekate-server/src/attachments_gc.rs` (60-second tick,
  bootstrap-then-loop). Copy for `sm_secret_versions` pruning.
- **Per-org JSONB policies (M4.6)** — extend with
  `sm_default_retention` and `sm_max_secret_size` policy keys.

## M6.0 schema

Ships in a single new migration (next free number after the
current baseline):

```sql
-- Project: top-level grouping, owns a sym key.
CREATE TABLE sm_projects (
  id                          TEXT PRIMARY KEY,            -- UUIDv7
  org_id                      TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name_ct                     TEXT NOT NULL,               -- EncString under sym key
  -- Sym key wrapped to each authorized principal lives in sm_project_access.
  current_sym_key_id          TEXT NOT NULL,               -- UUIDv7, bumps on revoke
  signing_seed_protected      TEXT NOT NULL,               -- EncString under owner account_key
  created_by_user_id          TEXT NOT NULL REFERENCES users(id),
  created_at                  TEXT NOT NULL,
  deleted_at                  TEXT
);

CREATE INDEX idx_sm_projects_org ON sm_projects(org_id) WHERE deleted_at IS NULL;

-- Polymorphic principal access. M6.0 only writes service_account rows;
-- M6.x can add user rows without schema change.
CREATE TABLE sm_project_access (
  project_id                  TEXT NOT NULL REFERENCES sm_projects(id) ON DELETE CASCADE,
  principal_type              TEXT NOT NULL CHECK (principal_type IN ('service_account', 'user')),
  principal_id                TEXT NOT NULL,
  protected_sym_key           TEXT NOT NULL,               -- EncString of project sym key, wrapped to principal's X25519 pubkey via signcryption
  can_read                    BOOLEAN NOT NULL DEFAULT TRUE,
  can_write                   BOOLEAN NOT NULL DEFAULT FALSE,
  granted_by_user_id          TEXT NOT NULL REFERENCES users(id),
  granted_at                  TEXT NOT NULL,
  pending_envelope            TEXT,                        -- after rotation, until principal calls /rotate-confirm
  pending_sym_key_id          TEXT,                        -- corresponds to pending_envelope
  PRIMARY KEY (project_id, principal_type, principal_id)
);

CREATE INDEX idx_sm_project_access_principal
  ON sm_project_access(principal_type, principal_id);

-- Current secret. value_ct holds the latest version; history in sm_secret_versions.
CREATE TABLE sm_secrets (
  id                          TEXT PRIMARY KEY,
  project_id                  TEXT NOT NULL REFERENCES sm_projects(id) ON DELETE CASCADE,
  key_ct                      TEXT NOT NULL,               -- EncString
  value_ct                    TEXT NOT NULL,               -- EncString
  current_version             BIGINT NOT NULL,
  note_ct                     TEXT,                        -- optional EncString comment
  revision                    BIGINT NOT NULL,             -- bump on every PUT, used for /sync If-Match like ciphers
  created_by                  TEXT NOT NULL,               -- user_id or service_account_id
  created_at                  TEXT NOT NULL,
  updated_at                  TEXT NOT NULL,
  deleted_at                  TEXT                         -- soft-delete; tombstone for /sync delivery
);

CREATE INDEX idx_sm_secrets_project ON sm_secrets(project_id) WHERE deleted_at IS NULL;

-- Append-only history. Pruned by GC according to project retention policy.
CREATE TABLE sm_secret_versions (
  id                          TEXT PRIMARY KEY,
  secret_id                   TEXT NOT NULL REFERENCES sm_secrets(id) ON DELETE CASCADE,
  version                     BIGINT NOT NULL,
  value_ct                    TEXT NOT NULL,
  written_by                  TEXT NOT NULL,
  written_at                  TEXT NOT NULL,
  UNIQUE (secret_id, version)
);

CREATE INDEX idx_sm_secret_versions_secret ON sm_secret_versions(secret_id);

-- Per-project retention. Defaults are NULL = "keep all".
ALTER TABLE sm_projects
  ADD COLUMN retention_prune_after_days INTEGER,
  ADD COLUMN retention_keep_last_n INTEGER;

-- Audit log. Future-compatible with a global events table.
CREATE TABLE sm_audit_events (
  id                          TEXT PRIMARY KEY,            -- UUIDv7
  org_id                      TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  project_id                  TEXT,                        -- NULL for org-scoped events
  secret_id                   TEXT,
  actor_principal_type        TEXT NOT NULL,
  actor_principal_id          TEXT NOT NULL,
  event_type                  TEXT NOT NULL,               -- 'secret.read', 'secret.write', 'project.create', etc.
  metadata_json               TEXT NOT NULL DEFAULT '{}',
  ip                          TEXT,
  user_agent                  TEXT,
  created_at                  TEXT NOT NULL
);

CREATE INDEX idx_sm_audit_org_time ON sm_audit_events(org_id, created_at DESC);
CREATE INDEX idx_sm_audit_project_time ON sm_audit_events(project_id, created_at DESC);
```

**AAD strings** (protocol-frozen — keep `pmgr-` per the rename
plan):

- `pmgr-sm-project-name-v1:<project_id>` — project name encryption
- `pmgr-sm-project-sym-key-v1:<project_id>:<key_id>` — bind sym
  key to project + key generation
- `pmgr-sm-secret-v1:<secret_id>:key` — secret key field
- `pmgr-sm-secret-v1:<secret_id>:value` — secret value field
- `pmgr-sm-secret-v1:<secret_id>:note` — optional secret note
- `pmgr-sm-key-rotation-v1` — rotation envelope payload kind
  (parallel to `pmgr-org-key-rotation-v1`)

## M6.0 routes

All under `/api/v1/secrets/`. Auth: bearer JWT (user) or
`pmgr_sat_*` SAT (service account). Scope-gated where indicated.

```
# Projects ─ owner-managed
POST   /api/v1/orgs/{org_id}/secrets/projects               (org owner)
GET    /api/v1/orgs/{org_id}/secrets/projects               (org member)
GET    /api/v1/secrets/projects/{project_id}                (project access)
PUT    /api/v1/secrets/projects/{project_id}                (org owner)
DELETE /api/v1/secrets/projects/{project_id}                (org owner; soft-delete)

# Project access grants
POST   /api/v1/secrets/projects/{project_id}/access         (org owner; grants SA can_read/can_write; signcryption envelope to SA pubkey)
GET    /api/v1/secrets/projects/{project_id}/access         (org owner)
DELETE /api/v1/secrets/projects/{project_id}/access/{principal_type}/{principal_id}
                                                            (org owner; triggers project sym-key rotation, parallels M4.5b revoke_member)
POST   /api/v1/secrets/projects/{project_id}/rotate-confirm (consume pending envelope; parallels orgs/{id}/rotate-confirm)

# Secrets ─ scope-gated
POST   /api/v1/secrets/projects/{project_id}/secrets        (secrets:write)
GET    /api/v1/secrets/projects/{project_id}/secrets        (secrets:read; list)
GET    /api/v1/secrets/{secret_id}                          (secrets:read)
PUT    /api/v1/secrets/{secret_id}                          (secrets:write; If-Match revision)
DELETE /api/v1/secrets/{secret_id}                          (secrets:write; soft-delete + tombstone)
GET    /api/v1/secrets/{secret_id}/versions                 (secrets:read; paginated)
GET    /api/v1/secrets/{secret_id}/versions/{version}       (secrets:read; specific version)

# Sync (delta)
GET    /api/v1/secrets/sync?project_id=...&since=...        (secrets:read; mirrors /api/v1/sync shape)

# Audit
GET    /api/v1/orgs/{org_id}/secrets/audit                  (org owner; paginated, filterable by project/event_type/actor/time)
```

Scope grammar (from design.md §7):

- `secrets:read[:project:<id>]` — read-only
- `secrets:write[:project:<id>]` — read + write
- `secrets:admin:org:<id>` — manage projects + access grants in
  this org (org-owner-only at M6.0; future use)

## M6.0 server crate layout

```
crates/hekate-server/src/
  routes/
    secrets/
      mod.rs              # router wiring
      projects.rs         # CRUD on sm_projects
      access.rs           # grant / revoke / rotate-confirm
      secrets.rs          # CRUD on sm_secrets
      sync.rs             # delta sync
      audit.rs            # GET /audit
  secrets/
    mod.rs
    crypto.rs             # AAD constants, signcryption helpers
    rotation.rs           # rotate_project_sym_key, mirrors orgs.rs revoke_member
    gc.rs                 # version pruning per retention policy
```

`hekate-core` gains `secrets` module with AAD constants and
plaintext types (so the SDK can depend on `hekate-core` without
pulling server code).

## M6.0 `pms` CLI

New crate `crates/pms-cli/`. **Auth via env-var SAT only** —
`HEKATE_SAT` env var holds `pmgr_sat_<id>.<secret>`. No master
password. No interactive prompts.

```
pms project create --org-id <id> --name <NAME>
pms project list   [--org-id <id>]
pms project delete <project_id>

pms secret set    <project_id> --key KEY --value VALUE [--note TEXT]
pms secret set    <project_id> --key KEY --from-file -            # value from stdin
pms secret get    <secret_id> [--reveal]
pms secret list   <project_id>
pms secret delete <secret_id>
pms secret history <secret_id>

pms run -- <cmd> [args...]
  # Looks up every secret the SAT can read in the configured
  # project, exports as ENV_VAR=<value>, exec's cmd, scrubs
  # the env. Project selected via HEKATE_PROJECT env var or
  # --project-id flag.
```

`pms run` is the headline integration with CI/CD — it makes
Hekate a drop-in for `vault read -format=...` patterns.

## M6.0 Rust SDK

New crate `crates/hekate-secrets-sdk/` with a small surface:

```rust
pub struct Client { /* SAT, base URL, http client */ }

impl Client {
  pub fn new(sat: &str, base_url: &str) -> Result<Self>;
  pub async fn project_list(&self) -> Result<Vec<Project>>;
  pub async fn project_get(&self, id: &str) -> Result<Project>;
  pub async fn secret_list(&self, project_id: &str) -> Result<Vec<SecretMeta>>;
  pub async fn secret_get(&self, id: &str) -> Result<Secret>;
  pub async fn secret_set(&self, project_id: &str, key: &str, value: &[u8], note: Option<&str>) -> Result<Secret>;
  pub async fn secret_delete(&self, id: &str) -> Result<()>;
  pub async fn secret_history(&self, id: &str) -> Result<Vec<SecretVersion>>;
  pub async fn sync(&self, project_id: &str, since: Option<DateTime>) -> Result<SyncDelta>;
}
```

Plaintext types live in `hekate-core::secrets`; SDK re-exports
them. Server-bound wire types stay private to the SDK.

`Client::secret_get` is the hot path — performs:
1. Decrypt project sym key from `protected_sym_key` (cached
   in-memory once per project per process).
2. Decrypt secret value under sym key with AAD
   `pmgr-sm-secret-v1:<secret_id>:value`.
3. Return plaintext bytes.

## Test plan (M6.0)

- **`hekate-core::secrets`** — AAD constants, EncString round-trip,
  rotation envelope payload shape. ~10 unit tests.
- **`hekate-server` integration** (`tests/secrets.rs`):
  - Owner creates project, grants SA read access, SA reads back
  - Owner creates project, grants SA write access, SA writes +
    re-reads
  - SA without grant gets 403
  - SA with read-only gets 403 on write
  - Revoke SA → project sym-key rotates → other authorized SAs
    get pending envelopes
  - rotate-confirm: pending envelope → cleared, new key wraps
  - Soft-delete of a project tombstones its secrets, /sync
    surfaces tombstones
  - Version history: 3 sets → /versions returns 3, /versions/2
    returns the specific version
  - Retention: `keep_last_n=1` after 3 sets → GC prunes versions
    1+2, version 3 remains
  - Cross-org isolation: org A's SAT can't touch org B's
    projects
  - Audit: every read / write / grant / revoke / rotation
    appears in `sm_audit_events` with correct actor + event_type
- **`pms-cli`** (`tests/`) — unit tests for env-var SAT loader,
  `pms run` env-injection + scrubbing.
- Target ~25 new integration tests; brings total to ~410.

## Smoke (M6.0)

End-to-end via `pms`:

1. Owner registers + creates org + creates project via web vault
2. Owner creates SA in the org, issues SAT with
   `secrets:write:project:<id>` scope
3. SAT lands in CI runner env: `HEKATE_SAT=pmgr_sat_…`,
   `HEKATE_BASE_URL=https://…`, `HEKATE_PROJECT=<id>`
4. CI runs:
   ```
   pms secret set <project_id> --key DB_PASSWORD --value 'super-secret'
   pms secret get <secret_id> --reveal
   pms run -- bash -c 'echo $DB_PASSWORD'   # prints super-secret
   ```
5. Owner revokes the SA → project sym key rotates atomically →
   subsequent `pms secret get` with the revoked SAT fails 401

Document this in `docs/m6-smoke.md` once M6.0 lands.

## Followup sub-milestones

- **M6.1 — language SDKs.** Lift wire types to
  `hekate-secrets-types`. Generate Python + Node bindings via
  `uniffi-rs`. Publish to PyPI + npm.
- **M6.2 — GitHub Actions + K8s operator.** JS-shim Action
  wrapping the Node SDK. CRD `HekateSecret` operator that
  reconciles into native K8s Secrets.
- **M6.3 — Terraform + Go SDK.** Provider ships
  `hekate_project` + `hekate_secret` resources. Go bindings via
  uniffi.
- **M6.4 — Ruby + remaining integrations.** On-demand only.

## Open questions / things to check before starting

- Server admin model: do SATs have an "audit-log read" scope or
  is that human-only? (M6.0 punts: org owner only.)
- Per-project signing seed: do we ship the per-project signed
  manifest immediately or defer like the per-cipher-key flow?
  (M6.0: ship the column + populate it; do not ship the
  end-to-end signed-manifest verify until M6.1+.)
- Is the project sym key wrapped under the org sym key or under
  each principal directly? **Answer: directly under each
  principal**, mirroring `organization_members.protected_org_key`.
  Cleaner crypto-flow than two layers of wrap.

---

## Implementation kickoff

When work on M6.0 begins, the build order is:

1. New migration (next free number after the current baseline)
   carrying the schema from this doc.
2. `hekate-core::secrets` module — AAD constants and plaintext
   types.
3. `hekate-server::routes::secrets::*` — projects, access,
   secrets, sync, audit. Wire under `/api/v1/secrets/`.
4. Integration tests in `hekate-server/tests/secrets.rs`,
   targeting the matrix in the design above.
5. `crates/pms-cli/` — env-var SAT auth, project / secret /
   run subcommands.
6. `crates/hekate-secrets-sdk/` — small async surface.

Reuse patterns from earlier milestones:

- **AuthService extractor + `pmgr_sat_*` tokens** —
  `hekate-server/src/routes/service_accounts.rs`. Per-project
  symmetric-key rotation on access revoke is structurally
  identical to the M4.5b rotate-on-revoke flow in
  `hekate-server/src/routes/orgs.rs`.
- **TOFU peer-pin + signcryption envelope** for any
  client-to-client key handoff.
- **Background GC worker** —
  `hekate-server/src/attachments_gc.rs` (60s tick,
  bootstrap-then-loop). Reuse for `sm_secret_versions`
  pruning.
- **Per-org JSONB policies** — M4.6 — extend with
  `sm_default_retention` and `sm_max_secret_size` keys.
