# Hekate

A high-performance, open-source password manager. Greenfield Rust-native alternative to Bitwarden, with full enterprise feature parity at a fraction of the operational footprint.

> **Brand vs. code names.** The product is **Hekate** (Greek goddess of keys and crossroads). Code-level identifiers — Cargo packages (`hekate-core`, `hekate-server`, `hekate-cli`), binaries (`hekate-server`, `hekate`), env vars (`HEKATE_*`), container/volume names — all use `hekate`. The protocol-frozen identifiers — AAD strings (`pmgr-cipher-key-v2:…`, `pmgr-vault-manifest-v3\x00`, every other `b"pmgr-…"` literal), signature DSTs, token wire formats (`pmgr_sat_*`, `pmgr_pat_*`), and the `PMGRA1` magic for chunked-AEAD bodies — keep the original `pmgr-…` / `pmgr_*` prefix because they're baked into ciphertexts, signed manifests, and stored hashes. Renaming them would invalidate every user's vault.

**Status:** Pre-alpha but feature-complete on the personal-vault track and the org track through M4.6 (create / invite / accept / cancel / collections / member removal + key rotation / basic policies). M5 (Trust UX redesign) and M6 (Secrets Manager) are the next major milestones. SSO / SCIM / advanced policies are deferred to a future managed-service offering.

- **Server:** axum + sqlx (SQLite + Postgres), distroless production image, OpenAPI 3.1 + Scalar docs, JWT auth, rolling refresh tokens, BW04 signed vault manifest, BW07/LP04 KDF-bind MAC, BW08 signed org rosters, signcryption-based org invites, server-side push (SSE), webhooks, PATs, service accounts.
- **Three first-party clients, all sharing the same `hekate-core` WASM crypto:**
  - `hekate` CLI (`crates/hekate-cli`) — full feature set, including SSH agent and `unlock` daemon.
  - Browser extension (Chromium MV3, `clients/extension/`) — vault, sends, orgs (full read + write including owner-only member removal with org key rotation), attachments, TOTP + WebAuthn, rotate-keys, autofill, passkey provider.
  - Web vault (`clients/web/`, SolidJS + Vite) — personal vault, sends, orgs (full read + write including owner-only member removal with org key rotation), settings (change password, 2FA TOTP+WebAuthn, peer pins, account export, account delete), rotate-keys, attachments. Ships at `/web/*` (owner mode) and `/send/*` (recipient mode for share links).
- **Crypto stack:** XChaCha20-Poly1305 / Argon2id / Ed25519 / X25519 / BLAKE3 / HKDF; EncString v3 wire format; PMGRA1 chunked-AEAD attachments; signed BW04 vault manifest v3; signed BW08 org rosters; signcryption envelopes for org invites.

## Run it (Docker, no host toolchain)

```bash
make up                                          # Postgres + server
curl http://localhost:8088/health/ready          # direct
curl http://hekate.localhost/health/ready          # via local Traefik
make logs
make down
```

For SQLite-only single-binary mode (no Postgres):

```bash
make up-sqlite
```

## Cross-origin browser access

The default deployment serves the SPA, the Send recipient surface, and
the API from the same `hekate-server` origin, so cross-origin browser
checks don't apply. If you split the stack — SPA on a CDN, API on a
separate hostname — set `HEKATE_CORS_ALLOWED_ORIGINS` to the exact
origins (scheme + host + port) that should be permitted to call the
API from a browser:

```bash
HEKATE_CORS_ALLOWED_ORIGINS='["https://vault.example.com"]'
```

Wildcards are intentionally not supported. The browser extension
doesn't go through this allowlist — it has its own cross-origin grant
via `host_permissions` in its manifest. Native (CLI) and
server-to-server callers ignore CORS entirely.

## Develop without installing Rust

Everything runs in Docker:

```bash
make build       # cargo build (release)
make test        # cargo test
make check       # cargo check
make fmt         # rustfmt
make clippy      # clippy --all-targets -D warnings
make shell       # interactive shell in the build image
```

## Documentation

| Doc | What's in it |
|---|---|
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | How to contribute (DCO sign-off required, no CLA) |
| [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) | Contributor Covenant 2.1 — community ground rules |
| [`SECURITY.md`](SECURITY.md) | Private vulnerability disclosure channel |
| [`docs/design.md`](docs/design.md) | Full architecture & cryptography spec — the north star |
| [`docs/status.md`](docs/status.md) | What's shipped, what's next, parity scorecard |
| [`docs/api.md`](docs/api.md) | Concrete endpoint reference + curl examples |
| [`docs/development.md`](docs/development.md) | Stack, layout, common workflows, troubleshooting |
| [`docs/browser-extension.md`](docs/browser-extension.md) | Build / install / use the MV3 browser extension |
| [`docs/followups.md`](docs/followups.md) | Single durable list of queued / deferred work — read at session start |
| [`docs/ssh-agent.md`](docs/ssh-agent.md) | Use `hekate ssh-agent` as a drop-in replacement for `ssh-agent`, with optional per-use approval via `--approve-cmd` |
| [`docs/m4-organizations.md`](docs/m4-organizations.md) | Design + implementation plan for the orgs / collections / sharing track — schema, BW08 mitigation, milestone breakdown |
| [`CHANGELOG.md`](CHANGELOG.md) | Per-milestone notes |

A live OpenAPI 3.1 spec is served at `http://hekate.localhost/api/v1/openapi.json` and rendered as interactive Scalar docs at `http://hekate.localhost/api/v1/docs`.

## Browser extension (Chromium MV3)

```bash
make extension        # builds the WASM core and stages it into clients/extension/wasm/
```

Then load `clients/extension/` as an unpacked extension at
`chrome://extensions` (Developer mode → Load unpacked). See
[`clients/extension/README.md`](clients/extension/README.md). The
popup ships full vault CRUD, sends, attachments, TOTP + WebAuthn,
organizations (full read + write — create, invite, accept,
cancel, collections, member removal with key rotation,
policies), `account rotate-keys`, a single-cipher autofill
path, and a passkey provider (`webAuthenticationProxy`) — all
driven by the same WASM crypto core the server and CLI use.

## Web vault (SolidJS + Vite)

```bash
make web             # builds clients/web/dist
make up              # production image bakes the SPA into /app/web-dist
```

The web vault is served by `hekate-server` itself at two URL prefixes:

- `http://hekate.localhost/web/` — owner mode (login, vault, sends, orgs, settings).
- `http://hekate.localhost/send/#/<id>/<key>` — recipient mode for share URLs. The recipient key lives in the URL fragment so the server never sees it; the SPA decrypts client-side via the same WASM crypto core.

Both prefixes serve the same SolidJS bundle.

`make web-dev` runs a Vite dev server on `:5173` for fast iteration.

## Layout

```
crates/
  hekate-core/     shared lib (crypto, sync types) — also compiles to wasm32 for the JS clients
  hekate-server/   axum HTTP server
  hekate-cli/      command-line client (binary: hekate)
clients/
  extension/     Chromium MV3 browser extension (Hekate)
  web/           SolidJS web vault (Hekate)
migrations/      sqlx migrations (SQLite + Postgres)
docker/          dev Dockerfile
docs/            design, status, api, development, browser-extension
Dockerfile       production multi-stage build (~42 MB distroless image
                 + bundled SPA + bundled WASM core)
```

## CLI quickstart

Build the CLI binary (Linux ELF, run inside the dev container):

```bash
make cli
docker run --rm -it \
  -v "$PWD":/workspace -v hekate_cargo_registry:/usr/local/cargo/registry \
  -v hekate_target:/workspace/target -w /workspace \
  -e XDG_CONFIG_HOME=/tmp/hekate-cli -e HOME=/tmp \
  hekate-dev:latest /workspace/target/release/hekate --help
```

Available commands:

| Command | Purpose |
|---|---|
| `register` | Create a new account (client-side Argon2id, X25519 keypair, account-key generation) |
| `login`    | Re-authenticate; saves access + refresh tokens locally |
| `status`   | Show current session state |
| `logout`   | Clear local state |
| `add login --name --username --password --uri [--notes]` | Create a login cipher |
| `add note --name --notes` | Create an encrypted secure note |
| `add card --name --cardholder --brand --number --exp-month --exp-year --cvv` | Create a card |
| `add identity --name --first --last --email --phone --address1 --city --state --postal --country [--ssn --passport --license]` | Create an identity entry |
| `add ssh-key --name --public-key= --private-key= [--fingerprint=]` | Store an SSH keypair |
| `add totp --name --secret=` | Store a TOTP entry (otpauth URL or bare base32); `show` prints the current code |
| `edit <kind> <id> [...]` | Modify a cipher; `<kind>` is `login`, `note`, `card`, `identity`, `ssh-key`, or `totp`. Revision-checked, conflicts surfaced. Common flags: `--name`, `--notes`, `--clear-notes`, `--favorite`. Per-type flags mirror `add` (e.g. `--cardholder`, `--first`, `--public-key`, `--secret`). |
| `list [--all]` | List vault items (mixed types, type-aware columns); `--all` includes trash |
| `show <id> [--reveal]` | Show one cipher (passwords / card numbers / CVV masked unless `--reveal`) |
| `delete <id>` | Soft-delete (move to trash) |
| `restore <id>` | Restore from trash |
| `purge <id> [--yes]` | Permanent delete (writes a tombstone) |
| `sync [--since RFC3339]` | Pull deltas + print counts and tombstones |
| `watch [--skip-unlock]` | Subscribe to `/push/v1/stream` and print events as they arrive |
| `token create --name --scopes [--expires-in-days]` | Issue a Personal Access Token (printed once) |
| `token list` | List your PATs (metadata only) |
| `token revoke <id>` | Revoke a PAT |
| `webhook create --name --url [--events]` | Subscribe a URL to receive HMAC-signed event POSTs (secret printed once) |
| `webhook list` | List webhook subscriptions |
| `webhook delete <id>` | Remove a webhook subscription |
| `webhook deliveries <id>` | Audit the last 50 delivery attempts (status, errors, retries) |
| `unlock [--ttl 15m]` | Start a per-user daemon caching the unwrapped account key — subsequent commands skip the password prompt + Argon2id (~40× faster). Unix only. |
| `lock` | Stop the unlock daemon |
| `ssh-agent {start,stop,status} [--approve-cmd CMD]` | Run a local SSH agent backed by stored ssh-key ciphers (Ed25519 only). Set `SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/hekate-ssh-<uid>.sock` to use it. `--approve-cmd` runs your shell command on every SIGN_REQUEST with `HEKATE_SSH_KEY_COMMENT` and `HEKATE_SSH_KEY_FP` in env; non-zero exit denies the sign. |
| `peer {fetch <id>, pins, fingerprint, verify <id> <fp>, unpin <id> --yes}` | TOFU public-key pinning for other accounts. `fetch` verifies the self-signed bundle and pins it locally; subsequent fetches require byte-identical match. `fingerprint` prints your own fingerprint for OOB verification with peers. |
| `org {create, list, invite, invites, accept, cancel-invite, remove-member, collection {…}, policy {…}, cipher-manifest {…}}` | Organization track. `create` makes a new org with the caller as sole owner; `invite` / `invites` / `accept` / `cancel-invite` cover the invite lifecycle; `remove-member` rotates the org sym key and re-wraps every org-owned cipher in one atomic POST; `collection` covers CRUD on encrypted-name collections; `policy` covers `set/get/list/unset`; `cipher-manifest` covers the per-org BW04 set-level integrity manifest. See [`docs/m4-organizations.md`](docs/m4-organizations.md). |
| `org service-account {create, list, disable, delete}` and `org service-account token {create, list, revoke}` | Org-scoped machine identities (`pmgr_sat_*` tokens). Owner-only management. Test against `/api/v1/service-accounts/me` to verify a token works. The Secrets Manager track will add call sites that gate on `secrets:*` scopes. |
| `attach {upload <cipher_id> <file>, download <id> [-o out], list <cipher_id>, delete <id> --yes}` | Chunked-AEAD attachments via tus 1.0. Generates a per-attachment XChaCha20-Poly1305 key, encrypts the file in 1-MiB AEAD chunks (PMGRA1 wire format), and uploads via tus with HEAD-resume on transient errors. The BW04 manifest is auto re-signed after every write so the `attachments_root` binding stays current. Personal and org-owned ciphers both supported (the unwrap path mirrors `hekate show`). |
| `send {create-text <text>, create-file <path>, list, delete <id> --yes, disable/enable <id>, open <url>}` | Ephemeral encrypted text and file shares. Sender generates a 32-byte send_key (URL fragment, never sent to the server), HKDFs to the AEAD content key, encrypts the payload, wraps send_key under the account key for sender-side list/edit. File Sends use the same chunked-AEAD format as attachments, tus 1.0 transport, and 5-minute anonymous download tokens. Optional Argon2id-PHC server-gate password (revoke-but-can't-decrypt). Atomic max-access-count enforcement, time-based expiration, GC drops past-deletion_date rows and their blobs. |
| `account change-password` | Rotate the master password (full key re-wrap; invalidates all other sessions) |
| `account rotate-keys` | Rotate the symmetric `account_key` and re-wrap every dependent (personal-cipher PCKs, Send keys, org member keys, X25519 private wrap) atomically. Master password unchanged; BW04 manifest and peer TOFU pins unaffected. Other devices need to re-login. |
| `import bitwarden <file> [--dry-run] [--skip-folders]` | Import an unencrypted Bitwarden JSON export. Folders plus the four standard item types (login / secure_note / card / identity); custom fields are appended to notes; org-owned items and unsupported types are skipped with warnings. Re-signs the BW04 manifest at the end. |
| `import 1password <file.1pux> [--dry-run] [--skip-folders]` | Import a 1Password 1PUX export. Vaults become folders. Maps Login / Card / Secure Note / Identity / Password categories; trashed items and unsupported categories (Documents, SSH Key, Software License, etc.) skipped with warnings. |
| `import keepass <file.kdbx> [--dry-run] [--skip-folders]` | Import a KeePass KDBX 3.1 / 4 database. Prompts for the database master password (separate from Hekate's). Every entry → login by default; entries with no UserName/Password/URL plus non-empty Notes get the secure_note heuristic. Leaf group name → folder. Custom fields and tags appended to notes. Recycle Bin contents skipped. |
| `import lastpass <file.csv> [--dry-run] [--skip-folders]` | Import a LastPass CSV export. Standard logins → cipher_type 1 with username/password/uri/totp; sentinel-URL rows (`http://sn`) → secure_note. Leaf segment of `grouping` (slash-separated) → folder. LastPass typed notes (credit cards or identities encoded with a `NoteType:` prefix) are skipped with per-row warnings — re-enter manually. |
| `account delete [--yes]` | Permanently delete the account (re-auth required) |
| `account export <file>` | Write an encrypted backup of the entire vault to a file |
| `config strict-manifest {on, off, status}` | Toggle whether `hekate sync` exits non-zero on a BW04 personal-manifest mismatch. Default off (warn-mode). Browser-extension equivalent in Settings → "Strict manifest verification". |
| `account 2fa {enable, disable, status, recovery-codes regenerate}` | TOTP 2FA and recovery codes. Recovery codes are an authentication-only 2FA bypass — they let you finish a login when your authenticator is gone, but do **not** decrypt the vault (lose your master password = data is gone). WebAuthn / FIDO2 is supported server-side at `/api/v1/account/2fa/webauthn/*` and via the browser extension (Settings → Manage 2FA); CLI WebAuthn is a follow-up (needs libfido2). |
| `generate [--length N] [--no-symbols / -numbers / -uppercase / -lowercase]` | CSPRNG random password |
| `generate --passphrase [--words N] [--separator S] [--capitalize]` | EFF-long-list passphrase (5 words ≈ 64.6 bits of entropy by default; 7776-word list embedded at build time) |

Access tokens are 1-hour JWTs; the CLI automatically refreshes via the saved refresh token on 401, so once you've logged in you stay logged in until the refresh token expires (30 days).

See [`docs/api.md`](docs/api.md) for the underlying endpoints.

## License

All code in this repository is licensed under **AGPL-3.0-or-later**.
See [`LICENSE`](LICENSE) for the full text and [`NOTICE`](NOTICE) for
the copyright statement.

### Trademark

"Hekate" is the project name and may be used by anyone running
unmodified Hekate. "Synapticcyber" and "Synaptic Cybersecurity Alliance"
are trademarks of Synaptic Cybersecurity Alliance, Inc.; commercial use
of those marks (including in the names of services hosted as a fork or
competitor) requires permission.
