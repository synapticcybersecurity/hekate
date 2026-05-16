# Hekate — Development Guide

How to build, test, and contribute. Everything runs inside Docker; you don't need a host Rust toolchain (or a host Node toolchain — the web vault builds in a sibling node container).

> Brand vs. code names: the product is **Hekate**. Code-level identifiers — Cargo packages (`hekate-core`, `hekate-server`, `hekate-cli`), binaries (`hekate-server`, `hekate`), env vars (`HEKATE_*`) — all use `hekate`. The protocol-frozen identifiers — every `b"pmgr-…"` AAD string, signature DSTs, token wire formats (`pmgr_sat_*`, `pmgr_pat_*`), and the `PMGRA1` magic — keep their original `pmgr-…` / `pmgr_*` prefix because they're baked into ciphertexts. See the README for the full split.

## Stack

- **Language:** Rust (latest stable, currently 1.86+ via `rust:slim-bookworm`)
- **HTTP:** axum 0.8 + tower + hyper + tokio
- **Database:** sqlx 0.8 over `AnyPool` — SQLite (default) or Postgres
- **Crypto:** RustCrypto (`argon2`, `chacha20poly1305`, `hkdf`, `sha2`)
- **Push:** SSE via `axum::response::sse` over `tokio::sync::broadcast`
- **Auth:** `jsonwebtoken` (HS256 for M1; EdDSA tracked for v1.0)
- **Config:** `figment` over TOML + `HEKATE_*` env vars
- **Tracing:** `tracing` + `tracing-subscriber` (JSON)

## Layout

```
crates/
  hekate-core/                 — shared crypto, types (also compiled to wasm32)
    src/
      kdf.rs                 — Argon2id + HKDF subkeys
      encstring.rs           — XChaCha20-Poly1305 envelope v3
      attachment.rs          — PMGRA1 chunked-AEAD format (M2.24)
      send.rs                — Send key/encode/encrypt + AAD constructors (M2.25)
      manifest.rs            — BW04 signed vault manifest (M2.15c)
      org_roster.rs          — BW08 signed org roster (M4.0)
      signcrypt.rs           — sign-then-encrypt envelope (M2.18)
      import_*.rs            — Bitwarden / 1Password / KeePass / LastPass parsers
      wasm.rs                — wasm-bindgen exports for popup + web vault
  hekate-server/               — axum binary
    src/
      main.rs / lib.rs       — bootstrap + run + build_router
      config.rs              — figment-loaded Config (incl. HEKATE_WEB_DIR)
      db.rs                  — sqlx pool, migrate(), ping()
      push.rs                — PushBus (broadcast channel + typed events)
      blob.rs                — DynBlobStore + LocalFsBlobStore (M2.24)
      attachments_gc.rs      — long-lived GC worker
      auth/                  — extractor, jwt, password, refresh, sat (M2.5)
      routes/
        accounts.rs          — register, prelogin, ApiError
        identity.rs          — token endpoint (password + refresh + 2FA)
        account.rs           — change-password, rotate-keys, 2FA, export, delete
        ciphers.rs           — cipher CRUD + restore + permanent + move-to-org
        folders.rs           — folder CRUD + permanent
        sync.rs              — delta sync (ciphers + sends + attachments + orgs)
        push.rs              — SSE stream
        attachments.rs       — tus 1.0 upload + download + delete
        sends.rs             — owner CRUD + public anonymous /access
        orgs.rs              — full M4 lifecycle (create / invite / accept / …)
        collections.rs       — org collection CRUD + permissions
        policies.rs          — org policies (M4.6)
        two_factor.rs        — TOTP + recovery codes (M2.22)
        two_factor_webauthn.rs — WebAuthn / FIDO2 passkeys (M2.23a)
        service_accounts.rs  — org-scoped machine identities (M2.5)
        web_app.rs           — SPA mount at /web/* and /send/*
        health.rs / api.rs / root.rs — small endpoints
    tests/                   — full integration suite
  hekate-cli/                  — `hekate` command-line client
    src/commands/            — one file per subcommand (login, add, send, …)
clients/
  extension/                 — Hekate browser extension (Chromium MV3)
    popup/                   — popup.html + popup.css + popup.js + WASM core
    icons/                   — 16/32/48/128 PNG + master SVG
    background.js            — MV3 service worker (SSE refresh, alarms)
  web/                       — Hekate web vault (SolidJS + Vite)
    src/                     — main.tsx + routes/{recipient,owner}/ + lib/ + ui/
    public/                  — icons + WASM core staging (regenerated)
    vite.config.ts           — base "./", Solid plugin
migrations/                  — 0001_baseline.sql (single SQLite + Postgres baseline)
docs/                        — design / status / api / development /
                               browser-extension / m4-organizations / ...
docker/dev.dockerfile        — dev image with rust + clippy + rustfmt + wasm-bindgen
Dockerfile                   — multi-stage release: rust-builder + node-builder + distroless
docker-compose.yml           — Postgres + server + Traefik labels + hekate_attachments volume
docker-compose.sqlite.yml    — single-binary SQLite mode
```

## Common workflows (all via Docker)

```bash
make up           # bring up Postgres + server (default)
make up-sqlite    # SQLite-only single binary
make ready        # curl /health/ready
make logs         # tail server logs
make down         # tear down both stacks

make build        # cargo build --release inside Docker
make cli          # build just target/release/hekate (Linux ELF)
make wasm         # build hekate-core for wasm32 + wasm-bindgen → dist/wasm/
make extension    # wasm + stage bindings into clients/extension/wasm/
make web          # build the SolidJS web vault → clients/web/dist/
make web-dev      # `vite dev` on :5173 (live-reload SPA against running server)
make check        # cargo check --all-targets
make test         # cargo test --all-targets
make fmt          # rustfmt
make clippy       # clippy --all-targets -D warnings
make shell        # interactive shell in dev image
make image        # build the production runtime image (server + bundled SPA)
make image-size   # report compressed image size
```

The first invocation of any cargo target builds the dev image; subsequent runs reuse it. Cargo caches (registry, git, target) live in named Docker volumes (`hekate_cargo_registry`, `hekate_cargo_git`, `hekate_target`) so iteration is fast. `make clean` drops them.

### Docker Desktop memory

Bump Docker Desktop's memory ceiling to **at least 16 GB** (24 GB recommended) before running `make test`. Settings → Resources → Memory → Apply & Restart.

`hekate-server`'s test target compiles ~70 integration test binaries (orgs, ciphers, sends, attachments, webauthn, …) against a large transitive dep graph (`reqwest`, `webauthn-rs`, `sqlx`, `axum`, `keepass`, `chacha20poly1305`, …). Cargo links several of those binaries in parallel; each `ld` invocation peaks at multiple GB. The 8 GB Docker Desktop default OOM-kills the linker mid-`make test` with errors like:

```
collect2: fatal error: ld terminated with signal 9 [Killed]
error: could not compile `hekate-server` (test "rotate_keys") due to 1 previous error
```

`cargo clippy` and individual `cargo test --test <name>` runs link far less in parallel and stay under the cap, so the failure mode is specifically full-workspace test builds. CI runners (`ubuntu-latest`) have the headroom and don't hit it.

## Configuration

`hekate-server` reads config in this order (later overrides earlier):
1. `hekate.toml` if present in the working directory
2. `HEKATE_*` environment variables

Keys:

| Key | Default | Notes |
|---|---|---|
| `HEKATE_LISTEN` | `0.0.0.0:8080` | bind address |
| `HEKATE_DATABASE_URL` | `sqlite:///data/hekate.sqlite?mode=rwc` | `sqlite://path` or `postgres://user:pw@host/db` |
| `HEKATE_FAKE_SALT_PEPPER` | random per process | base64-no-pad. Set explicitly in production for stable prelogin responses across restarts. |
| `RUST_LOG` | `info,hekate_server=debug,sqlx=warn` | tracing filter |
| `HEKATE_WEB_DIR` | `None` (dev) / `/app/web-dist` (prod image) | Filesystem root for the bundled SolidJS web vault. When set, `hekate-server` serves the SPA at `/web/*` (owner mode) and `/send/*` (recipient mode for share links). When unset, both prefixes serve a small placeholder page. |
| `HEKATE_ATTACHMENTS_DIR` | `/data/attachments` | Filesystem root for the local-FS blob backend (M2.24). Created on bootstrap if missing. Cloud deployments will swap to S3 in M2.24a. |
| `HEKATE_WEBAUTHN_RP_ID` | `hekate.localhost` | Relying-party ID for FIDO2 passkeys (M2.23). Must match the eTLD+1 of the browser-facing origin. Self-host: set to your domain. |
| `HEKATE_WEBAUTHN_RP_ORIGIN` | `http://hekate.localhost` | Browser-facing origin URL. HTTPS in production except `localhost` / `*.localhost`. |

## Database

- Migrations: plain SQL in `migrations/`, run automatically on startup via `Db::migrate()` (a thin wrapper over `sqlx::migrate!()`).
- The migration files must be **portable across SQLite and Postgres** — stick to TEXT columns for IDs/timestamps, `INTEGER` for booleans, and avoid driver-specific syntax. Defaults like `CURRENT_TIMESTAMP` format differently across drivers; prefer setting timestamps explicitly from chrono RFC3339 in handlers.
- Enable `EXPLAIN`-time access from the dev shell:
  ```
  docker compose exec postgres psql -U hekate -d hekate
  ```

## Adding a new endpoint

Standard pattern:

1. Create or extend a module under `crates/hekate-server/src/routes/`.
2. Define `pub fn router() -> Router<AppState>` returning the route(s).
3. Add the module to `routes/mod.rs` and `.merge(routes::your_module::router())` in `lib.rs::build_router`.
4. For auth-required routes, add `user: AuthUser` to the handler signature.
5. For DB access, use `state.db.pool()` with `sqlx::query` / `query_as`.
6. For push, call `state.push.publish(PushEvent { ... })` after successful writes.
7. Errors: return `Result<T, ApiError>` (defined in `routes/accounts.rs`).
8. Tests: prefer integration in `crates/hekate-server/tests/` over unit tests for endpoints; use `tower::ServiceExt::oneshot` against `build_router(state)`.

## Testing

- Run with `make test`. Targets `--all-targets` so doctests, integration tests, and binaries all compile.
- Integration tests use `sqlite::memory:` — `Db::connect` constrains the pool to one connection automatically when it sees an in-memory URL.
- Add tests for: each new endpoint's happy path, an error case (auth failure, validation), and any state-machine edges (conflict, replay, etc.).
- Property tests (`proptest`) and Jepsen-style sync tests are reserved for M2/M7 hardening.

## Cutting commits

Per the global engineering standards:

- One concern per commit — no mixing features + refactors + formatting.
- Commit message:
  ```
  <type>: <short summary>

  <body explaining why>
  ```
  Types: `feat`, `fix`, `refactor`, `docs`, `test`, `chore`, `build`, `ci`, `security`, `perf`.
- Stage files explicitly (`git add file1 file2`), not `git add -A`.
- Run `make test && make clippy` before committing.
- After landing a feature, update `CHANGELOG.md` and `docs/status.md` in the same commit (or a documentation follow-up). The implementation status doc is part of the work.

## Ports and routing

- Direct: `http://localhost:8088/...`
- Via local Traefik: `http://hekate.localhost/...` (Traefik labels in `docker-compose.yml`, attaches to the external `apps` network).
- Internal container port is `8080`.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `port 8080 already allocated` | Local Traefik dashboard is on 8080. We map host 8088 → container 8080. |
| Tests hang on a flaky base64 char | Refresh tokens use URL-safe base64; if you add another token type, do the same. |
| Tombstone watermarks comparing wrong | Don't rely on Postgres `CURRENT_TIMESTAMP` defaults — set timestamps explicitly via `chrono::Utc::now().to_rfc3339()`. |
| Migration failed in CI but not locally | Use only portable SQL (TEXT/INTEGER, `CREATE TABLE IF NOT EXISTS`, no driver-specific types). |
| `feature edition2024 required` build error | Bump the Rust toolchain; we track `rust:slim-bookworm` (latest stable). |
