# Project Standards

This file extends the global `~/.claude/CLAUDE.md` and defines conventions specific to **hekate** — a self-hosted, Bitwarden-compatible password/secrets manager (pre-alpha). It only covers what changes behavior here; the global standards still apply. For the full contributor workflow see `CONTRIBUTING.md`; for design/threat docs see `docs/`.

---

## Protocol-Frozen Identifiers (read first)

There is a deliberate **brand-vs-code-name split**, and getting it wrong corrupts stored data:

- Code-level identifiers use `hekate` — Cargo packages (`hekate-core`, `hekate-server`, `hekate-cli`), binaries (`hekate-server`, `hekate`), env vars (`HEKATE_*`).
- **Protocol-frozen byte literals keep their original `pmgr-…` / `pmgr_*` prefix and the `PMGRA1` magic** — every `b"pmgr-…"` AAD string, signature DST, and token wire format (`pmgr_sat_*`, `pmgr_pat_*`), plus the `PMGRA1` chunked-AEAD magic. These are **baked into existing ciphertexts**.

**Never rename a `pmgr`/`PMGRA1` literal "for consistency."** Changing one of these byte strings breaks AEAD verification and makes previously-encrypted vault data undecryptable. See the README and `docs/design.md` for the full split.

---

## Crypto-Core Sensitivity

`hekate-core` holds the cryptography (KDF, `EncString` envelope, vault manifest, the `PMGRA1` chunked-AEAD attachment/Send format, signcryption, token formats). Before changing anything in the crypto path:

- Read `docs/design.md` and `docs/threat-model-gaps.md` first.
- Treat any change to an on-the-wire or at-rest format as a decision worth recording (and ask before changing one) — format changes are migration/compat events, not refactors.

---

## Security & Secure Coding

Hekate is a password manager built on custom crypto. Before touching key material, AEAD call sites, auth, or any client secret-handling path, read [`docs/secure-coding.md`](docs/secure-coding.md) — the authoritative checklist. The crypto non-negotiables (the no-panic and `clippy`/`deny`/`audit` rules below also apply):

- **Constant-time comparison** for secrets — tokens, MACs, auth tags, and password-hash outputs go through `subtle` (`ConstantTimeEq`), never `==`.
- **Zero key material** — wrap keys, passwords, and derived secrets in `zeroize` / `ZeroizeOnDrop`; don't leave plaintext copies behind `String`/`Vec` reallocations.
- **Don't hand-roll crypto** — use the vetted RustCrypto stack; CSPRNG (`getrandom` / `OsRng`) for anything security-bearing; never reuse a `(key, nonce)` pair; pass the matching AAD on encrypt *and* decrypt.
- **Never log or surface secrets** — no plaintext, keys, or tokens in logs, error messages, or `Debug` impls (redact secret fields).

**Publish gate:** no public binary (Apple `.app`, app store, signed release) ships until these standards are met and a comprehensive security analysis is complete — see [`docs/followups.md`](docs/followups.md) and [`docs/status.md`](docs/status.md) M7.

---

## Stack

Rust (edition 2021, rustc 1.89), Cargo workspace. axum / tower / hyper server. Persistence via `sqlx` over `AnyPool` — **SQLite by default, Postgres optional**. Docker Compose.

---

## Docker-First Development (`make`)

All `cargo` work runs inside the dev image via `make` targets — don't assume a host Rust toolchain.

```bash
make up          # hekate-server + Postgres
make up-sqlite   # hekate-server alone, SQLite backend
make down / logs / ready / ps
make build cli wasm extension web web-dev desktop   # build artifacts
```

The dual-backend split is real: `make up` (Postgres) vs `make up-sqlite` — test changes that touch persistence against both where it matters, since `sqlx` runs over `AnyPool`.

---

## Code Style

- **Formatting:** `cargo fmt` (CI enforces `cargo fmt --all -- --check` → `make fmt-check`).
- **Linting:** `cargo clippy --workspace -- -D warnings` → `make clippy`; clippy warnings are errors.
- **Naming:** standard Rust — `snake_case` items, `PascalCase` types/traits, `SCREAMING_SNAKE_CASE` consts. (Protocol literals are the documented exception above.)

---

## Error Handling, Async, Rust Rules

- **Library crates use `thiserror`; binaries use `anyhow`.** Propagate with `?`.
- **No `.unwrap()`/`.expect()`/`panic!` in library/service code** (`hekate-core`, server/service layers) — return `Result`. Acceptable only in tests, `main()` startup, or provably-impossible invariants (document why).
- **Tokio runtime;** spawned tasks must have an owner (keep/await/abort the `JoinHandle`); never block the async executor with sync I/O — use `spawn_blocking`.
- **`unsafe` is rare** — isolate with a `// SAFETY:` comment if unavoidable. Structured logging via `tracing`, not `println!`.

---

## Dependency Management

- `Cargo.toml` + `Cargo.lock` committed (workspace).
- Supply-chain gates exist and must stay green: `make deny` (`cargo deny check` via `deny.toml`) and `make audit` (`cargo audit`, `.cargo/audit.toml`). Run them before adding a dependency.
- `hekate-core` also targets `wasm32` (for the web vault and browser extension) — keep it `no_std`-friendly where it must compile to wasm; don't pull native-only deps into the wasm path.

---

## Commits & Contribution

- **Sign off every commit: `git commit -s`** (DCO). Unsigned commits are bounced — this is non-negotiable here.
- **Commit style:** `<type>(<scope>): <short summary>` — types per global; **scope** is a crate/client (`core`, `server`, `cli`, `popup`, `web`, `extension`) or a milestone tag (e.g. `GH #1`, `M4.5b-web`).

---

## Validation Commands

```bash
make fmt-check    # cargo fmt --all -- --check
make clippy       # cargo clippy --workspace -- -D warnings
make test         # cargo test --workspace
make deny audit   # supply-chain gates
```

CI runs `fmt --check` + `clippy -D warnings` + `test`. All must pass before marking work complete.

---

## Project Architecture

**Application type:** Self-hosted, Bitwarden-compatible password/secrets manager (pre-alpha).

**Workspace crates:**
- `hekate-core/` — domain + cryptography; also compiles to `wasm32` for the web/extension clients
- `hekate-server/` — axum HTTP server binary (`hekate-server`)
- `hekate-cli/` — CLI binary (`hekate`)

**Clients:** `clients/web/` (SolidJS web vault, wasm-backed), browser extension (`make extension` / Firefox MV3), `clients/desktop/` (Tauri — in progress).

**Ports:**
| Service | Port |
|---|---|
| hekate-server | 8080 (compose exposes 8088→8080 via Traefik at `hekate.localhost`) |
| Postgres | 5432 |

**Key decisions:**
- Persistence: `sqlx` over `AnyPool` (SQLite default / Postgres optional); SQL migrations in `migrations/`
- Auth tokens: JWT HS256 (EdDSA deferred); token wire formats are protocol-frozen (see top)
- Realtime: SSE push over `tokio::broadcast`
- Config: figment; rate-limiting: `governor`
- Crypto: RustCrypto stack; `PMGRA1` chunked-AEAD for attachments/Sends
