# Contributing to Hekate

Thanks for your interest. This is a pre-alpha project under active
development; the contribution flow is still light.

## Before you start

- **Open an issue first** for anything beyond a small fix or doc
  tweak. Drive-by PRs that change architecture, add new endpoints,
  or rework the wire format will likely get pushed back to discuss
  scope in an issue first.
- **One concern per PR.** Bug fixes don't carry refactors;
  refactors don't carry feature work. Mixed PRs are slow to review.
- **Read [`docs/design.md`](docs/design.md) and
  [`docs/status.md`](docs/status.md)** if your change touches the
  cryptographic core, the manifest, or org/share semantics.

## Reporting security vulnerabilities

**Please don't open a public issue for security problems.** See
[`SECURITY.md`](SECURITY.md) for the private disclosure channel.

## Dev setup

The project is Docker-first; you don't need a host Rust toolchain.

```bash
make build       # cargo build (release)
make test        # cargo test --workspace
make check       # cargo check --workspace
make fmt         # cargo fmt --all
make clippy      # cargo clippy --workspace -- -D warnings
make wasm        # build hekate-core as WASM
make extension   # build wasm + copy into clients/extension/
make web         # build the SolidJS web vault
make up          # bring up Postgres + server (compose)
make down        # tear down
```

The full target list is `make help`.

If you'd rather use a host Rust toolchain, the workspace builds on
stable Rust ≥ 1.89 (declared in [`Cargo.toml`](Cargo.toml)).

## Before opening a PR

Run, at minimum:

```bash
make fmt         # auto-format
make clippy      # lint with -D warnings
make test        # full workspace tests
```

CI runs all three plus `cargo fmt --all -- --check`. PRs that fail
CI won't be reviewed until they're green.

## Commit style

We use a lightly-conventional prefix:

```
<type>(<scope>): <short summary>
```

Types observed in `git log`: `feat`, `fix`, `refactor`, `docs`,
`test`, `chore`, `build`, `ci`, `security`, `perf`. Scope is
usually the crate or client (`core`, `server`, `cli`, `popup`,
`web`, `extension`) or a milestone tag (`M4.5b-web`, `GH #1`).

Examples from history:
```
feat(popup): GH #1 — passkey approval UI + create/get builders
fix(server): defer roster advance until accept (GH #2)
docs(followups): GH #1 — record commits 1–4 and the smoke debt
chore: cargo fmt --all
```

Body should explain **why**, not just what. Reference the issue
(`Closes #N` or `Refs #N`) when applicable.

## PR checklist

Your PR description should cover:

- **What** changed and **why**.
- The linked issue number.
- **Test plan** — what you ran, what new tests you added, what you
  couldn't validate (and why).
- **Risks / tradeoffs** — anything reviewers should poke at.
- **Migration / operational notes** if applicable (schema changes,
  config changes, env vars added).

`.github/PULL_REQUEST_TEMPLATE.md` mirrors this; GitHub will
pre-fill your PR body.

## Testing expectations

- Every new code path / branch / error case should have a test.
- Cryptographic changes need byte-stable test vectors (look at
  `crates/hekate-core/src/manifest.rs` and `passkey.rs` for examples).
- For client-only changes, hand-smoke against the running stack and
  document what you ran in `docs/followups.md` if you couldn't add
  an automated test.

## Sign-off (Developer Certificate of Origin)

All commits must be signed off with `git commit -s`, asserting
the [Developer Certificate of Origin](https://developercertificate.org/).
This adds a `Signed-off-by:` trailer to your commit message and
is how you certify that you wrote the patch (or have the right to
contribute it under the project's license). Pull requests with
unsigned commits will be asked to amend.

There is no Contributor License Agreement.

## Licensing

Hekate is **AGPL-3.0-or-later**. By submitting a contribution you
agree it can be distributed under that license.

This means: if you run a modified Hekate server as a network
service, the AGPL requires you to make your modifications available
to its users. That's intentional — the AGPL is the project's
business model.
