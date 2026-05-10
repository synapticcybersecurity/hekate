# syntax=docker/dockerfile:1.7

# ---- chef: base image with cargo-chef ----------------------------------------
FROM rust:slim-bookworm AS chef
WORKDIR /app
RUN apt-get update \
 && apt-get install -y --no-install-recommends pkg-config libssl-dev \
 && rm -rf /var/lib/apt/lists/* \
 && cargo install cargo-chef --version 0.1.68 --locked

# ---- planner: compute dependency recipe --------------------------------------
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ---- builder: build dependencies, then the workspace -------------------------
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
# This step only rebuilds when Cargo.toml/Cargo.lock change.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo chef cook --release --recipe-path recipe.json

# Add the wasm32 target + wasm-bindgen-cli so the same builder produces
# the WASM core that the web vault SPA bundles. Pinned to the same
# version as docker/dev.dockerfile so dev / prod artifacts match.
RUN rustup target add wasm32-unknown-unknown \
 && cargo install --locked wasm-bindgen-cli@0.2.121

COPY . .
ARG GIT_SHA=dev
ENV HEKATE_GIT_SHA=${GIT_SHA}
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release --bin hekate-server \
 && cargo build --release --target wasm32-unknown-unknown -p hekate-core \
 && rm -rf /staged-wasm \
 && wasm-bindgen --target web --out-dir /staged-wasm \
        target/wasm32-unknown-unknown/release/hekate_core.wasm \
 && cp /app/target/release/hekate-server /hekate-server \
 && install -d -m 0700 /staged-data

# ---- web-builder: bundle the SolidJS SPA -------------------------------------
FROM node:22-alpine AS web-builder
WORKDIR /app/clients/web
# Install deps first (cacheable layer keyed only on package.json /
# lockfile) so source edits don't reinstall node_modules every build.
COPY clients/web/package.json clients/web/package-lock.json ./
RUN npm ci --no-audit --no-fund

COPY clients/web/ ./
# WASM core bindings produced in the rust builder above; staged into
# `public/wasm/` so Vite's public-dir pass-through copies them verbatim
# into `dist/wasm/` (where the SPA's runtime loader expects them).
COPY --from=builder /staged-wasm ./public/wasm
RUN npm run build

# ---- runtime: distroless/cc, no shell, ~22 MB base ---------------------------
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime
WORKDIR /app

# Pre-create /data owned by the nonroot UID baked into distroless (uid=65532).
# Docker propagates the directory's owner+mode to a fresh named volume on
# first mount, so without this the SQLite path fails with EACCES on /data.
# (Distroless has no shell, so we stage an empty dir from the builder.)
COPY --from=builder --chown=65532:65532 /hekate-server /usr/local/bin/hekate-server
COPY --from=builder --chown=65532:65532 /staged-data /data
COPY --from=web-builder --chown=65532:65532 /app/clients/web/dist /app/web-dist

USER nonroot:nonroot
EXPOSE 8080
ENV HEKATE_LISTEN=0.0.0.0:8080 \
    HEKATE_DATABASE_URL=sqlite:///data/hekate.sqlite?mode=rwc \
    HEKATE_WEB_DIR=/app/web-dist \
    RUST_LOG=info,hekate_server=debug,sqlx=warn

ENTRYPOINT ["/usr/local/bin/hekate-server"]
