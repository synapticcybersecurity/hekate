# hekate — Docker-first developer workflow.
# All targets run inside Docker so no host Rust toolchain is required.

SHELL := bash
.SHELLFLAGS := -eu -o pipefail -c
.ONESHELL:
.DEFAULT_GOAL := help

# ---- runtime targets (compose) -----------------------------------------------

GIT_SHA := $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)
export GIT_SHA

.PHONY: up
up: ## Start hekate-server + Postgres in the background
	docker compose up -d --build

.PHONY: up-sqlite
up-sqlite: ## Start hekate-server alone with SQLite (no Postgres)
	docker compose -f docker-compose.sqlite.yml up -d --build

.PHONY: down
down: ## Stop and remove containers
	docker compose -f docker-compose.yml down
	docker compose -f docker-compose.sqlite.yml down 2>/dev/null || true

.PHONY: logs
logs: ## Tail server logs
	docker compose logs -f hekate-server

.PHONY: ps
ps: ## Show compose status
	docker compose ps

.PHONY: ready
ready: ## Curl the readiness endpoint
	@curl -fsS http://localhost:8088/health/ready | jq . || (echo "not ready" && exit 1)

# ---- build / test (one-shot dev image) ---------------------------------------

DEV_IMAGE := hekate-dev:latest
DEV_RUN := docker run --rm \
	-v "$$PWD":/workspace \
	-v hekate_cargo_registry:/usr/local/cargo/registry \
	-v hekate_cargo_git:/usr/local/cargo/git \
	-v hekate_target:/workspace/target \
	-w /workspace \
	$(DEV_IMAGE)

.PHONY: dev-image
dev-image: ## Build the dev image (rustup + clippy + rustfmt)
	docker build -f docker/dev.dockerfile -t $(DEV_IMAGE) docker

.PHONY: build
build: dev-image ## cargo build --release inside Docker
	$(DEV_RUN) cargo build --release

.PHONY: cli
cli: dev-image ## Build the hekate CLI binary into target/release/hekate
	$(DEV_RUN) cargo build --release --bin hekate
	@echo "Built: target/release/hekate (Linux ELF, run inside Docker or rebuild on host)"

# ---- CLI runner (saves typing the long `docker run` for every command) -------
#
# `make hekate ARGS="…"` wraps the dev image + persistent Postgres-network +
# CLI state volume + the pre-built binary. Use whenever you'd otherwise paste
# the giant `docker run` block.
#
# Examples:
#   make hekate ARGS="register --server http://hekate-server:8080 --email me@x.test"
#   make hekate ARGS="login    --server http://hekate-server:8080 --email me@x.test"
#   make hekate ARGS="list"
#   make hekate ARGS="org create --name 'Smoke Org'"
#
# State (tokens, pinned peers, prefs) lives in the named `hekate_cli_state`
# volume so successive invocations stay logged in.
.PHONY: hekate
hekate: cli ## Run a hekate CLI command (use ARGS="…")
	@if [ -z "$(ARGS)" ]; then \
	  echo "usage: make hekate ARGS=\"<command> [flags]\""; \
	  echo "examples:"; \
	  echo "  make hekate ARGS=\"register --server http://hekate-server:8080 --email me@x.test\""; \
	  echo "  make hekate ARGS=\"login    --server http://hekate-server:8080 --email me@x.test\""; \
	  echo "  make hekate ARGS=\"list\""; \
	  exit 1; \
	fi
	docker run --rm -it \
	  -v "$$PWD":/workspace \
	  -v hekate_cargo_registry:/usr/local/cargo/registry \
	  -v hekate_target:/workspace/target \
	  -v hekate_cli_state:/tmp/hekate-cli \
	  -w /workspace \
	  -e XDG_CONFIG_HOME=/tmp/hekate-cli -e HOME=/tmp \
	  --network hekate_default \
	  $(DEV_IMAGE) \
	  /workspace/target/release/hekate $(ARGS)

.PHONY: wasm
wasm: dev-image ## Build hekate-core for wasm32 + run wasm-bindgen → dist/wasm/
	$(DEV_RUN) bash -c '\
	    cargo build --release --target wasm32-unknown-unknown -p hekate-core && \
	    rm -rf dist/wasm && mkdir -p dist/wasm && \
	    wasm-bindgen --target web --out-dir dist/wasm \
	        target/wasm32-unknown-unknown/release/hekate_core.wasm && \
	    ls -la dist/wasm'

.PHONY: extension
extension: wasm ## Build wasm and copy bindings into the browser extension
	rm -rf clients/extension/wasm
	mkdir -p clients/extension/wasm
	cp dist/wasm/hekate_core_bg.wasm clients/extension/wasm/
	cp dist/wasm/hekate_core.js clients/extension/wasm/
	cp dist/wasm/hekate_core.d.ts clients/extension/wasm/
	cp dist/wasm/hekate_core_bg.wasm.d.ts clients/extension/wasm/ 2>/dev/null || true
	@echo "Extension ready: load 'clients/extension' as an unpacked MV3 extension."
	@ls -la clients/extension/wasm

# ---- Firefox MV3 build (#6) --------------------------------------------------
#
# Stages the Chromium extension tree to dist/extension-firefox/, swaps the
# manifest for the Gecko variant (event-page background, no offscreen /
# webAuthenticationProxy permissions), and runs `web-ext lint` to catch
# anything AMO will reject. The passkey-provider feature is intentionally
# absent here — it stays on the Chromium build until Firefox ships
# `browser.webAuthn` (tracked separately as #4).
#
# `web-ext` is invoked via npx so we don't add a root package.json; the
# host needs Node 18+.
.PHONY: extension-firefox
extension-firefox: extension ## Stage + lint the Firefox MV3 unpacked build
	rm -rf dist/extension-firefox
	mkdir -p dist/extension-firefox
	rsync -a clients/extension/ dist/extension-firefox/ \
	    --exclude README.md --exclude COMPILEandDEBUG.md \
	    --exclude offscreen.html --exclude offscreen.js
	cp dist/extension-firefox/manifest.firefox.json dist/extension-firefox/manifest.json
	rm dist/extension-firefox/manifest.firefox.json
	npx --yes web-ext@10 lint --source-dir dist/extension-firefox --no-config-discovery
	@echo "Firefox unpacked build: dist/extension-firefox/"

.PHONY: extension-firefox-zip
extension-firefox-zip: extension-firefox ## Produce AMO-uploadable artifact in dist/
	npx --yes web-ext@10 build \
	    --source-dir dist/extension-firefox \
	    --artifacts-dir dist \
	    --overwrite-dest \
	    --no-config-discovery
	@echo "AMO artifact:"
	@ls -la dist/*.zip

# ---- web vault (SolidJS SPA) -------------------------------------------------
#
# `make web` produces clients/web/dist/, which `hekate-server` mounts at
# /web/* (owner mode) and /send/* (recipient mode) via the
# `routes::web_app` ServeDir. The `public/wasm/` staging copy makes the
# hekate-core bindings visible to Vite's `public/` pass-through. In dev,
# point `HEKATE_WEB_DIR` at clients/web/dist after `make web` to serve it
# without rebuilding the server image.
WEB_NODE_IMAGE := node:22-alpine
WEB_RUN := docker run --rm \
	-v "$$PWD":/workspace \
	-v hekate_web_node_modules:/workspace/clients/web/node_modules \
	-w /workspace/clients/web \
	$(WEB_NODE_IMAGE)

.PHONY: web
web: wasm ## Build the SolidJS web vault into clients/web/dist
	rm -rf clients/web/public/wasm clients/web/dist
	mkdir -p clients/web/public/wasm
	cp dist/wasm/hekate_core_bg.wasm clients/web/public/wasm/
	cp dist/wasm/hekate_core.js clients/web/public/wasm/
	cp dist/wasm/hekate_core.d.ts clients/web/public/wasm/ 2>/dev/null || true
	cp dist/wasm/hekate_core_bg.wasm.d.ts clients/web/public/wasm/ 2>/dev/null || true
	$(WEB_RUN) sh -c 'npm ci --no-audit --no-fund && npm run build'
	@echo "Web vault built: clients/web/dist"
	@ls -la clients/web/dist | head -20

.PHONY: web-dev
web-dev: ## Vite dev server on :5173 (point a browser at http://localhost:5173/)
	rm -rf clients/web/public/wasm
	mkdir -p clients/web/public/wasm
	@if [ -d dist/wasm ]; then \
	  cp dist/wasm/hekate_core_bg.wasm clients/web/public/wasm/; \
	  cp dist/wasm/hekate_core.js clients/web/public/wasm/; \
	else \
	  echo "WARNING: dist/wasm not found — run 'make wasm' first"; \
	fi
	docker run --rm -it \
	  -v "$$PWD":/workspace \
	  -v hekate_web_node_modules:/workspace/clients/web/node_modules \
	  -w /workspace/clients/web \
	  -p 5173:5173 \
	  $(WEB_NODE_IMAGE) \
	  sh -c 'npm ci --no-audit --no-fund && npm run dev -- --host 0.0.0.0'

.PHONY: check
check: dev-image ## cargo check
	$(DEV_RUN) cargo check --all-targets

.PHONY: test
test: dev-image ## cargo test
	$(DEV_RUN) cargo test --all-targets

.PHONY: fmt
fmt: dev-image ## rustfmt
	$(DEV_RUN) cargo fmt --all

.PHONY: fmt-check
fmt-check: dev-image ## rustfmt --check
	$(DEV_RUN) cargo fmt --all -- --check

.PHONY: clippy
clippy: dev-image ## clippy with -D warnings
	$(DEV_RUN) cargo clippy --all-targets -- -D warnings

.PHONY: audit
audit: dev-image ## cargo audit (advisories; see .cargo/audit.toml)
	$(DEV_RUN) bash -c 'cargo install --locked cargo-audit >/dev/null && cargo audit'

.PHONY: deny
deny: dev-image ## cargo deny check (licenses, sources, advisories, bans)
	$(DEV_RUN) bash -c 'cargo install --locked cargo-deny >/dev/null && cargo deny check'

.PHONY: smoke
smoke: dev-image ## End-to-end CLI smoke against a fresh Postgres-backed server
	bash scripts/smoke.sh

.PHONY: smoke-org
smoke-org: dev-image ## M4.1 two-user invite/accept smoke (alice + bob)
	bash scripts/smoke-org.sh

.PHONY: shell
shell: dev-image ## Interactive shell in the dev image
	docker run --rm -it \
		-v "$$PWD":/workspace \
		-v hekate_cargo_registry:/usr/local/cargo/registry \
		-v hekate_cargo_git:/usr/local/cargo/git \
		-v hekate_target:/workspace/target \
		-w /workspace \
		$(DEV_IMAGE) bash

# ---- runtime image (production) ----------------------------------------------

.PHONY: image
image: ## Build the production runtime image (distroless)
	docker build --build-arg GIT_SHA=$(GIT_SHA) -t hekate-server:$(GIT_SHA) -t hekate-server:latest .

.PHONY: image-size
image-size: image
	@docker image ls hekate-server:latest --format '{{.Size}}'

# ---- housekeeping ------------------------------------------------------------

.PHONY: clean
clean: ## Remove cargo target volume
	docker volume rm hekate_target hekate_cargo_registry hekate_cargo_git 2>/dev/null || true

.PHONY: help
help:
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "} {printf "\033[36m%-14s\033[0m %s\n", $$1, $$2}'
