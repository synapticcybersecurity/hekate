# Dev image for `make check / test / fmt / clippy / shell / wasm` — has
# rustup, no binary build. Mounted source from the host so iteration is fast.

FROM rust:slim-bookworm
WORKDIR /workspace

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        pkg-config libssl-dev git make ca-certificates curl \
 && rm -rf /var/lib/apt/lists/* \
 && rustup component add rustfmt clippy \
 && rustup target add wasm32-unknown-unknown \
 && cargo install --locked wasm-bindgen-cli@0.2.121

# Pre-warm the cargo registry cache by name. Real fetch happens at runtime
# against the bind-mounted source.
ENV CARGO_HOME=/usr/local/cargo

CMD ["bash"]
