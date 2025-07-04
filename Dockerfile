FROM lukemathwalker/cargo-chef:latest-rust-1 AS chef
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
# Build dependencies - this is the caching Docker layer!
RUN cargo chef cook --release --recipe-path recipe.json
# Build application
COPY . .
RUN apt-get update && apt-get install -y pkg-config libssl-dev git && \
    cargo build --release --bin ferropipe-audit && \
    cargo install cargo-audit --version 0.21.2 --locked && \
    cargo install cargo-license --version 0.6.1 --locked && \
    git clone --depth 1 https://github.com/rustsec/advisory-db /usr/local/cargo/advisory-db

FROM debian:bookworm-slim AS runtime
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates libssl3 cargo rustc git && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/ferropipe-audit /usr/local/bin/ferropipe-audit
COPY --from=builder /usr/local/cargo/bin/cargo-audit        /usr/local/bin/cargo-audit
COPY --from=builder /usr/local/cargo/bin/cargo-license      /usr/local/bin/cargo-license
COPY --from=builder /usr/local/cargo/advisory-db       /usr/local/cargo/advisory-db
ENTRYPOINT ["/usr/local/bin/ferropipe-audit"]
