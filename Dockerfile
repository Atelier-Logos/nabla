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
RUN rustup target add x86_64-unknown-linux-musl
RUN apt-get update && apt-get install -y musl-tools && \
    cargo build --release --bin ferropipe-audit --target x86_64-unknown-linux-musl

# We do not need the Rust toolchain to run the binary!
FROM scratch
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/ferropipe-audit /ferropipe-audit
ENTRYPOINT ["/ferropipe-audit"]
