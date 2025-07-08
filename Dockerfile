FROM rust:1.82-slim AS builder
WORKDIR /app
COPY . .
RUN apt-get update && apt-get install -y --no-install-recommends pkg-config libssl-dev ca-certificates && rm -rf /var/lib/apt/lists/*
RUN cargo build --release

ARG DATABASE_URL
ENV DATABASE_URL=${DATABASE_URL}

FROM rust:1.82-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libacl1 && rm -rf /var/lib/apt/lists/*
RUN cargo install --locked cargo-audit --version 0.21.2
COPY --from=builder /app/target/release/ferropipe-audit /usr/local/bin/ferropipe-audit
ENTRYPOINT ["ferropipe-audit"]