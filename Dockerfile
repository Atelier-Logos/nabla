FROM cgr.dev/chainguard/rust:latest AS builder
WORKDIR /app

# Set up build arguments and environment variables BEFORE copying code
ARG LICENSE_SIGNING_KEY
ENV LICENSE_SIGNING_KEY=$LICENSE_SIGNING_KEY

COPY . .
RUN apt-get update && apt-get install -y --no-install-recommends pkg-config libssl-dev ca-certificates && rm -rf /var/lib/apt/lists/*
RUN cargo build --release

FROM rust:1.82-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libacl1 && rm -rf /var/lib/apt/lists/*
RUN cargo install --locked cargo-audit --version 0.21.2
COPY --from=builder /app/target/release/nabla /usr/local/bin/nabla
ENTRYPOINT ["nabla"]