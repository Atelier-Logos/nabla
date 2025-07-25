FROM rust:1.88-slim@sha256:38bc5a86d998772d4aec2348656ed21438d20fcdce2795b56ca434cf21430d89 AS builder
WORKDIR /app

# Set up build arguments and environment variables BEFORE copying code
ARG LICENSE_SIGNING_KEY
ENV LICENSE_SIGNING_KEY=$LICENSE_SIGNING_KEY

COPY . .
RUN apt-get update && apt-get install -y --no-install-recommends pkg-config libssl-dev ca-certificates && rm -rf /var/lib/apt/lists/*
RUN cargo build --release

FROM rust:1.88-slim@sha256:38bc5a86d998772d4aec2348656ed21438d20fcdce2795b56ca434cf21430d89 AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libacl1 && rm -rf /var/lib/apt/lists/*
RUN cargo install --locked cargo-audit --version 0.21.2
COPY --from=builder /app/target/release/nabla /usr/local/bin/nabla
ENTRYPOINT ["nabla"]