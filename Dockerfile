FROM rust:1.88-slim@sha256:38bc5a86d998772d4aec2348656ed21438d20fcdce2795b56ca434cf21430d89 AS builder
WORKDIR /app

# Set up build arguments and environment variables
ARG LICENSE_SIGNING_KEY
ARG FIPS_MODE=false
ARG FIPS_VALIDATION=false
ENV LICENSE_SIGNING_KEY=$LICENSE_SIGNING_KEY
ENV FIPS_MODE=$FIPS_MODE
ENV FIPS_VALIDATION=$FIPS_VALIDATION

COPY . .
RUN apt-get update && apt-get install -y --no-install-recommends pkg-config libssl-dev ca-certificates && rm -rf /var/lib/apt/lists/*
RUN cargo build --release

FROM rust:1.88-slim@sha256:38bc5a86d998772d4aec2348656ed21438d20fcdce2795b56ca434cf21430d89 AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libacl1 && rm -rf /var/lib/apt/lists/*
RUN cargo install --locked cargo-audit --version 0.21.2
COPY --from=builder /app/target/release/nabla /usr/local/bin/nabla

# Set FIPS environment variables
ENV FIPS_MODE=false
ENV FIPS_VALIDATION=false

ENTRYPOINT ["nabla"]