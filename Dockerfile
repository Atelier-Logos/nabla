# Set up build arguments and environment variables
ARG LICENSE_SIGNING_KEY
ARG FIPS_MODE=false
ARG FIPS_VALIDATION=false

# Conditional base image selection for builder stage
FROM cgr.dev/chainguard/rust:latest AS builder-fips
FROM rust:1.88-slim@sha256:38bc5a86d998772d4aec2348656ed21438d20fcdce2795b56ca434cf21430d89 AS builder-standard

FROM builder-${FIPS_MODE:+fips}${FIPS_MODE:+}${FIPS_MODE:-standard} AS builder
WORKDIR /app

ENV LICENSE_SIGNING_KEY=$LICENSE_SIGNING_KEY
ENV FIPS_MODE=$FIPS_MODE
ENV FIPS_VALIDATION=$FIPS_VALIDATION

COPY . .
# Install dependencies only for standard (non-FIPS) builds - Chainguard images include these
RUN if [ "$FIPS_MODE" = "false" ]; then \
    apt-get update && apt-get install -y --no-install-recommends pkg-config libssl-dev ca-certificates && rm -rf /var/lib/apt/lists/*; \
    fi
RUN cargo build --release

# Conditional base image selection for runtime stage
FROM cgr.dev/chainguard/static:latest AS runtime-fips
FROM rust:1.88-slim@sha256:38bc5a86d998772d4aec2348656ed21438d20fcdce2795b56ca434cf21430d89 AS runtime-standard

FROM runtime-${FIPS_MODE:+fips}${FIPS_MODE:+}${FIPS_MODE:-standard} AS runtime

# Install runtime dependencies only for standard (non-FIPS) builds
RUN if [ "$FIPS_MODE" = "false" ]; then \
    apt-get update && apt-get install -y --no-install-recommends ca-certificates libacl1 && rm -rf /var/lib/apt/lists/* && \
    cargo install --locked cargo-audit --version 0.21.2; \
    fi

COPY --from=builder /app/target/release/nabla /usr/local/bin/nabla

# Set FIPS environment variables
ENV FIPS_MODE=$FIPS_MODE
ENV FIPS_VALIDATION=$FIPS_VALIDATION

ENTRYPOINT ["nabla"]