# Use a more specific base image for better caching
FROM rust:1.88-slim@sha256:38bc5a86d998772d4aec2348656ed21438d20fcdce2795b56ca434cf21430d89 AS builder
WORKDIR /app

# Set up build arguments and environment variables
ARG LICENSE_SIGNING_KEY
ARG FIPS_MODE=false
ARG FIPS_VALIDATION=false
ENV LICENSE_SIGNING_KEY=$LICENSE_SIGNING_KEY
ENV FIPS_MODE=$FIPS_MODE
ENV FIPS_VALIDATION=$FIPS_VALIDATION

# Install system dependencies first (this layer will be cached)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    pkg-config \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency files first for better caching
COPY Cargo.toml Cargo.lock ./
COPY src/lib.rs src/lib.rs
COPY src/main.rs src/main.rs
COPY src/config.rs src/config.rs
COPY src/middleware.rs src/middleware.rs
COPY src/binary/mod.rs src/binary/mod.rs
COPY src/routes/mod.rs src/routes/mod.rs
COPY src/cli/mod.rs src/cli/mod.rs
COPY src/enterprise/mod.rs src/enterprise/mod.rs

# Create dummy files for modules that don't exist yet (for dependency resolution)
RUN mkdir -p src/binary src/routes src/cli src/enterprise/providers
RUN touch src/binary/dummy.rs src/routes/dummy.rs src/cli/dummy.rs src/enterprise/providers/dummy.rs

# Build dependencies only (this layer will be cached if dependencies don't change)
RUN cargo build --release --bin nabla

# Now copy the actual source code
COPY . .

# Initialize submodules
RUN git submodule update --init --recursive --force

# Build the actual application (this layer will be cached if source doesn't change)
RUN cargo build --release --bin nabla

# Runtime stage
FROM rust:1.88-slim@sha256:38bc5a86d998772d4aec2348656ed21438d20fcdce2795b56ca434cf21430d89 AS runtime

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libacl1 \
    && rm -rf /var/lib/apt/lists/*

# Install cargo-audit in a separate layer for better caching
RUN cargo install --locked cargo-audit --version 0.21.2

# Copy the binary
COPY --from=builder /app/target/release/nabla /usr/local/bin/nabla

# Set FIPS environment variables
ENV FIPS_MODE=false
ENV FIPS_VALIDATION=false

ENTRYPOINT ["nabla"]