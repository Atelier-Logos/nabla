FROM rust:1.88-slim@sha256:38bc5a86d998772d4aec2348656ed21438d20fcdce2795b56ca434cf21430d89 AS builder
WORKDIR /app

# Set up build arguments and environment variables
ARG LICENSE_SIGNING_KEY
ARG FIPS_MODE=false
ARG FIPS_VALIDATION=false
ENV LICENSE_SIGNING_KEY=$LICENSE_SIGNING_KEY
ENV FIPS_MODE=$FIPS_MODE
ENV FIPS_VALIDATION=$FIPS_VALIDATION

# Install git and other dependencies
RUN apt-get update && apt-get install -y --no-install-recommends git pkg-config libssl-dev ca-certificates && rm -rf /var/lib/apt/lists/*

# Copy the main project files (excluding the enterprise submodule)
COPY Cargo.toml Cargo.lock ./
COPY src/ ./src/
COPY public/ ./public/
COPY tests/ ./tests/

# Remove the enterprise submodule directory if it exists
RUN rm -rf src/enterprise

# Clone the enterprise repository directly
RUN git clone https://github.com/Atelier-Logos/nabla-enterprise.git src/enterprise && \
    cd src/enterprise && \
    git checkout 2158ca657115b890fa1bcd3407a5bdf566e33b30

# Build the project
RUN cargo build --release

FROM rust:1.88-slim@sha256:38bc5a86d998772d4aec2348656ed21438d20fcdce2795b56ca434cf21430d89 AS runtime
WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*

# Copy the built binaries
COPY --from=builder /app/target/release/nabla /usr/local/bin/
COPY --from=builder /app/target/release/test-middleware /usr/local/bin/
COPY --from=builder /app/target/release/test-deployment-modes /usr/local/bin/

# Copy public assets
COPY --from=builder /app/public /app/public

# Set the default command
CMD ["nabla"]