# Build stage
FROM rust:1.75 as builder

# Install system dependencies needed for cargo-audit and cargo-license
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libpq-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install cargo tools
RUN cargo install cargo-audit cargo-license sqlx-cli

WORKDIR /app

# Copy manifest files
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY src ./src
COPY migrations ./migrations

# Build the application
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libssl3 \
    libpq5 \
    ca-certificates \
    git \
    tar \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Rust and Cargo for runtime analysis
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Install cargo tools in runtime
RUN cargo install cargo-audit cargo-license

WORKDIR /app

# Copy the built binary
COPY --from=builder /app/target/release/ferropipe-audit ./
COPY --from=builder /app/migrations ./migrations

# Create a non-root user
RUN useradd -r -s /bin/false ferropipe
RUN chown ferropipe:ferropipe /app/ferropipe-audit

USER ferropipe

EXPOSE 3001

CMD ["./ferropipe-audit"] 