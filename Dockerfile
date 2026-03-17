# --- Build Stage ---
FROM rust:slim-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    libssl-dev \
    pkg-config \
    libsasl2-dev \
    libldap2-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the entire workspace
COPY . .

# Build the nxc binary in release mode
RUN cargo build --release -p nxc

# --- Runtime Stage ---
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libssl3 \
    libldap-2.5-0 \
    libsasl2-2 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the binary from the builder stage
COPY --from=builder /app/target/release/nxc /usr/local/bin/nxc

# Create a non-root user (good practice)
RUN useradd -ms /bin/bash nxcuser
USER nxcuser

# Use the telegram subcommand by default
ENTRYPOINT ["nxc", "telegram"]
