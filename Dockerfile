# LSFTP Docker Build
# Multi-stage build for optimized containers

# Stage 1: Build environment
FROM rust:1.70-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    libtpm2-tools \
    libpcsclite-dev \
    libudev-dev \
    libusb-1.0-0-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy Cargo files
COPY Cargo.toml Cargo.lock ./
COPY lsftp-core/Cargo.toml lsftp-core/
COPY lsftp-client/Cargo.toml lsftp-client/
COPY lsftp-server/Cargo.toml lsftp-server/
COPY lsftp-tools/Cargo.toml lsftp-tools/

# Download dependencies
RUN cargo fetch

# Copy source code
COPY . .

# Build all crates
RUN cargo build --release --all-targets --all-features

# Stage 2: Runtime image for server
FROM ubuntu:20.04 as server

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libssl1.1 \
    libtpm2-tools \
    libpcsclite1 \
    libudev1 \
    libusb-1.0-0 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create LSFTP user
RUN useradd -r -s /bin/false lsftp

# Create directories
RUN mkdir -p /var/lsftp /var/log/lsftp /etc/lsftp
RUN chown -R lsftp:lsftp /var/lsftp /var/log/lsftp /etc/lsftp

# Copy server binary
COPY --from=builder /app/target/release/lsftp-server /usr/local/bin/

# Set permissions
RUN chmod +x /usr/local/bin/lsftp-server

# Switch to non-root user
USER lsftp

# Expose port
EXPOSE 8443

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD lsftp-server --help || exit 1

# Default command
CMD ["lsftp-server", "--address", "0.0.0.0", "--port", "8443", "--root-dir", "/var/lsftp"]

# Stage 3: Runtime image for client
FROM ubuntu:20.04 as client

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libssl1.1 \
    libtpm2-tools \
    libpcsclite1 \
    libudev1 \
    libusb-1.0-0 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create LSFTP user
RUN useradd -r -s /bin/false lsftp

# Copy client binary
COPY --from=builder /app/target/release/lsftp-client /usr/local/bin/

# Set permissions
RUN chmod +x /usr/local/bin/lsftp-client

# Switch to non-root user
USER lsftp

# Default command
CMD ["lsftp-client", "--help"]

# Stage 4: Runtime image for tools
FROM ubuntu:20.04 as tools

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libssl1.1 \
    libtpm2-tools \
    libpcsclite1 \
    libudev1 \
    libusb-1.0-0 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create LSFTP user
RUN useradd -r -s /bin/false lsftp

# Copy tools binary
COPY --from=builder /app/target/release/lsftp-tools /usr/local/bin/

# Set permissions
RUN chmod +x /usr/local/bin/lsftp-tools

# Switch to non-root user
USER lsftp

# Default command
CMD ["lsftp-tools", "--help"]

# Stage 5: Complete image with all components
FROM ubuntu:20.04 as complete

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libssl1.1 \
    libtpm2-tools \
    libpcsclite1 \
    libudev1 \
    libusb-1.0-0 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create LSFTP user
RUN useradd -r -s /bin/false lsftp

# Create directories
RUN mkdir -p /var/lsftp /var/log/lsftp /etc/lsftp
RUN chown -R lsftp:lsftp /var/lsftp /var/log/lsftp /etc/lsftp

# Copy all binaries
COPY --from=builder /app/target/release/lsftp-server /usr/local/bin/
COPY --from=builder /app/target/release/lsftp-client /usr/local/bin/
COPY --from=builder /app/target/release/lsftp-tools /usr/local/bin/

# Set permissions
RUN chmod +x /usr/local/bin/lsftp-*

# Switch to non-root user
USER lsftp

# Expose port
EXPOSE 8443

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD lsftp-server --help || exit 1

# Default command
CMD ["lsftp-server", "--address", "0.0.0.0", "--port", "8443", "--root-dir", "/var/lsftp"]
