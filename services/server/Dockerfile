# ============================================================
# memwal Server — Dockerfile
# Multi-stage build: Rust binary + Node.js sidecar scripts
# ============================================================

# ── Stage 1: Build Rust binary ──────────────────────────────
# pinned by digest for reproducible, supply-chain-safe builds.
# Tag: rust:1.88-bookworm  |  arch: linux/amd64  |  pinned: 2026-06-08
# To refresh: docker inspect --format='{{index .RepoDigests 0}}' rust:1.88-bookworm
FROM rust:1.88-bookworm@sha256:4727898c104ecd2e22d780925832502faee9fe4e70581b8572af081370b315a0 AS builder

WORKDIR /app

# Cache dependencies — copy manifests first
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release && rm -rf src

# Build real source
COPY src/ src/
COPY migrations/ migrations/
COPY migrations_legacy/ migrations_legacy/
# Touch main.rs to invalidate the cache for the actual source
RUN touch src/main.rs
RUN cargo build --release

# ── Stage 2: Runtime (Node.js slim) ─────────────────────────
# pinned by digest for reproducible, supply-chain-safe builds.
# Tag: node:22.23.4-bookworm-slim  |  multi-platform index  |  pinned: 2026-10-22
# To refresh: docker buildx imagetools inspect node:22.23.4-bookworm-slim
FROM node:22.23.4-bookworm-slim@sha256:de170b39439eb0e5a3444ad7d60b015614a381e10fecae2e30ec9e735122f38d AS runtime

# Install Rust runtime deps (ca-certificates and libssl3)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Add non-root user
RUN useradd -ms /bin/bash appuser
USER appuser
WORKDIR /app

# Copy Rust binary
COPY --from=builder --chown=appuser:appuser /app/target/release/memwal-server ./memwal-server

# Copy TS sidecar scripts + install deps
COPY --chown=appuser:appuser scripts/package.json scripts/package-lock.json ./scripts/
RUN cd scripts && npm ci --omit=dev
COPY --chown=appuser:appuser scripts/*.ts ./scripts/
# Sidecar + MCP modules — sidecar-server.ts imports ./sidecar/server.js,
# which in turn imports ./mcp/index.js. Without these copies the runtime
# image fails at boot with module-not-found for ./sidecar/* or ./mcp/*.
COPY --chown=appuser:appuser scripts/sidecar/ ./scripts/sidecar/
COPY --chown=appuser:appuser scripts/mcp/ ./scripts/mcp/

# Copy migrations (for reference / manual runs)
COPY --chown=appuser:appuser migrations/ ./migrations/

# Port config — must match defaults in types.rs + sidecar-server.ts
ENV PORT=8000
ENV SIDECAR_PORT=9000
ENV SIDECAR_URL=http://localhost:9000
ENV SIDECAR_SCRIPTS_DIR=/app/scripts
EXPOSE ${PORT}

CMD ["./memwal-server"]
