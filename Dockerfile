# =============================================================================
# Vetro Rust AST Proxy — Multi-stage Dockerfile
# Builder: rust:1.88-slim-bookworm (Debian/glibc — required for bindgen/dlopen)
# Runner:  debian:bookworm-slim (matches glibc ABI)
# =============================================================================

# Stage 1: Builder (Debian — glibc supports dlopen needed by bindgen/pg_query)
FROM rust:1.88-slim-bookworm AS builder
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libclang-dev \
    clang \
    libssl-dev \
    pkg-config \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# Tell bindgen where to find libclang.
ENV LIBCLANG_PATH=/usr/lib/llvm-14/lib

# Cache dep compilation: copy only the manifest, build a dummy binary.
COPY Cargo.toml ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs \
    && cargo generate-lockfile \
    && cargo build --release \
    && rm -rf src

# Build the real binary.
COPY src ./src
RUN touch src/main.rs && cargo build --release

# Stage 2: Runtime — minimal Debian (no Rust toolchain, no LLVM)
FROM debian:bookworm-slim AS runner

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Security: non-root user
RUN groupadd --system --gid 1001 vetro && \
    useradd --system --uid 1001 --gid vetro vetro

COPY --from=builder /app/target/release/vetro-proxy /usr/local/bin/vetro-proxy
RUN chown vetro:vetro /usr/local/bin/vetro-proxy

USER vetro

# 5434 = HTTP evaluation endpoint (consumed by Fastify API)
# 5433 = PostgreSQL TCP wire-protocol proxy
ENV PROXY_EVAL_PORT=5434
ENV RUST_LOG=info
ENV RUST_BACKTRACE=0

EXPOSE 5433
EXPOSE 5434

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS "http://localhost:${PROXY_EVAL_PORT}/health" || exit 1

CMD ["/usr/local/bin/vetro-proxy"]
