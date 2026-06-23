# =============================================================================
# Vetro Rust AST Proxy — Multi-stage Dockerfile
# Builder: rust:1.88-slim-bookworm (Debian/glibc — required for bindgen/dlopen)
# Runner:  debian:bookworm-slim (matches glibc ABI)
# =============================================================================

# syntax=docker/dockerfile:1.7

FROM rust:1.88-slim-bookworm AS builder
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libclang-dev \
    clang \
    libssl-dev \
    pkg-config \
    protobuf-compiler \
    git \
    && rm -rf /var/lib/apt/lists/*

ENV LIBCLANG_PATH=/usr/lib/llvm-14/lib

COPY Cargo.toml ./
RUN --mount=type=secret,id=github_token,required=true \
    TOKEN=$(cat /run/secrets/github_token) \
    && git config --global url."https://${TOKEN}@github.com/".insteadOf "https://github.com/" \
    && mkdir src && echo 'fn main() {}' > src/main.rs \
    && cargo generate-lockfile \
    && cargo build --release \
    && rm -rf src

COPY src ./src
RUN --mount=type=secret,id=github_token,required=true \
    TOKEN=$(cat /run/secrets/github_token) \
    && git config --global url."https://${TOKEN}@github.com/".insteadOf "https://github.com/" \
    && touch src/main.rs && cargo build --release

FROM debian:bookworm-slim AS runner

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system --gid 1001 vetro && \
    useradd --system --uid 1001 --gid vetro vetro

COPY --from=builder /app/target/release/vetro-proxy /usr/local/bin/vetro-proxy
RUN chown vetro:vetro /usr/local/bin/vetro-proxy

USER vetro

ENV PROXY_EVAL_PORT=5434
ENV RUST_LOG=info
ENV RUST_BACKTRACE=0

EXPOSE 5433
EXPOSE 5434

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS "http://localhost:${PROXY_EVAL_PORT}/health" || exit 1

CMD ["/usr/local/bin/vetro-proxy"]
