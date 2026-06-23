# =============================================================================
# Vetro Rust AST Proxy — Multi-stage Dockerfile
# Uses cargo-chef to cache dependency compilation separately from source.
#
# Stages:
#   chef     — installs cargo-chef tool
#   planner  — generates recipe.json from Cargo.toml
#   builder  — compiles deps (cached), then source (fast on rebuilds)
#   runner   — minimal runtime image
# =============================================================================

# syntax=docker/dockerfile:1.7

# ── Stage 1: install cargo-chef ──────────────────────────────────────────────
FROM rust:1.88-slim-bookworm AS chef
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

RUN cargo install cargo-chef --locked

# ── Stage 2: generate recipe (dependency fingerprint) ────────────────────────
FROM chef AS planner
COPY . .
RUN --mount=type=secret,id=github_token,required=true \
    git config --global url."https://$(cat /run/secrets/github_token)@github.com/".insteadOf "https://github.com/" \
    && cargo chef prepare --recipe-path recipe.json

# ── Stage 3: compile deps (cached layer) + source ────────────────────────────
FROM chef AS builder

# Deps layer — only invalidated when Cargo.toml changes
COPY --from=planner /app/recipe.json recipe.json
RUN --mount=type=secret,id=github_token,required=true \
    git config --global url."https://$(cat /run/secrets/github_token)@github.com/".insteadOf "https://github.com/" \
    && cargo chef cook --release --recipe-path recipe.json

# Source layer — only recompiles your code (seconds on rebuilds)
COPY src ./src
RUN --mount=type=secret,id=github_token,required=true \
    git config --global url."https://$(cat /run/secrets/github_token)@github.com/".insteadOf "https://github.com/" \
    && cargo build --release

# ── Stage 4: minimal runtime ──────────────────────────────────────────────────
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
