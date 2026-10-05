# =============================================================================
# Vericto Rust AST Proxy — Multi-stage Dockerfile
# Uses cargo-chef to cache dependency compilation separately from source.
#
# Stages:
#   chef     — installs cargo-chef and cargo-about
#   planner  — generates recipe.json from Cargo.toml
#   builder  — compiles deps (cached), then source (fast on rebuilds), then
#              writes THIRD_PARTY_LICENSES
#   runner   — minimal runtime image, with the license files under
#              /usr/share/doc/vericto-proxy
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

# Generates THIRD_PARTY_LICENSES in the builder stage. Pinned, so the notices only
# change format when this line does.
RUN cargo install cargo-about --version 0.9.2 --locked --features cli

# ── Stage 2: generate recipe (dependency fingerprint) ────────────────────────
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ── Stage 3: compile deps (cached layer) + source ────────────────────────────
FROM chef AS builder

# Deps layer — only invalidated when Cargo.toml changes
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

# Source layer — only recompiles your code (seconds on rebuilds). The manifest
# and lockfile are required here: `cargo chef cook` builds only dependencies
# against a dummy crate, so the real binary is compiled from Cargo.toml + src in
# this step. Without the manifest, `cargo build` would leave the chef stub.
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release

# Notices for everything compiled into the binary; see third-party/build-notices.sh.
COPY third-party ./third-party
RUN sh third-party/build-notices.sh THIRD_PARTY_LICENSES

# ── Stage 4: minimal runtime ──────────────────────────────────────────────────
FROM debian:bookworm-slim AS runner

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system --gid 1001 vericto && \
    useradd --system --uid 1001 --gid vericto vericto

COPY --from=builder /app/target/release/vericto-proxy /usr/local/bin/vericto-proxy
RUN chown vericto:vericto /usr/local/bin/vericto-proxy

# The Elastic License 2.0 requires that anyone who receives the software also
# receives its terms, and the dependencies' licenses require their notices to go
# with binary copies, so all three files ship next to the binary.
COPY LICENSE NOTICE /usr/share/doc/vericto-proxy/
COPY --from=builder /app/THIRD_PARTY_LICENSES /usr/share/doc/vericto-proxy/

USER vericto

# `PROXY_EVAL_PORT` and `EXPOSE 5434` date from when evaluation was an HTTP call to a
# sidecar. The engine runs in-process now and the variable is not read anywhere in the
# source, so the image no longer advertises a port it does not serve.
ENV RUST_LOG=info
ENV RUST_BACKTRACE=0

EXPOSE 5433

# The health listener is plain TCP: it accepts a connection and closes it without
# exchanging any bytes (src/tcp/healthz.rs), and it binds `VERICTO_HEALTHZ_PORT`. So the
# probe is a TCP connect rather than an HTTP GET.
#
# Both deployments already check it this way and do not rely on this directive:
# docker-compose.yml defines its own TCP check, and on ECS the verdict comes from the
# NLB target group with `HealthCheckProtocol: TCP`. Matching them here keeps the image
# usable on its own, which is what `docker run` and `docker ps` report against.
#
# The listener is opt-in, so with `VERICTO_HEALTHZ_PORT` unset there is nothing to
# probe and the container reports healthy: the absence of an optional port is not a
# failure. Using bash's `exec 3<>` keeps the runtime image free of curl.
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD bash -c 'if [ -z "${VERICTO_HEALTHZ_PORT:-}" ]; then exit 0; fi; \
        exec 3<>/dev/tcp/127.0.0.1/"${VERICTO_HEALTHZ_PORT}" && exec 3<&- && exec 3>&-' || exit 1

CMD ["/usr/local/bin/vericto-proxy"]
