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
# Base images are pinned by digest (multi-arch index) as well as tag, so a
# re-pushed tag cannot change what is built; Dependabot (docker) bumps them.
FROM rust:1.88-slim-bookworm@sha256:38bc5a86d998772d4aec2348656ed21438d20fcdce2795b56ca434cf21430d89 AS chef
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

RUN cargo install cargo-chef --version 0.1.78 --locked

# Generates THIRD_PARTY_LICENSES in the builder stage. Pinned, so the notices only
# change format when this line does.
RUN cargo install cargo-about --version 0.9.2 --locked --features cli

# ── Stage 2: generate recipe (dependency fingerprint) ────────────────────────
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ── Optional PGO profile (4.19.0) ─────────────────────────────────────────────
# Empty unless the build is given one as a named context:
#   docker buildx build --build-context pgo=<dir holding merged.profdata> .
# release.yml trains it on the performance gate's corpus (perf/pgo-train.sh,
# docs/PERFORMANCE.md "PGO"). Without it the build is the plain release build.
FROM scratch AS pgo

# ── Stage 3: compile deps (cached layer) + source ────────────────────────────
FROM chef AS builder

# The profile, when there is one: `-Cprofile-use` for the dependencies and the
# proxy alike (both steps need the same RUSTFLAGS, or cargo rebuilds the deps).
COPY --from=pgo / /pgo/
# Opt-in code generation for one CPU family, e.g. `--build-arg TARGET_CPU=neoverse-v1`
# for an image that only runs on Graviton3. Empty for the published images, which
# must run on any x86_64 / aarch64 machine.
ARG TARGET_CPU=

# Deps layer — only invalidated when Cargo.toml changes (or the profile does)
COPY --from=planner /app/recipe.json recipe.json
RUN RUSTFLAGS="${TARGET_CPU:+-Ctarget-cpu=$TARGET_CPU}"; \
    if [ -f /pgo/merged.profdata ]; then RUSTFLAGS="$RUSTFLAGS -Cprofile-use=/pgo/merged.profdata"; fi; \
    RUSTFLAGS="$RUSTFLAGS" cargo chef cook --release --locked --recipe-path recipe.json

# Source layer — only recompiles your code (seconds on rebuilds). The manifest
# and lockfile are required here: `cargo chef cook` builds only dependencies
# against a dummy crate, so the real binary is compiled from Cargo.toml + src in
# this step. Without the manifest, `cargo build` would leave the chef stub.
COPY Cargo.toml Cargo.lock ./
COPY src ./src
# --locked: build exactly the reviewed Cargo.lock, never a re-resolved one.
RUN RUSTFLAGS="${TARGET_CPU:+-Ctarget-cpu=$TARGET_CPU}"; \
    if [ -f /pgo/merged.profdata ]; then RUSTFLAGS="$RUSTFLAGS -Cprofile-use=/pgo/merged.profdata"; fi; \
    RUSTFLAGS="$RUSTFLAGS" cargo build --release --locked

# Notices for everything compiled into the binary; see third-party/build-notices.sh.
COPY third-party ./third-party
RUN sh third-party/build-notices.sh THIRD_PARTY_LICENSES

# ── Stage 4: minimal runtime ──────────────────────────────────────────────────
# Chainguard glibc-dynamic (since 4.15.2, from debian:bookworm-slim): glibc,
# libgcc_s, the CA bundle and nothing else. No shell, no package manager, no
# coreutils, so the base carries no OS packages for a scanner to report beyond
# those three. The binary links only libc, libm and libgcc_s (checked with the
# image's own `ld.so --list` for 4.15.2); TLS is rustls with the webpki-roots
# store compiled in, so OpenSSL is not needed and the image's CA bundle is not
# read (`UPSTREAM_SSLROOTCERT` is a file the deployment mounts).
#
# Only the `latest` tag is free on cgr.dev, so it is pinned by digest and
# Dependabot (docker, weekly) proposes the new digest; Chainguard does not
# promise to keep old digests, so a stale pin can stop pulling.
FROM cgr.dev/chainguard/glibc-dynamic:latest@sha256:5bb932663cff4fb276186720e0357af55c5e47f12e4d9f44ea0060fa3e7bca88 AS runner

# Owned by root and not writable by the user the proxy runs as.
COPY --from=builder /app/target/release/vericto-proxy /usr/local/bin/vericto-proxy

# The Functional Source License requires that anyone who receives the software
# also receives its terms (or a link to them) and its copyright notices, and the
# dependencies' licenses require their notices to go with binary copies, so all
# three files ship next to the binary.
COPY LICENSE NOTICE /usr/share/doc/vericto-proxy/
COPY --from=builder /app/THIRD_PARTY_LICENSES /usr/share/doc/vericto-proxy/

# Chainguard's non-root user (`nonroot`, 65532:65532). Up to 4.15.1 the image ran as
# vericto (1001:1001): a volume written by an older image needs `chown -R 65532:65532`,
# or run this one with `--user 1001:1001`.
USER 65532:65532

# `PROXY_EVAL_PORT` and `EXPOSE 5434` date from when evaluation was an HTTP call to a
# sidecar. The engine runs in-process now and the variable is not read anywhere in the
# source, so the image no longer advertises a port it does not serve.
ENV RUST_LOG=info
ENV RUST_BACKTRACE=0

EXPOSE 5433

# The health listener is plain TCP: it accepts a connection and closes it without
# exchanging any bytes (src/tcp/healthz.rs), and it binds `VERICTO_HEALTHZ_PORT`.
# `vericto-proxy healthcheck` makes that TCP connect (to 127.0.0.1, or to
# `VERICTO_HEALTHZ_ADDR` when it names one address) and exits 0 or 1. The image has
# no shell, so the check is the binary itself, in exec form.
#
# Both deployments already check it this way and do not rely on this directive:
# docker-compose.yml defines its own check, and on ECS the verdict comes from the
# NLB target group with `HealthCheckProtocol: TCP`. Matching them here keeps the image
# usable on its own, which is what `docker run` and `docker ps` report against.
#
# The listener is opt-in, so with `VERICTO_HEALTHZ_PORT` unset there is nothing to
# probe and the container reports healthy: the absence of an optional port is not a
# failure.
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/vericto-proxy", "healthcheck"]

CMD ["/usr/local/bin/vericto-proxy"]
