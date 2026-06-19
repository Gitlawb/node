# syntax=docker/dockerfile:1.6
#
# gitlawb-node — production image for operators.
# Multi-arch (linux/amd64, linux/arm64), non-root runtime, HEALTHCHECK.

# ── Build stage ─────────────────────────────────────────────────────────────
FROM rust:1.91-bookworm AS builder

WORKDIR /build

# Cache dependencies first for faster rebuilds
COPY Cargo.toml Cargo.lock ./
COPY crates/gitlawb-core/Cargo.toml crates/gitlawb-core/
COPY crates/gitlawb-node/Cargo.toml crates/gitlawb-node/
COPY crates/gl/Cargo.toml crates/gl/
COPY crates/git-remote-gitlawb/Cargo.toml crates/git-remote-gitlawb/

# Fetch deps (this layer caches until Cargo.{toml,lock} change)
RUN mkdir -p crates/gitlawb-core/src crates/gitlawb-node/src crates/gl/src crates/git-remote-gitlawb/src && \
    echo 'fn main() {}' > crates/gitlawb-node/src/main.rs && \
    echo 'fn main() {}' > crates/gl/src/main.rs && \
    echo 'fn main() {}' > crates/git-remote-gitlawb/src/main.rs && \
    echo '' > crates/gitlawb-core/src/lib.rs && \
    cargo build --release -p gitlawb-node -p gl -p git-remote-gitlawb || true

# Now copy real sources and build for real.
# Force-bump mtimes so cargo's fingerprint check rebuilds — without this,
# cargo can keep the dummy `fn main() {}` binaries from the cache layer above
# and the runtime container exits immediately with code 0.
COPY crates/ crates/
COPY bootstrap-peers.json ./
RUN find crates -name "*.rs" -exec touch {} + && \
    rm -f target/release/gitlawb-node target/release/gl target/release/git-remote-gitlawb && \
    rm -rf target/release/.fingerprint/gitlawb-node-* \
           target/release/.fingerprint/gl-* \
           target/release/.fingerprint/git-remote-gitlawb-* && \
    cargo build --release -p gitlawb-node -p gl -p git-remote-gitlawb && \
    strip target/release/gitlawb-node target/release/gl target/release/git-remote-gitlawb

# ── Runtime stage ───────────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        ca-certificates \
        curl \
        tini \
    && rm -rf /var/lib/apt/lists/*

# Non-root user for runtime
RUN groupadd -r gitlawb --gid=1000 \
    && useradd -r -g gitlawb --uid=1000 --home-dir=/data --shell=/sbin/nologin gitlawb \
    && mkdir -p /data/repos /data/keys \
    && chown -R gitlawb:gitlawb /data

COPY --from=builder /build/target/release/gitlawb-node /usr/local/bin/
COPY --from=builder /build/target/release/gl /usr/local/bin/
COPY --from=builder /build/target/release/git-remote-gitlawb /usr/local/bin/

USER gitlawb
WORKDIR /data

ENV GITLAWB_REPOS_DIR=/data/repos \
    GITLAWB_KEY=/data/keys/identity.pem \
    GITLAWB_HOST=0.0.0.0 \
    GITLAWB_PORT=7545 \
    GITLAWB_P2P_PORT=7546

EXPOSE 7545 7546/udp

VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -fsS http://127.0.0.1:${GITLAWB_PORT}/health || exit 1

# Run under tini so the node is never PID 1. As PID 1 a process must reap
# reparented orphans itself; the node does not, so git's reparented grandchildren
# (e.g. pack-objects orphaned when a served upload-pack dies on a client
# disconnect) would accumulate as zombies until fork() fails with EAGAIN (#53).
# tini reaps them and forwards SIGTERM/SIGINT to the node, which runs its own
# graceful shutdown. (No `-g`: the node manages its own children, so group-wide
# signalling would only disturb in-flight git helpers during shutdown.)
ENTRYPOINT ["tini", "--", "gitlawb-node"]
