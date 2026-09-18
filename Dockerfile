# syntax=docker/dockerfile:1.7
FROM rust:1.98.1-bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       build-essential pkg-config clang ca-certificates \
       libpcap-dev libxdp-dev libbpf-dev libelf-dev zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY Cargo.toml build.rs rust-toolchain.toml ./
COPY native ./native
COPY src ./src
COPY frontend ./frontend

# A successful image build is also a compile/unit-test gate. BuildKit caches
# downloads and compilation artifacts even when a source compile fails, while
# the final executable is copied out of the cache mount into the image layer.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    cargo test --release --all-features \
    && cargo build --release --all-features \
    && cp /src/target/release/bazalt /tmp/bazalt

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       ca-certificates curl libpcap0.8 libxdp1 libbpf1 libelf1 zlib1g \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /tmp/bazalt /usr/local/bin/bazalt
COPY --from=builder /src/frontend ./frontend

RUN mkdir -p /data/segments /data/raw /pcaps

ENV BAZALT_LISTEN=0.0.0.0:65000 \
    BAZALT_SEGMENT_DIR=/data/segments \
    BAZALT_RAW_SEGMENT_DIR=/data/raw \
    BAZALT_PACKET_LOGGING=false \
    BAZALT_RAW_CAPTURE=false \
    RUST_LOG=info

EXPOSE 65000
HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=6 \
    CMD-SHELL curl -fsS -u "$BAZALT_AUTH_USERNAME:$BAZALT_AUTH_PASSWORD" http://127.0.0.1:65000/api/health >/dev/null || exit 1

ENTRYPOINT ["/usr/local/bin/bazalt"]
