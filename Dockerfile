FROM rust:1 AS builder

RUN \
    apt update &&\
    apt install -y libdbus-1-dev pkg-config

ADD . /build
WORKDIR /build

# Cache a build layer for downloads
RUN cargo fetch
# VTA for containerized use
RUN cargo build --package vta-service --no-default-features --features "setup,config-seed"

# Create the actual image
FROM debian:trixie-slim
ARG DEBIAN_FRONTEND=noninteractive
RUN \
    apt-get update &&\
    apt-get install -y ca-certificates &&\
    apt-get clean &&\
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/debug/vta /vta
WORKDIR /data
ENTRYPOINT ["/vta"]
CMD ["--config", "/data/config.toml"]
