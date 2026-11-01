# syntax=docker/dockerfile:1
# Build image for Anthropic's OSS Scanner (https://github.com/anthropics/oss-scanner).
# It sets smolvm up the way the Linux CI job does: the whole workspace compiles on a
# glibc host, the guest agent additionally builds as a static musl binary, and the
# host-runnable unit tests run as a smoke check. Linux loads libkrun with dlopen at
# run time, so nothing links against it here; the prebuilt libraries under lib/ are
# in the checkout. Booting a machine needs /dev/kvm, which the scanner's VM does not
# have, so the integration suites under tests/ are not runnable in this image.
FROM rust:1-bookworm
ENV DEBIAN_FRONTEND=noninteractive \
    CARGO_TERM_COLOR=never \
    CARGO_NET_RETRY=5 \
    RUST_BACKTRACE=1
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates git build-essential clang pkg-config libssl-dev \
      musl-tools e2fsprogs file python3 curl tini \
    && rm -rf /var/lib/apt/lists/*

# Scanner contract: the checkout lives inside the image, at /src.
COPY . /src
WORKDIR /src

# rust-toolchain.toml asks for stable with rustfmt and clippy; install them while the
# network is still available so no later cargo call tries to.
RUN rustup component add rustfmt clippy \
    && rustup target add "$(uname -m)-unknown-linux-musl"

# Fetch every crate so later builds work with --offline.
RUN cargo fetch --locked

# Debug build of every crate and every target, as CI's clippy pass compiles them: the
# smolvm CLI and library, the network, credential, pack, checkpoint, OCI-layer, registry,
# protocol, Smolfile, S3 and CUDA crates, the containerd shim, and the guest agent.
RUN cargo build --locked --workspace --all-targets

# The guest agent as it ships: a static musl binary for this host's architecture.
RUN cargo build --locked --release --target "$(uname -m)-unknown-linux-musl" -p smolvm-agent

# Compile (but do not run) every test so the suites are usable offline.
RUN cargo test --locked --workspace --no-run

# Where the prebuilt libkrun and libkrunfw for this architecture live, for anything that
# needs to dlopen them (a few host-side tests create qcow2 overlays through libkrun).
RUN ln -s "/src/lib/linux-$(uname -m)" /opt/smolvm-lib
ENV SMOLVM_LIB_DIR=/opt/smolvm-lib

# Run the unit tests CI runs on Linux as a smoke check, as the unprivileged user CI
# runs them as: a root run takes the service's shared-base checkpoint layout and the
# install test asserts the per-user one (see threat_model.md). tini reaps the orphans the
# process-cleanup tests leave, as an init would. smolvm-network's real-socket suite is
# skipped as it is in CI. Failures do not abort the build. /tmp is emptied afterwards so
# the scanner's own runs do not meet files another user left there.
RUN useradd --create-home --shell /bin/bash scanner && chown -R scanner:scanner /src \
    && tini -s -- runuser -u scanner -- bash -c ' \
      (timeout 1800 cargo test --locked --offline --lib \
          -p smolvm -p smolvm-pack -p smolvm-registry -p smolvm-protocol \
          -p smolfile -p smolvm-cuda -p smolvm-s3fs \
        || echo "WARNING: smolvm unit tests reported failures") \
      && (timeout 900 cargo test --locked --offline -p smolvm-agent --bins \
        || echo "WARNING: smolvm-agent unit tests reported failures") \
      && (timeout 900 cargo test --locked --offline -p smolvm-shim \
        || echo "WARNING: smolvm-shim unit tests reported failures")' \
    && find /tmp -mindepth 1 -delete
