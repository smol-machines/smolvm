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

# The build and the tests run as the unprivileged user CI runs them as: a root run takes
# the service's shared-base checkpoint layout and one install test asserts the per-user
# one (see threat_model.md). The checkout is copied already owned by that user, so no
# later chown duplicates the build tree into another layer.
RUN useradd --create-home --shell /bin/bash scanner

# Scanner contract: the checkout lives inside the image, at /src.
COPY --chown=scanner:scanner . /src
WORKDIR /src

# rust-toolchain.toml selects the stable toolchain, which is not the one the base image
# ships, so install it with rustfmt, clippy and the musl target from inside the checkout
# while the network is still available, and no later cargo call has to.
RUN rustup show active-toolchain \
    && rustup component add rustfmt clippy \
    && rustup target add "$(uname -m)-unknown-linux-musl"

# Where the prebuilt libkrun and libkrunfw for this architecture live, for anything that
# needs to dlopen them (a few host-side tests create qcow2 overlays through libkrun).
RUN ln -s "/src/lib/linux-$(uname -m)" /opt/smolvm-lib
ENV SMOLVM_LIB_DIR=/opt/smolvm-lib

USER scanner

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

# Run the unit tests CI runs on Linux as a smoke check. tini reaps the orphans the
# process-cleanup tests leave, as an init would. smolvm-network's real-socket suite is
# skipped as it is in CI. Failures do not abort the build. The tests leave sparse machine
# disks (hundreds of GiB apparent) under ~/.cache/smolvm, which an image layer would store
# expanded, so the state they wrote is removed in the same step.
RUN tini -s -- bash -c ' \
      (timeout 1800 cargo test --locked --offline --lib \
          -p smolvm -p smolvm-pack -p smolvm-registry -p smolvm-protocol \
          -p smolfile -p smolvm-cuda -p smolvm-s3fs \
        || echo "WARNING: smolvm unit tests reported failures") \
      && (timeout 900 cargo test --locked --offline -p smolvm-agent --bins \
        || echo "WARNING: smolvm-agent unit tests reported failures") \
      && (timeout 900 cargo test --locked --offline -p smolvm-shim \
        || echo "WARNING: smolvm-shim unit tests reported failures")' \
    && rm -rf "$HOME"/.cache/smolvm* "$HOME"/.local/share/smolvm* "$HOME"/.config/smolvm*

# Back to root for the scanner's own layer; /tmp is emptied so its runs do not meet
# files another user left there.
USER root
RUN find /tmp -mindepth 1 -delete
