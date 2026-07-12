//! CUDA API remoting: run an unmodified CUDA app against a GPU in another
//! process/host/VM, with no driver in the client. The client marshals
//! `cudaX*`/`cu*` calls over a byte stream; a host replays them on the real GPU.
//!
//! Built for smolvm microVMs, but the core depends on nothing smolvm-specific
//! and is consumable standalone — see `README.md` for the drop-in-shim and
//! Rust-library usage. The transport is any `Read + Write`; the backend is a
//! trait; the only VM-specific seam is [`host::Backend::gpa_to_hva`] (guest-RAM
//! mapping for the zero-copy rings), which non-VM consumers can ignore.
//!
//! - `proto` — the wire protocol (framing, request/response codec). No deps.
//! - `client` — guest-side marshalling over any `Read`/`Write` stream.
//! - `config` — endpoint config from the environment (`CUDA_REMOTE_ENDPOINT`).
//! - `host` — host-side dispatch with a `Backend` trait; ships a real GPU
//!   backend (`GpuBackend`, `gpu` feature) and a CPU emulation backend
//!   (`CpuBackend`) for GPU-less verification.
//!
//! The guest binary depends on this crate with `default-features = false` to
//! pull only `proto` + `client` (no `libloading`), keeping the musl build lean.

pub mod client;
/// Environment-driven endpoint config for the guest shims (de-branded).
pub mod config;
pub mod proto;
/// Shared-memory command/completion rings (low-latency in-VM transport).
pub mod ring;

/// Fingerprint of the wire-defining source (see `build.rs`). The client sends
/// it in the `Init` handshake; the host rejects a mismatch, turning a stale
/// shim/server pairing into a loud error instead of silent data corruption.
pub const PROTO_HASH: u64 = {
    // env! gives the hex string from build.rs; parse it at compile time.
    let s = env!("SMOLVM_PROTO_HASH").as_bytes();
    let mut v = 0u64;
    let mut i = 0;
    while i < s.len() {
        let d = match s[i] {
            b'0'..=b'9' => s[i] - b'0',
            b'a'..=b'f' => s[i] - b'a' + 10,
            _ => 0,
        };
        v = v * 16 + d as u64;
        i += 1;
    }
    v
};

/// Shared-memory bulk-data channel (zero-copy memcpy). Linux-only.
#[cfg(target_os = "linux")]
pub mod shm;

#[cfg(feature = "host")]
pub mod host;
