//! CUDA Driver-API remoting for smolvm: a guest microVM forwards `cu*` calls
//! over vsock to a host server that runs them on the host's NVIDIA GPU.
//!
//! - `proto` — the wire protocol (framing, request/response codec). No deps.
//! - `client` — guest-side marshalling over any `Read`/`Write` stream.
//! - `host` — host-side dispatch with a `Backend` trait; ships a real GPU
//!   backend (`GpuBackend`, `gpu` feature) and a CPU emulation backend
//!   (`CpuBackend`) for GPU-less verification.
//!
//! The guest binary depends on this crate with `default-features = false` to
//! pull only `proto` + `client` (no `libloading`), keeping the musl build lean.

pub mod client;
pub mod proto;
/// Shared-memory command/completion rings (low-latency in-VM transport).
pub mod ring;

/// FNV-1a 64-bit hash of `data`, never zero (0 is reserved as a sentinel).
///
/// Lives at the crate root so both the always-compiled `client` (content-hash
/// module dedup) and the feature-gated `host` (module cache keys, chunk CRCs)
/// share one implementation without `client` reaching into `host`.
pub fn fnv64(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h.max(1)
}

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
