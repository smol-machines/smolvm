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

#[cfg(feature = "host")]
pub mod host;
