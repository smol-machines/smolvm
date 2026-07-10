//! Host-side CUDA RPC server on TCP loopback, for exercising the
//! `smolvm-cuda-shim` ABI without a VM.
//!
//! Serves the real GPU backend when the driver loads, else CPU emulation, one
//! connection at a time (each on its own thread — the CUDA context binds to
//! the serving thread, mirroring the production per-connection model).
//!
//!   cargo run --release --example shim_server -p smolvm-cuda --features gpu -- [addr]
//!
//! Default addr 127.0.0.1:7901. Prints `SHIM-SERVER-READY <addr> <backend>` once
//! listening, so scripts can wait for the line then point a shim-linked binary
//! at it via `SMOLVM_CUDA_RPC=tcp:<addr>`.

use smolvm_cuda::host::{serve, Backend, CpuBackend, GpuBackend};
use std::net::TcpListener;

fn main() {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:7901".into());
    let listener = TcpListener::bind(&addr).expect("bind");
    let backend_kind = match GpuBackend::load() {
        Ok(_) => "gpu",
        Err(_) => "cpu-emulation",
    };
    println!("SHIM-SERVER-READY {addr} {backend_kind}");
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        std::thread::spawn(move || {
            let mut backend: Box<dyn Backend> = match GpuBackend::load() {
                Ok(b) => Box::new(b),
                Err(_) => Box::<CpuBackend>::default(),
            };
            let _ = serve(stream, backend.as_mut());
        });
    }
}
