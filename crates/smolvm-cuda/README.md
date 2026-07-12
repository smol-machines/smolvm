# smolvm-cuda

CUDA API remoting: run an **unmodified** CUDA application (PyTorch, vLLM,
llama.cpp, …) against an NVIDIA GPU that lives in another process, another host,
or on the far side of a VM boundary — with **no driver and no CUDA toolkit in
the client**. The client marshals `cudaX*`/`cu*` calls over a byte stream; a
host process replays them on the real GPU and ships results back.

Originally built for [smolvm](../../) microVMs, but the core has **no dependency
on smolvm or libkrun** and is usable standalone. Two ways to consume it:

## 1. As a drop-in shim (any CUDA app, no Rust, no smolvm)

Build the two shims and the server, then point any CUDA program at a remote GPU
host by preloading the shims — the program thinks it has a local GPU:

```sh
# on the GPU host: start the server
cargo run --release -p smolvm-cuda --example shim_server -- 0.0.0.0:7000

# on the client (no GPU, no CUDA toolkit needed): point the app at it
export CUDA_REMOTE_ENDPOINT=tcp:GPU_HOST:7000
export LD_LIBRARY_PATH=/path/to/shims   # dir with libcudart.so.12 + libcuda.so.1
python train.py                          # runs on the remote GPU, unchanged
```

`CUDA_REMOTE_ENDPOINT` accepts `tcp:HOST:PORT`, `unix:/path`, or `vsock`
(defaults to host CID 2 / port 7000, overridable with `CUDA_REMOTE_VSOCK`).

The shims are `smolvm-cudart-shim` (→ `libcudart.so.12`, the runtime API) and
`smolvm-cuda-shim` (→ `libcuda.so.1`, the driver API). Stage them over the
application's CUDA libraries (they export the same symbols).

## 2. As a Rust library

The transport is any `Read + Write`, and the backend is a trait — so you can
embed remoting into your own runtime, VMM, or GPU broker:

```rust
use smolvm_cuda::client::Client;
use smolvm_cuda::host::{serve, GpuBackend};

// client side (guest): marshal over any stream you own
let mut cli = Client::new(your_stream);   // TcpStream, VsockStream, a pipe, …
cli.init()?;
let dptr = cli.mem_alloc(4096)?;
// … cli.launch_kernel(), cli.memcpy_htod(), cli.graph_launch() …

// host side (has the GPU): dispatch onto the real driver
let mut backend = GpuBackend::load()?;     // dlopen's libcuda.so.1
serve(your_stream, &mut backend)?;         // one connection, in call order
```

See `examples/gpu_loopback.rs` for a complete client+server in one process.

## Extension seams

- **Transport** — `Client<S: Read + Write>`. Bring your own stream. Built-in:
  TCP, Unix, AF_VSOCK. For same-host VMs there is also a zero-copy shared-memory
  ring path (see `ring`), which needs the host to map guest RAM (below).
- **Backend** (`host::Backend`) — `GpuBackend` (real driver via `dlopen`) and
  `CpuBackend` (GPU-less emulation for testing) ship in-box; implement your own
  to record/replay, meter, or target a different device.
- **Guest memory** (`Backend::gpa_to_hva`) — the only VM-specific seam. The
  embedder provides guest-physical → host-virtual mappings so the rings can DMA
  guest RAM directly. Non-VM consumers skip it and use the socket transport
  (fully functional, just not zero-copy).

## Coverage & honesty

This forwards the surface that has been exercised end-to-end (PyTorch training +
inference, vLLM, llama.cpp, Triton, FlashAttention, bitsandbytes, cuBLAS/cuBLASLt,
cuDNN v8, CUDA graphs, the VMM allocator). Everything else is an **honest
`NOT_SUPPORTED` stub** — a workload that needs an unimplemented call fails
loudly, it does not silently return wrong data. A connect-time protocol
handshake likewise rejects a client/server built from mismatched source rather
than corrupting.

Not yet forwarded: cuSOLVER/cuFFT/cuRAND/NCCL, complex (C/Z) BLAS, and reduction
BLAS (whose result-pointer mode can't be disambiguated safely). The cuBLAS/cuDNN
surface is generated from a small spec (`smolvm-cuda-codegen`), so extending it
is mechanical.

## Performance

Same-host (shared-memory rings), forwarded vs native on an RTX 3070: vLLM
CUDA-graph decode ~97%, llama.cpp ~98%. Over a network the story is
latency-bound — decode pays ~1.3 synchronizations per token (fine under ~1 ms
RTT, degraded but usable at multi-ms), and cold start is dominated by the
framework's own synchronization barriers during warmup. Immutable device/kernel
queries are cached client-side to keep the per-token round-trip count near its
floor.
