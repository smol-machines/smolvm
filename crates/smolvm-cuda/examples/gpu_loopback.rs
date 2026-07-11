//! GPU live-verification harness.
//!
//! Exercises the *real* CUDA stack — `GpuBackend` (driver via `nvcuda.dll` /
//! `libcuda.so.1`), the `host::serve` dispatch, the wire `proto`, and the guest
//! `Client` — over a local TCP loopback socket, running an arbitrary-module +
//! named-kernel workload on the host GPU. This is the same code path production
//! uses; only the vsock/microVM transport is swapped for loopback so it can run
//! directly on a GPU host (e.g. the RTX 3070) without booting a VM.
//!
//! Run on a machine with an NVIDIA driver:
//!   cargo run --release --example gpu_loopback --features gpu
//!
//! Prints the device name and `GPU-VERIFY-OK` on success; exits 2 if no GPU
//! driver loads, 3 on a result mismatch.

use smolvm_cuda::client::Client;
use smolvm_cuda::host::{serve, Backend, GpuBackend};
use std::net::{TcpListener, TcpStream};

const VECADD_PTX: &str = r#".version 7.0
.target sm_52
.address_size 64
.visible .entry vecadd(.param .u64 a, .param .u64 b, .param .u64 c, .param .u32 n)
{ .reg .pred %p<2>; .reg .f32 %f<4>; .reg .b32 %r<6>; .reg .b64 %rd<11>;
 ld.param.u64 %rd1,[a]; ld.param.u64 %rd2,[b]; ld.param.u64 %rd3,[c]; ld.param.u32 %r2,[n];
 mov.u32 %r3,%ntid.x; mov.u32 %r4,%ctaid.x; mov.u32 %r5,%tid.x; mad.lo.s32 %r1,%r4,%r3,%r5;
 setp.ge.u32 %p1,%r1,%r2; @%p1 bra $E;
 cvta.to.global.u64 %rd4,%rd1; cvta.to.global.u64 %rd5,%rd2; cvta.to.global.u64 %rd6,%rd3;
 mul.wide.u32 %rd7,%r1,4; add.s64 %rd8,%rd4,%rd7; add.s64 %rd9,%rd5,%rd7; add.s64 %rd10,%rd6,%rd7;
 ld.global.f32 %f1,[%rd8]; ld.global.f32 %f2,[%rd9]; add.f32 %f3,%f1,%f2; st.global.f32 [%rd10],%f3;
$E: ret; }
"#;

fn main() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().unwrap();

    // Host side: real driver backend, served on the accepting thread (the CUDA
    // context is created and stays current on this one thread).
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        let mut backend: Box<dyn Backend> = match GpuBackend::load() {
            Ok(b) => Box::new(b),
            Err(e) => {
                eprintln!("gpu_loopback: no CUDA driver: {e}");
                std::process::exit(2);
            }
        };
        let _ = serve(stream, backend.as_mut());
    });

    let mut cu = Client::new(TcpStream::connect(addr).expect("connect"));
    cu.init().expect("cuInit");
    let count = cu.device_get_count().expect("device count");
    let name = cu.device_get_name(0).expect("device name");
    let vram = cu.device_total_mem(0).expect("total mem");
    println!(
        "gpu_loopback: {count} device(s); device 0 = {name} ({} MiB)",
        vram / (1024 * 1024)
    );
    let _ctx = cu.ctx_create(0).expect("ctx create");

    // Arbitrary module + named kernel — the general path, not a baked op.
    let module = cu
        .module_load_data(VECADD_PTX.as_bytes())
        .expect("module load");
    let func = cu
        .module_get_function(module, "vecadd")
        .expect("get function");

    let n: usize = 1 << 16; // 65536 elements
    let bytes = (n * 4) as u64;
    let a: Vec<f32> = (0..n).map(|i| i as f32).collect();
    let b: Vec<f32> = (0..n).map(|i| (3 * i) as f32).collect();
    let da = cu.mem_alloc(bytes).expect("alloc a");
    let db = cu.mem_alloc(bytes).expect("alloc b");
    let dc = cu.mem_alloc(bytes).expect("alloc c");
    cu.memcpy_htod(da, bytemuck(&a), 0).expect("h2d a");
    cu.memcpy_htod(db, bytemuck(&b), 0).expect("h2d b");

    let block = 256u32;
    let grid = (n as u32).div_ceil(block);
    cu.launch_kernel(
        func,
        [grid, 1, 1],
        [block, 1, 1],
        0,
        0,
        &[
            da.to_le_bytes().to_vec(),
            db.to_le_bytes().to_vec(),
            dc.to_le_bytes().to_vec(),
            (n as u32).to_le_bytes().to_vec(),
        ],
    )
    .expect("launch");
    cu.ctx_synchronize().expect("sync");

    let out = cu.memcpy_dtoh(dc, bytes, 0).expect("d2h");
    let c: Vec<f32> = out
        .chunks_exact(4)
        .map(|p| f32::from_le_bytes(p.try_into().unwrap()))
        .collect();
    for i in 0..n {
        let expect = a[i] + b[i]; // i + 3i = 4i
        if (c[i] - expect).abs() > 1e-2 {
            eprintln!("gpu_loopback: MISMATCH at {i}: got {} want {expect}", c[i]);
            std::process::exit(3);
        }
    }
    cu.mem_free(da).ok();
    cu.mem_free(db).ok();
    cu.mem_free(dc).ok();
    drop(cu);
    let _ = server.join();
    println!(
        "gpu_loopback: vecadd n={n} verified on GPU (c[1]={}, c[{}]={})",
        c[1],
        n - 1,
        c[n - 1]
    );
    println!("GPU-VERIFY-OK: {name}");
}

/// Reinterpret `&[f32]` as bytes (f32 has no invalid bit patterns).
fn bytemuck(v: &[f32]) -> &[u8] {
    // SAFETY: f32 is plain-old-data; reading its bytes is sound.
    unsafe { std::slice::from_raw_parts(v.as_ptr() as *const u8, std::mem::size_of_val(v)) }
}
