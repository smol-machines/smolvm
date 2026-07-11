//! Guest-side CUDA-over-vsock runner.
//!
//! Connects out to the host CUDA server over `AF_VSOCK` (host CID 2, the smolvm
//! CUDA port) and drives a real Driver-API workload through the RPC client:
//! load an arbitrary PTX module, look up a named kernel, allocate device
//! buffers, copy in, launch, synchronize, copy out, and verify. This exercises
//! the *generalized* protocol (arbitrary module + named launch), not a baked-in
//! single operation — the same path a real driver-API program takes.
//!
//! On success it prints `SMOLVM-CUDA-OK`; on any failure it prints the error and
//! exits non-zero so a `machine exec` caller sees the result.

/// smolvm's reserved guest→host CUDA vsock port (mirrors `smolvm_protocol::ports::CUDA`).
#[cfg(target_os = "linux")]
const CUDA_PORT: u32 = 7000;
/// `VMADDR_CID_HOST` — the host end of the vsock.
#[cfg(target_os = "linux")]
const HOST_CID: u32 = 2;

/// A hand-written vector-add kernel. `.target sm_52` JITs forward-compatibly to
/// any newer GPU (e.g. the RTX 3070's sm_86). No nvcc required.
#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
fn run() -> Result<(), Box<dyn std::error::Error>> {
    use smolvm_cuda::client::Client;
    use vsock::VsockStream;

    let stream = VsockStream::connect_with_cid_port(HOST_CID, CUDA_PORT)
        .map_err(|e| format!("connect vsock {HOST_CID}:{CUDA_PORT}: {e}"))?;
    let mut cu = Client::new(stream);

    cu.init()?;
    let count = cu.device_get_count()?;
    if count < 1 {
        return Err("no CUDA devices reported by host".into());
    }
    let name = cu.device_get_name(0)?;
    let _ctx = cu.ctx_create(0)?;
    println!("smolvm-cuda: host device 0 = {name}");

    // Load an arbitrary module + look up the kernel by name (the general path).
    let module = cu.module_load_data(VECADD_PTX.as_bytes())?;
    let func = cu.module_get_function(module, "vecadd")?;

    let n: usize = 1024;
    let bytes = (n * 4) as u64;
    let a: Vec<f32> = (0..n).map(|i| i as f32).collect();
    let b: Vec<f32> = (0..n).map(|i| (2 * i) as f32).collect();

    let da = cu.mem_alloc(bytes)?;
    let db = cu.mem_alloc(bytes)?;
    let dc = cu.mem_alloc(bytes)?;
    cu.memcpy_htod(da, as_bytes(&a), 0)?;
    cu.memcpy_htod(db, as_bytes(&b), 0)?;

    // kernelParams: one little-endian blob per arg, in declaration order.
    let params = vec![
        da.to_le_bytes().to_vec(),
        db.to_le_bytes().to_vec(),
        dc.to_le_bytes().to_vec(),
        (n as u32).to_le_bytes().to_vec(),
    ];
    let block = 256u32;
    let grid = (n as u32).div_ceil(block);
    cu.launch_kernel(func, [grid, 1, 1], [block, 1, 1], 0, 0, &params)?;
    cu.ctx_synchronize()?;

    let out = cu.memcpy_dtoh(dc, bytes, 0)?;
    let c: Vec<f32> = out
        .chunks_exact(4)
        .map(|p| f32::from_le_bytes(p.try_into().unwrap()))
        .collect();

    for i in 0..n {
        let expect = a[i] + b[i];
        if (c[i] - expect).abs() > 1e-3 {
            return Err(format!("mismatch at {i}: got {} want {expect}", c[i]).into());
        }
    }
    cu.mem_free(da)?;
    cu.mem_free(db)?;
    cu.mem_free(dc)?;
    println!(
        "smolvm-cuda: vecadd n={n} verified (c[1]={}, c[{}]={})",
        c[1],
        n - 1,
        c[n - 1]
    );
    println!("SMOLVM-CUDA-OK");
    Ok(())
}

#[cfg(target_os = "linux")]
fn as_bytes(v: &[f32]) -> &[u8] {
    // SAFETY: f32 has no padding/invalid bit patterns; reading its bytes is sound.
    unsafe { std::slice::from_raw_parts(v.as_ptr() as *const u8, std::mem::size_of_val(v)) }
}

#[cfg(target_os = "linux")]
fn main() {
    if let Err(e) = run() {
        eprintln!("smolvm-cuda: ERROR: {e}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("smolvm-cuda-run runs only inside a Linux guest microVM");
    std::process::exit(1);
}
