//! Path 3 M1 routing probe: connect to a running cuda-daemon as an ISOLATING fork
//! clone (`init` with resume_token=1). With SMOLVM_CUDA_FORK_WORKERS=1 +
//! SMOLVM_CUDA_FORK_ISOLATE=1 the daemon serves us in a dedicated worker PROCESS
//! (its own CUDA context/UVA). We then run a real vecadd kernel and verify —
//! proving the routed worker process serves the clone correctly (M1).
//!
//! Run: cargo run --release --example m1_route_probe -p smolvm-cuda -- <daemon.sock>
use smolvm_cuda::client::Client;
use std::os::unix::net::UnixStream;

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

fn bytemuck(v: &[f32]) -> &[u8] {
    // SAFETY: f32 has no invalid bit patterns; reading its bytes is sound.
    unsafe { std::slice::from_raw_parts(v.as_ptr() as *const u8, std::mem::size_of_val(v)) }
}

fn main() {
    let sock = std::env::args()
        .nth(1)
        .expect("usage: m1_route_probe <daemon.sock>");
    let mut stream = UnixStream::connect(&sock).expect("connect daemon");
    // Identify as a fork clone (proxy preamble): magic + clone id.
    {
        use std::io::Write as _;
        let mut p = smolvm_cuda::proto::CLONE_PREAMBLE_MAGIC.to_vec();
        p.extend_from_slice(&u64::from(std::process::id()).to_le_bytes());
        stream.write_all(&p).expect("clone preamble");
    }
    let mut cu = Client::new(stream);
    let token = cu.init(1).expect("init (isolating clone, resume_token=1)");
    eprintln!("m1_route_probe: connected as isolating clone; server token={token}");
    let _ctx = cu.primary_ctx_retain(0).expect("primary ctx retain");
    let name = cu.device_get_name(0).expect("device name");

    let module = cu
        .module_load_data(VECADD_PTX.as_bytes())
        .expect("module load");
    let func = cu
        .module_get_function(module, "vecadd")
        .expect("get function");
    let n: usize = 1 << 16;
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
    let ok = (0..n).all(|i| (c[i] - (a[i] + b[i])).abs() < 1e-2);
    println!(
        "M1-ROUTE-PROBE {}: device={name} vecadd[7]={} (want {})",
        if ok { "PASS" } else { "FAIL" },
        c[7],
        a[7] + b[7]
    );
    std::process::exit(if ok { 0 } else { 3 });
}
