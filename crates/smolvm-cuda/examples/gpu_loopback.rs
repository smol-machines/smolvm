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
    cu.init(0).expect("cuInit");
    let count = cu.device_get_count().expect("device count");
    let name = cu.device_get_name(0).expect("device name");
    let vram = cu.device_total_mem(0).expect("total mem");
    println!(
        "gpu_loopback: {count} device(s); device 0 = {name} ({} MiB)",
        vram / (1024 * 1024)
    );
    let ctx = cu.ctx_create(0).expect("ctx create");

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
        .as_chunks::<4>()
        .0
        .iter()
        .map(|p| f32::from_le_bytes(*p))
        .collect();
    for i in 0..n {
        let expect = a[i] + b[i]; // i + 3i = 4i
        if (c[i] - expect).abs() > 1e-2 {
            eprintln!("gpu_loopback: MISMATCH at {i}: got {} want {expect}", c[i]);
            std::process::exit(3);
        }
    }

    // Capture the same topology twice with different kernel arguments, update
    // the first executable in place, and verify that replay uses graph 2's
    // parameters. This is the dynamic-input path used by piecewise graph runtimes.
    let stream = cu.stream_create(1).expect("graph stream");
    let graph_one = (1_u64 << 63) | 0x101;
    let graph_two = (1_u64 << 63) | 0x102;
    let graph_exec = (1_u64 << 63) | 0x201;
    cu.stream_begin_capture(stream, 2)
        .expect("begin first capture");
    cu.launch_kernel(
        func,
        [grid, 1, 1],
        [block, 1, 1],
        0,
        stream,
        &[
            da.to_le_bytes().to_vec(),
            db.to_le_bytes().to_vec(),
            dc.to_le_bytes().to_vec(),
            (n as u32).to_le_bytes().to_vec(),
        ],
    )
    .expect("capture first kernel");
    assert_eq!(
        cu.stream_end_capture(stream, graph_one)
            .expect("end first capture"),
        1
    );
    cu.graph_instantiate(graph_one, graph_exec)
        .expect("instantiate first graph");

    cu.stream_begin_capture(stream, 2)
        .expect("begin updated capture");
    cu.launch_kernel(
        func,
        [grid, 1, 1],
        [block, 1, 1],
        0,
        stream,
        &[
            da.to_le_bytes().to_vec(),
            da.to_le_bytes().to_vec(),
            dc.to_le_bytes().to_vec(),
            (n as u32).to_le_bytes().to_vec(),
        ],
    )
    .expect("capture updated kernel");
    assert_eq!(
        cu.stream_end_capture(stream, graph_two)
            .expect("end updated capture"),
        1
    );
    assert_eq!(
        cu.graph_exec_update(graph_exec, graph_two)
            .expect("update graph exec"),
        0
    );
    cu.graph_launch(graph_exec, stream)
        .expect("launch updated graph");
    cu.stream_synchronize(stream)
        .expect("synchronize updated graph");
    let updated = cu.memcpy_dtoh(dc, bytes, stream).expect("updated d2h");
    let updated: Vec<f32> = updated
        .as_chunks::<4>()
        .0
        .iter()
        .map(|p| f32::from_le_bytes(*p))
        .collect();
    for (i, &value) in updated.iter().enumerate() {
        let expect = (2 * i) as f32;
        if (value - expect).abs() > 1e-2 {
            eprintln!("gpu_loopback: graph update mismatch at {i}: got {value} want {expect}");
            std::process::exit(4);
        }
    }

    // With SMOLVM_CUDA_AUTO_GRAPH=1 these two asynchronous launches are
    // automatically grouped at StreamSynchronize. Repeating the shape with
    // different pointers exercises host capture + GraphExecUpdate without any
    // framework graph API calls; the final exact repeat exercises cached replay.
    if std::env::var("SMOLVM_CUDA_AUTO_GRAPH").as_deref() == Ok("1") {
        let dd = cu.mem_alloc(bytes).expect("alloc auto-graph output");
        let run_segment = |cu: &mut Client<TcpStream>, left: u64, right: u64, tail: u64| {
            cu.launch_kernel(
                func,
                [grid, 1, 1],
                [block, 1, 1],
                0,
                stream,
                &[
                    left.to_le_bytes().to_vec(),
                    right.to_le_bytes().to_vec(),
                    dc.to_le_bytes().to_vec(),
                    (n as u32).to_le_bytes().to_vec(),
                ],
            )?;
            cu.launch_kernel(
                func,
                [grid, 1, 1],
                [block, 1, 1],
                0,
                stream,
                &[
                    dc.to_le_bytes().to_vec(),
                    tail.to_le_bytes().to_vec(),
                    dd.to_le_bytes().to_vec(),
                    (n as u32).to_le_bytes().to_vec(),
                ],
            )?;
            cu.stream_synchronize(stream)
        };
        run_segment(&mut cu, da, db, da).expect("auto graph eager observation");
        run_segment(&mut cu, da, da, db).expect("auto graph second observation");
        run_segment(&mut cu, db, db, da).expect("auto graph third observation");
        run_segment(&mut cu, da, db, da).expect("auto graph promotion");
        run_segment(&mut cu, db, db, da).expect("auto graph parameter update");
        run_segment(&mut cu, db, db, da).expect("auto graph exact replay");
        let auto = cu
            .memcpy_dtoh(dd, bytes, stream)
            .expect("auto graph output");
        for (i, value) in auto.as_chunks::<4>().0.iter().enumerate() {
            let value = f32::from_le_bytes(*value);
            let expect = (7 * i) as f32;
            if (value - expect).abs() > 1e-2 {
                eprintln!("gpu_loopback: auto graph mismatch at {i}: got {value} want {expect}");
                std::process::exit(5);
            }
        }
        cu.mem_free(dd).ok();
        println!("AUTO-GRAPH-OK: eager, capture, update, and exact replay verified");
    }
    if let Some(segments) = std::env::var("SMOLVM_CUDA_AUTO_GRAPH_BENCH_SEGMENTS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|&value| value > 0)
    {
        let width = std::env::var("SMOLVM_CUDA_AUTO_GRAPH_BENCH_WIDTH")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|&value| value > 1)
            .unwrap_or(32);
        for dynamic in [false, true] {
            // Consumer cards aggressively downclock between commands; enough
            // warmup is required so baseline and graph modes measure steady
            // execution rather than different clock-ramp phases.
            for iteration in 0..100 {
                let second = if dynamic && iteration % 2 == 0 {
                    da
                } else {
                    db
                };
                run_bench_segment(&mut cu, func, grid, block, stream, da, second, dc, n, width);
            }
            let started = std::time::Instant::now();
            for iteration in 0..segments {
                let second = if dynamic && iteration.is_multiple_of(2) {
                    da
                } else {
                    db
                };
                run_bench_segment(&mut cu, func, grid, block, stream, da, second, dc, n, width);
            }
            let elapsed = started.elapsed();
            let launches = segments * width;
            println!(
                "AUTO-GRAPH-BENCH mode={} segments={} width={} elapsed_ms={:.3} launches_per_s={:.0}",
                if dynamic { "dynamic" } else { "fixed" },
                segments,
                width,
                elapsed.as_secs_f64() * 1000.0,
                launches as f64 / elapsed.as_secs_f64()
            );
        }
    }
    if count >= 2 {
        let pci0 = cu.device_get_pci_bus_id(0).expect("device 0 PCI id");
        let pci1 = cu.device_get_pci_bus_id(1).expect("device 1 PCI id");
        assert_ne!(pci0, pci1, "distinct GPUs must expose distinct PCI IDs");
        let can_peer = cu
            .device_can_access_peer(1, 0)
            .expect("peer-access capability");
        let ctx0 = cu.primary_ctx_retain(0).expect("retain device 0");
        cu.ctx_set_current(ctx0).expect("bind device 0");
        let peer_bytes = 4096u64;
        let source: Vec<u32> = (0..peer_bytes as u32 / 4).collect();
        let peer_src = cu.mem_alloc(peer_bytes).expect("device 0 peer source");
        cu.memcpy_htod(peer_src, bytemuck_u32(&source), 0)
            .expect("upload peer source");

        let ctx1 = cu.primary_ctx_retain(1).expect("retain device 1");
        cu.ctx_set_current(ctx1).expect("bind device 1");
        let peer_dst = cu.mem_alloc(peer_bytes).expect("device 1 peer destination");
        if can_peer != 0 {
            cu.device_enable_peer_access(0, 0)
                .expect("enable device 1 to device 0 peer access");
        }
        cu.memcpy_peer_async(peer_dst, 1, peer_src, 0, peer_bytes, 0)
            .expect("peer copy");
        cu.ctx_synchronize().expect("peer copy synchronize");
        let copied = cu
            .memcpy_dtoh(peer_dst, peer_bytes, 0)
            .expect("download peer destination");
        assert_eq!(copied, bytemuck_u32(&source));
        if can_peer != 0 {
            cu.device_disable_peer_access(0)
                .expect("disable peer access");
        }
        cu.mem_free(peer_dst).ok();
        cu.ctx_set_current(ctx0).expect("restore device 0");
        cu.mem_free(peer_src).ok();
        cu.primary_ctx_release(1).ok();
        cu.primary_ctx_release(0).ok();
        // The main workload's module, graphs, stream, and allocations belong
        // to the explicit device-0 context created above, not its primary
        // context. Restore it before destroying those context-owned objects.
        cu.ctx_set_current(ctx).expect("restore original context");
        println!("MULTI-GPU-OK: device 0 ({pci0}) -> device 1 ({pci1}), peer_access={can_peer}");
    }
    cu.graph_exec_destroy(graph_exec).ok();
    cu.graph_destroy(graph_one).ok();
    cu.graph_destroy(graph_two).ok();
    cu.stream_destroy(stream).ok();
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
    println!("GRAPH-UPDATE-OK: topology-compatible parameters patched in place");
}

#[allow(clippy::too_many_arguments)]
fn run_bench_segment(
    cu: &mut Client<TcpStream>,
    func: u64,
    grid: u32,
    block: u32,
    stream: u64,
    first: u64,
    second: u64,
    output: u64,
    n: usize,
    width: usize,
) {
    for _ in 0..width {
        cu.launch_kernel(
            func,
            [grid, 1, 1],
            [block, 1, 1],
            0,
            stream,
            &[
                first.to_le_bytes().to_vec(),
                second.to_le_bytes().to_vec(),
                output.to_le_bytes().to_vec(),
                (n as u32).to_le_bytes().to_vec(),
            ],
        )
        .expect("benchmark launch");
    }
    cu.stream_synchronize(stream)
        .expect("benchmark synchronize");
}

/// Reinterpret `&[f32]` as bytes (f32 has no invalid bit patterns).
fn bytemuck(v: &[f32]) -> &[u8] {
    // SAFETY: f32 is plain-old-data; reading its bytes is sound.
    unsafe { std::slice::from_raw_parts(v.as_ptr() as *const u8, std::mem::size_of_val(v)) }
}

fn bytemuck_u32(v: &[u32]) -> &[u8] {
    // SAFETY: u32 is plain-old-data; reading its bytes is sound.
    unsafe { std::slice::from_raw_parts(v.as_ptr() as *const u8, std::mem::size_of_val(v)) }
}
