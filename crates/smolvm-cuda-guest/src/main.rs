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

    // Cross-VM device-memory sharing probe (validates the shared-daemon model):
    //  writer — retain the primary context, allocate a buffer, write a known
    //           pattern, print its device pointer, then hold the connection open.
    //  reader — retain the same primary context (shared daemon → same GPU
    //           context) and read the writer's pointer back.
    match std::env::var("SMOLVM_CUDA_TEST").as_deref() {
        Ok("writer") => return run_writer(&mut cu),
        Ok("reader") => return run_reader(&mut cu),
        Ok("loop") => {
            drop(cu);
            return run_loop();
        }
        _ => {}
    }

    cu.init(0)?;
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

/// The shared pattern the writer stores and the reader verifies.
#[cfg(target_os = "linux")]
const PROBE_PATTERN: [f32; 4] = [3.14, 2.71, 1.41, 1.61];

#[cfg(target_os = "linux")]
type VClient = smolvm_cuda::client::Client<vsock::VsockStream>;

/// Open a fresh vsock connection to the CUDA host, run the handshake resuming
/// `resume_token` (0 first time), and retain the primary context. A short
/// socket timeout makes a severed connection surface as an error instead of
/// hanging — the signal a fork clone uses to reconnect (its pid is unchanged
/// across the VM snapshot, so pid-based detection can't fire).
#[cfg(target_os = "linux")]
fn connect_cuda(resume_token: u64) -> Result<(VClient, u64), Box<dyn std::error::Error>> {
    use vsock::VsockStream;
    let stream = VsockStream::connect_with_cid_port(HOST_CID, CUDA_PORT)?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(std::time::Duration::from_secs(2)))?;
    let mut cu = VClient::new(stream);
    let token = cu.init(resume_token)?;
    cu.primary_ctx_retain(0)?;
    Ok((cu, token))
}

/// Long-lived probe for the VM-fork path: allocate a buffer with a known
/// pattern, then loop reading it back. On a transport error (the clone's
/// inherited connection is dead after the fork), reconnect — resuming the
/// parent session's token — and keep reading. Because every VM shares the
/// daemon's one GPU context, the reconnected clone reads the SAME device
/// pointer the parent allocated. Ticks are appended to `SMOLVM_CUDA_OUT` with a
/// per-boot tag so the host can see the golden vs. the clone.
#[cfg(target_os = "linux")]
fn run_loop() -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;
    let out = std::env::var("SMOLVM_CUDA_OUT").unwrap_or_else(|_| "/dev/stderr".into());
    let tag = std::fs::read_to_string("/etc/machine-id")
        .unwrap_or_default()
        .trim()
        .chars()
        .take(8)
        .collect::<String>();
    let mut append = |line: String| {
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&out)
        {
            let _ = writeln!(f, "{line}");
        }
    };

    let (mut cu, mut token) = connect_cuda(0)?;
    let dptr = cu.mem_alloc(16)?;
    cu.memcpy_htod(dptr, as_bytes(&PROBE_PATTERN), 0)?;
    cu.ctx_synchronize()?;
    append(format!("BOOT tag={tag} dptr=0x{dptr:x} token={token}"));

    for tick in 0.. {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        match cu.memcpy_dtoh(dptr, 16, 0) {
            Ok(bytes) => {
                let v: Vec<f32> = bytes
                    .chunks_exact(4)
                    .map(|p| f32::from_le_bytes(p.try_into().unwrap()))
                    .collect();
                let ok = v
                    .iter()
                    .zip(PROBE_PATTERN.iter())
                    .all(|(g, e)| (g - e).abs() < 1e-3);
                append(format!("TICK tag={tag} n={tick} t={now} ok={ok} v={v:?}"));
            }
            Err(e) => {
                append(format!("SEVERED tag={tag} n={tick} t={now} err={e}"));
                match connect_cuda(token) {
                    Ok((c, t)) => {
                        cu = c;
                        token = t;
                        let t2 = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_millis())
                            .unwrap_or(0);
                        append(format!("RECONNECT tag={tag} n={tick} t={t2} token={token}"));
                    }
                    Err(e2) => append(format!("RECONNECT-FAIL tag={tag} n={tick} err={e2}")),
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn run_writer(
    cu: &mut smolvm_cuda::client::Client<vsock::VsockStream>,
) -> Result<(), Box<dyn std::error::Error>> {
    cu.init(0)?;
    cu.primary_ctx_retain(0)?;
    let dptr = cu.mem_alloc(16)?;
    cu.memcpy_htod(dptr, as_bytes(&PROBE_PATTERN), 0)?;
    cu.ctx_synchronize()?;
    // The device pointer is a raw GPU address, valid in the daemon's shared
    // context for any other VM's connection.
    println!("DPTR=0x{dptr:x}");
    println!("WRITER-READY");
    // stdout is block-buffered when piped through the VM console; flush so the
    // orchestrator sees the pointer before we block holding the connection.
    std::io::Write::flush(&mut std::io::stdout())?;
    // Robust side channel: also publish the pointer to a writable mount so the
    // host can read it without depending on live console relay.
    if let Ok(path) = std::env::var("SMOLVM_CUDA_OUT") {
        std::fs::write(&path, format!("0x{dptr:x}\n"))?;
    }
    // Hold the connection (and thus the primary-context retain + allocation)
    // while a second VM reads it.
    std::thread::sleep(std::time::Duration::from_secs(180));
    Ok(())
}

#[cfg(target_os = "linux")]
fn run_reader(
    cu: &mut smolvm_cuda::client::Client<vsock::VsockStream>,
) -> Result<(), Box<dyn std::error::Error>> {
    cu.init(0)?;
    cu.primary_ctx_retain(0)?;
    let ptr_env = std::env::var("SMOLVM_CUDA_PTR")?;
    let dptr = u64::from_str_radix(ptr_env.trim().trim_start_matches("0x"), 16)?;
    let out = cu.memcpy_dtoh(dptr, 16, 0)?;
    let got: Vec<f32> = out
        .chunks_exact(4)
        .map(|p| f32::from_le_bytes(p.try_into().unwrap()))
        .collect();
    let ok = got
        .iter()
        .zip(PROBE_PATTERN.iter())
        .all(|(g, e)| (g - e).abs() < 1e-3);
    println!("READER read {got:?} from 0x{dptr:x} (expect {PROBE_PATTERN:?})");
    println!(
        "{}",
        if ok {
            "CROSS-VM-SHARED-OK"
        } else {
            "CROSS-VM-SHARED-FAIL"
        }
    );
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
