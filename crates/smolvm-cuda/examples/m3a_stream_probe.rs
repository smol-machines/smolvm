//! Path 3 M3a (streams/events): golden creates a stream + event, loads a module,
//! allocates VMM buffers (a,b,c), writes a,b. A clone (routed to a worker PROCESS)
//! reconstructs memory + reloads the module AND recreates the golden's stream +
//! event, then LAUNCHES the kernel on the golden's INHERITED stream and records +
//! synchronizes the golden's INHERITED event. The worker translates each inherited
//! handle to its own recreated one → vecadd runs on the clone's stream → c = a+b.
//! Proves stream + event handle reconstruction end-to-end through the daemon.
//!
//! Roles:  m3a_stream_probe golden <sock> <statefile>  |  ... clone <sock> <statefile>
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

fn bytes(v: &[f32]) -> &[u8] {
    unsafe { std::slice::from_raw_parts(v.as_ptr() as *const u8, std::mem::size_of_val(v)) }
}
fn vmm_buf(cu: &mut Client<UnixStream>, size: u64, gran: u64) -> u64 {
    let va = cu.mem_address_reserve(size, gran).expect("reserve");
    let h = cu.mem_create(size, 0).expect("create");
    cu.mem_map(va, size, 0, h).expect("map");
    cu.mem_set_access(va, size, 0).expect("access");
    va
}

const N: usize = 256;

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let (role, sock, state) = (a[1].as_str(), a[2].as_str(), a[3].as_str());
    let done = format!("{state}.clonedone");
    match role {
        "golden" => {
            let mut cu = Client::new(UnixStream::connect(sock).expect("connect"));
            let token = cu.init(0).expect("init");
            cu.primary_ctx_retain(0).expect("ctx");
            let module = cu.module_load_data(VECADD_PTX.as_bytes()).expect("module");
            let func = cu.module_get_function(module, "vecadd").expect("func");
            // The handles the clone will inherit and must have translated.
            let stream = cu.stream_create(0).expect("stream");
            let event = cu.event_create(0).expect("event");
            let gran = cu.mem_get_allocation_granularity(0, 0).expect("gran");
            let (va_a, va_b, va_c) = (
                vmm_buf(&mut cu, gran, gran),
                vmm_buf(&mut cu, gran, gran),
                vmm_buf(&mut cu, gran, gran),
            );
            let av: Vec<f32> = (0..N).map(|i| i as f32).collect();
            let bv: Vec<f32> = (0..N).map(|i| (3 * i) as f32).collect();
            cu.memcpy_htod(va_a, bytes(&av), 0).expect("h2d a");
            cu.memcpy_htod(va_b, bytes(&bv), 0).expect("h2d b");
            cu.ctx_synchronize().ok(); // commit writes before the clone imports the physical
            std::fs::write(
                state,
                format!("{token} {va_a} {va_b} {va_c} {func} {stream} {event}"),
            )
            .unwrap();
            eprintln!(
                "golden: token={token} func={func:#x} stream={stream:#x} event={event:#x} — staying connected"
            );
            for _ in 0..600 {
                if std::path::Path::new(&done).exists() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            loop {
                std::thread::sleep(std::time::Duration::from_secs(3600));
            }
        }
        "clone" => {
            let s = std::fs::read_to_string(state).unwrap();
            let p: Vec<u64> = s.split_whitespace().map(|x| x.parse().unwrap()).collect();
            let (token, va_a, va_b, va_c, func, stream, event) =
                (p[0], p[1], p[2], p[3], p[4], p[5], p[6]);
            let mut conn = UnixStream::connect(sock).expect("connect");
            // Identify as a fork clone (proxy preamble): magic + clone id.
            {
                use std::io::Write as _;
                let mut p = smolvm_cuda::proto::CLONE_PREAMBLE_MAGIC.to_vec();
                p.extend_from_slice(&u64::from(std::process::id()).to_le_bytes());
                conn.write_all(&p).expect("clone preamble");
            }
            let mut cu = Client::new(conn);
            cu.init(token).expect("init clone");
            cu.primary_ctx_retain(0).expect("ctx");
            eprintln!(
                "clone: launching vecadd on INHERITED stream={stream:#x} func={func:#x} event={event:#x}"
            );
            let block = 256u32;
            let grid = (N as u32).div_ceil(block);
            cu.launch_kernel(
                func, // the golden's raw function handle — worker must translate
                [grid, 1, 1],
                [block, 1, 1],
                0,
                stream, // the golden's raw stream handle — worker must translate
                &[
                    va_a.to_le_bytes().to_vec(),
                    va_b.to_le_bytes().to_vec(),
                    va_c.to_le_bytes().to_vec(),
                    (N as u32).to_le_bytes().to_vec(),
                ],
            )
            .expect("launch (inherited stream+func)");
            // Record + sync the golden's INHERITED event on the inherited stream.
            cu.event_record(event, stream).expect("event_record");
            cu.event_synchronize(event).expect("event_synchronize");
            cu.stream_synchronize(stream).expect("stream_synchronize");
            let out = cu.memcpy_dtoh(va_c, (N * 4) as u64, 0).expect("d2h");
            let c: Vec<f32> = out
                .chunks_exact(4)
                .map(|p| f32::from_le_bytes(p.try_into().unwrap()))
                .collect();
            let ok = (0..N).all(|i| (c[i] - (4 * i) as f32).abs() < 1e-2);
            std::fs::write(&done, "done").ok();
            println!(
                "M3A-STREAM-PROBE {}: clone ran kernel on inherited stream + synced inherited event; c[7]={} (want 28)",
                if ok { "PASS" } else { "FAIL" },
                c[7]
            );
            std::process::exit(if ok { 0 } else { 5 });
        }
        _ => std::process::exit(2),
    }
}
