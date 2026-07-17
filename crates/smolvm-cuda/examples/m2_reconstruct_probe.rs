//! Path 3 M2 validation (with isolation): golden allocates VMM memory (exportable)
//! and writes pattern P1; a clone (routed to a worker PROCESS) reconstructs the
//! golden's memory at the golden's EXACT VA, reads P1 (shared data), then WRITES
//! P2. The golden then re-reads its VA and must still see P1 — proving the clone's
//! writes hit a PRIVATE copy at the same virtual address (address-preserving
//! isolation through the real daemon).
//!
//! Roles:  m2_reconstruct_probe golden <sock> <statefile>
//!         m2_reconstruct_probe clone  <sock> <statefile>
use smolvm_cuda::client::Client;
use std::os::unix::net::UnixStream;
use std::path::Path;

fn pattern(size: u64, seed: u8) -> Vec<u8> {
    (0..size)
        .map(|i| (i as u8).wrapping_mul(37) ^ seed)
        .collect()
}
fn wait_for(p: &str) {
    for _ in 0..600 {
        if Path::new(p).exists() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let (role, sock, state) = (a[1].as_str(), a[2].as_str(), a[3].as_str());
    let done = format!("{state}.clonedone");
    match role {
        "golden" => {
            let mut cu = Client::new(UnixStream::connect(sock).expect("connect"));
            let token = cu.init(0).expect("init golden");
            cu.primary_ctx_retain(0).expect("ctx");
            let gran = cu.mem_get_allocation_granularity(0, 0).expect("gran");
            let size = gran;
            let va = cu.mem_address_reserve(size, gran).expect("reserve");
            let h = cu
                .mem_create(size, 0)
                .expect("create (exportable under PATH3)");
            cu.mem_map(va, size, 0, h).expect("map");
            cu.mem_set_access(va, size, 0).expect("set_access");
            cu.memcpy_htod(va, &pattern(size, 0x5A), 0).expect("h2d P1");
            std::fs::write(state, format!("{token} {va} {size}")).expect("write state");
            eprintln!("golden: token={token} va={va:#x} — wrote P1, waiting for clone");
            wait_for(&done); // clone has written P2 to the same VA in its own process
            let after = cu.memcpy_dtoh(va, size, 0).expect("golden re-read");
            let uncorrupted = after == pattern(size, 0x5A);
            std::fs::write(
                format!("{state}.goldenafter"),
                if uncorrupted {
                    "UNCORRUPTED"
                } else {
                    "CORRUPTED"
                },
            )
            .ok();
            eprintln!("golden: re-read after clone write — uncorrupted={uncorrupted}");
            loop {
                std::thread::sleep(std::time::Duration::from_secs(3600));
            }
        }
        "clone" => {
            let s = std::fs::read_to_string(state).expect("read state");
            let p: Vec<u64> = s.split_whitespace().map(|x| x.parse().unwrap()).collect();
            let (token, va, size) = (p[0], p[1], p[2]);
            let mut conn = UnixStream::connect(sock).expect("connect");
            // Identify as a fork clone (proxy preamble): magic + clone id.
            {
                use std::io::Write as _;
                let mut p = smolvm_cuda::proto::CLONE_PREAMBLE_MAGIC.to_vec();
                p.extend_from_slice(&u64::from(std::process::id()).to_le_bytes());
                conn.write_all(&p).expect("clone preamble");
            }
            let mut cu = Client::new(conn);
            let t = cu.init(token).expect("init clone");
            cu.primary_ctx_retain(0).expect("ctx");
            eprintln!("clone: resumed token={token} (server={t}); golden VA {va:#x}");
            let read_ok = cu.memcpy_dtoh(va, size, 0).expect("d2h") == pattern(size, 0x5A);
            cu.memcpy_htod(va, &pattern(size, 0xC3), 0)
                .expect("clone write P2");
            let write_ok = cu.memcpy_dtoh(va, size, 0).expect("d2h") == pattern(size, 0xC3);
            std::fs::write(&done, "done").ok();
            println!(
                "M2-ISO-PROBE(clone): read_golden_data={read_ok} clone_private_write={write_ok}"
            );
            std::process::exit(if read_ok && write_ok { 0 } else { 4 });
        }
        _ => std::process::exit(2),
    }
}
