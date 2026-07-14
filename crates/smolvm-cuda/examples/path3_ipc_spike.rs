//! Path 3 primitive spike — validates the address-preserving IPC primitives the
//! per-clone-process isolation needs:
//!   * `mem_create_exportable` + `mem_export_handle` → a POSIX fd for a physical,
//!   * `mem_import_handle` → the physical back, mapped at a SECOND VA that must
//!     alias the first (reads back bytes written through VA_a), and
//!   * `mem_address_reserve_fixed` → reserve at an exact VA (place a clone's
//!     memory at the golden's address).
//! Cross-process separate-UVA behavior is proven in scratchpad/spike_vmm_ipc.py;
//! this validates the in-tree `GpuBackend` primitives added for Path 3.
//!
//! Run: cargo run --release --example path3_ipc_spike -p smolvm-cuda

#[cfg(feature = "gpu")]
fn main() {
    use smolvm_cuda::host::{Backend, GpuBackend};
    let mut b = match GpuBackend::load() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("path3_ipc_spike: no CUDA driver: {e}");
            std::process::exit(2);
        }
    };
    b.init().expect("cuInit");
    let _ctx = b.primary_ctx_retain(0).expect("primary ctx retain");
    let dev = 0;

    let gran = b
        .mem_get_allocation_granularity(dev, 0)
        .expect("granularity");
    assert!(gran > 0, "granularity must be > 0");
    let size = gran; // one allocation granule

    // Golden: exportable physical, mapped at VA_a, filled with a pattern.
    let h = b
        .mem_create_exportable(size, dev)
        .expect("mem_create_exportable");
    let va_a = b.mem_address_reserve(size, gran).expect("reserve a");
    b.mem_map(va_a, size, 0, h).expect("map a");
    b.mem_set_access(va_a, size, dev).expect("set_access a");
    let pattern: Vec<u8> = (0..size)
        .map(|i| (i as u8).wrapping_mul(31) ^ 0xAB)
        .collect();
    b.memcpy_htod(va_a, &pattern, 0).expect("h2d");

    // Export the physical to a POSIX fd, then import it back to a fresh handle.
    let fd = b.mem_export_handle(h).expect("export");
    assert!(fd >= 0, "export gave a bad fd: {fd}");
    let h2 = b.mem_import_handle(fd).expect("import");

    // Map the imported physical at a DIFFERENT VA — it must alias the same memory.
    let va_b = b.mem_address_reserve(size, gran).expect("reserve b");
    b.mem_map(va_b, size, 0, h2).expect("map b");
    b.mem_set_access(va_b, size, dev).expect("set_access b");
    let got = b.memcpy_dtoh(va_b, size, 0).expect("d2h");
    assert_eq!(
        got, pattern,
        "imported mapping does not alias the exported physical"
    );

    // Fixed-address reservation: reserve a region, free it, re-reserve at that
    // exact VA — proves the addr hint is honored (place clone memory at golden VA).
    let probe = b.mem_address_reserve(size, gran).expect("reserve probe");
    b.mem_address_free(probe, size).expect("free probe");
    let fixed = b
        .mem_address_reserve_fixed(size, gran, probe)
        .expect("reserve fixed");
    assert_eq!(
        fixed, probe,
        "fixed-address reserve did not honor the requested VA"
    );

    println!(
        "PATH3-IPC-SPIKE PASS: export/import aliases ({size} B); fixed-addr reserve honored @ {probe:#x}"
    );
}

#[cfg(not(feature = "gpu"))]
fn main() {
    eprintln!("path3_ipc_spike requires the `gpu` feature");
    std::process::exit(2);
}
