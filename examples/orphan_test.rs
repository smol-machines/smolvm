//! Manual verification harness for the parent-death watchdog (orphaned-VMM leak).
//!
//! Mimics an SDK embedder: it owns a VM in-process (sets SMOLVM_BOOT_BINARY,
//! never detaches), prints its pid, then blocks forever. The driver script
//! `kill -9`s this process to simulate a host crash and asserts the `_boot-vm`
//! VMM exits instead of orphaning. Run via `cargo run --example orphan_test`.
use smolvm::embedded::{EmbeddedRuntime, MachineSpec};
use smolvm::VmResources;

fn main() {
    let name = std::env::var("ORPHAN_TEST_VM").unwrap_or_else(|_| "orphan-test".into());
    let rt = EmbeddedRuntime::new().expect("create embedded runtime");

    let spec = MachineSpec {
        name: name.clone(),
        mounts: vec![],
        ports: vec![],
        resources: VmResources {
            cpus: 1,
            memory_mib: 512,
            network: true,
            ..Default::default()
        },
        persistent: false,
    };
    let _ = rt.create_machine(spec); // ignore "already exists" on reruns
    rt.start_machine(&name).expect("start machine");

    let pid = rt.pid(&name).unwrap_or(-1);
    // Sentinel the driver greps for: embedder pid + the VMM child pid.
    println!(
        "ORPHAN_TEST_READY embedder={} vmm={}",
        std::process::id(),
        pid
    );
    use std::io::Write;
    let _ = std::io::stdout().flush();

    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}
