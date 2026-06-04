//! Verifies delete_machine is idempotent (double-delete no longer errors).
use smolvm::embedded::{EmbeddedRuntime, MachineSpec};
use smolvm::VmResources;

fn main() {
    let rt = EmbeddedRuntime::new().expect("runtime");
    let name = "doubledelete-test";
    let _ = rt.delete_machine(name); // clean slate
    rt.create_machine(MachineSpec {
        name: name.into(),
        mounts: vec![],
        ports: vec![],
        resources: VmResources {
            cpus: 1,
            memory_mib: 512,
            network: false,
            ..Default::default()
        },
        persistent: false,
    })
    .expect("create");
    rt.delete_machine(name).expect("first delete");
    match rt.delete_machine(name) {
        Ok(()) => println!("PASS: second delete is idempotent (no error)"),
        Err(e) => println!("FAIL: second delete errored: {e}"),
    }
}
