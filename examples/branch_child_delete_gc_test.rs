//! Verifies an embedded (SDK) delete of a branch child reclaims the parent's
//! fork generation that only that child referenced, as the CLI delete does.
use smolvm::embedded::{EmbeddedRuntime, MachineSpec};
use smolvm::VmResources;

fn generations(name: &str) -> usize {
    std::fs::read_dir(smolvm::agent::vm_data_dir(name).join("s"))
        .map(|entries| entries.filter_map(|entry| entry.ok()).count())
        .unwrap_or(0)
}

fn main() {
    let rt = EmbeddedRuntime::new().expect("runtime");
    let source = "gc-source";
    for name in ["gc-kid-1", "gc-kid-2", source] {
        let _ = rt.delete_machine(name);
    }
    rt.create_machine(MachineSpec {
        name: source.into(),
        resources: VmResources {
            cpus: 1,
            memory_mib: 512,
            network: false,
            ..Default::default()
        },
        persistent: true,
        forkable: true,
        ..Default::default()
    })
    .expect("create");
    rt.start_machine(source).expect("start");
    rt.fork_machine(source, "gc-kid-1", &[]).expect("branch 1");
    rt.fork_machine(source, "gc-kid-2", &[]).expect("branch 2");
    let before = generations(source);
    rt.delete_machine("gc-kid-1").expect("delete kid 1");
    let after = generations(source);
    println!("generations before={before} after={after}");
    for name in ["gc-kid-2", source] {
        rt.delete_machine(name).expect("cleanup");
    }
    if after < before {
        println!("PASS: deleting a child reclaimed its generation");
    } else {
        println!("FAIL: the parent kept the deleted child's generation");
        std::process::exit(1);
    }
}
