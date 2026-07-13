//! Verifies the large-output guard: a huge non-streaming exec returns a CLEAR
//! error (not a SIGPIPE-truncated result) and leaves the machine HEALTHY.
use smolvm::embedded::{EmbeddedRuntime, MachineSpec};
use smolvm::VmResources;

fn main() {
    let rt = EmbeddedRuntime::new().expect("runtime");
    let name = "largeoutput-test";
    let _ = rt.delete_machine(name);
    let _ = rt.create_machine(MachineSpec {
        name: name.into(),
        mounts: vec![],
        ports: vec![],
        resources: VmResources {
            cpus: 1,
            memory_mib: 1024,
            network: false,
            ..Default::default()
        },
        persistent: false,
        runtime_managed: false,
    });
    rt.start_machine(name).expect("start");
    // small output: works
    let (c, out, _) = rt
        .exec(
            name,
            vec!["echo".into(), "small".into()],
            vec![],
            None,
            None,
        )
        .unwrap();
    println!(
        "small exec: exit={c} out={:?}",
        String::from_utf8_lossy(&out).trim()
    );
    // ~40 MiB output: expect a clean error, not a truncated/SIGPIPE result
    match rt.exec(
        name,
        vec![
            "sh".into(),
            "-c".into(),
            "head -c 41943040 /dev/zero | tr '\\0' a".into(),
        ],
        vec![],
        None,
        None,
    ) {
        Ok((c, out, _)) => println!("BIG exec: UNEXPECTED ok exit={c} len={}", out.len()),
        Err(e) => println!("BIG exec: clean error -> {e}"),
    }
    // machine still healthy?
    match rt.exec(
        name,
        vec!["echo".into(), "after".into()],
        vec![],
        None,
        None,
    ) {
        Ok((_, out, _)) => println!(
            "after BIG: HEALTHY out={:?}",
            String::from_utf8_lossy(&out).trim()
        ),
        Err(e) => println!("after BIG: POISONED -> {e}"),
    }
    rt.delete_machine(name).expect("delete");
}
