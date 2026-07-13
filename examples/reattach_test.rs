//! Verifies start-or-reconnect for a stopped persistent machine — the path the
//! SDK's local `Machine.connect()` now uses (native connect → start_machine).
use smolvm::embedded::{EmbeddedRuntime, MachineSpec};
use smolvm::VmResources;

fn main() {
    let rt = EmbeddedRuntime::new().expect("runtime");
    let name = "reattach-test";
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
        persistent: true,
        runtime_managed: false,
    })
    .expect("create");
    rt.start_machine(name).expect("start");
    rt.exec(
        name,
        vec![
            "sh".into(),
            "-c".into(),
            "echo survived-restart > /root/persist.txt".into(),
        ],
        vec![],
        None,
        None,
    )
    .expect("write");
    println!("wrote /root/persist.txt; stopping machine...");
    rt.stop_machine(name).expect("stop");

    println!("reattaching to stopped persistent machine via start_machine() ...");
    rt.start_machine(name)
        .expect("reattach (start-or-reconnect)");
    let (code, out, _) = rt
        .exec(
            name,
            vec!["cat".into(), "/root/persist.txt".into()],
            vec![],
            None,
            None,
        )
        .expect("read after reattach");
    let content = String::from_utf8_lossy(&out);
    println!("readback: exit={code} content={:?}", content.trim());
    println!(
        "{}",
        if content.trim() == "survived-restart" {
            "RESULT: PASS — reattached + data persisted"
        } else {
            "RESULT: FAIL"
        }
    );

    rt.delete_machine(name).expect("delete");
}
