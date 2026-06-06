//! Verifies the read_file non-regular-file fix: reading a directory or an
//! unbounded special file must return a CLEAN error and NOT poison the agent
//! connection (previously a dir read bricked the machine; /dev/zero hung).
use smolvm::embedded::{EmbeddedRuntime, MachineSpec};
use smolvm::VmResources;
use std::time::Duration;

fn main() {
    let rt = EmbeddedRuntime::new().expect("runtime");
    let name = "readfile-fix-test";
    let _ = rt.create_machine(MachineSpec {
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
    });
    rt.start_machine(name).expect("start");

    let echo = |label: &str| match rt.exec(
        name,
        vec!["echo".into(), label.into()],
        vec![],
        None,
        Some(Duration::from_secs(10)),
    ) {
        Ok((code, out, _)) => println!(
            "  {label}: HEALTHY exit={code} out={:?}",
            String::from_utf8_lossy(&out).trim()
        ),
        Err(e) => println!("  {label}: POISONED → {e}"),
    };

    echo("before");
    match rt.read_file(name, "/tmp") {
        Ok(b) => println!("readFile(/tmp dir): UNEXPECTED ok ({} bytes)", b.len()),
        Err(e) => println!("readFile(/tmp dir): clean error → {e}"),
    }
    echo("after-dir");
    match rt.read_file(name, "/dev/zero") {
        Ok(b) => println!("readFile(/dev/zero): UNEXPECTED ok ({} bytes)", b.len()),
        Err(e) => println!("readFile(/dev/zero): clean error → {e}"),
    }
    echo("after-devzero");
    // sanity: a real file still reads
    let _ = rt.exec(
        name,
        vec![
            "sh".into(),
            "-c".into(),
            "echo content > /tmp/real.txt".into(),
        ],
        vec![],
        None,
        None,
    );
    match rt.read_file(name, "/tmp/real.txt") {
        Ok(b) => println!(
            "readFile(/tmp/real.txt): ok → {:?}",
            String::from_utf8_lossy(&b).trim()
        ),
        Err(e) => println!("readFile(/tmp/real.txt): UNEXPECTED error → {e}"),
    }

    rt.delete_machine(name).expect("delete");
}
