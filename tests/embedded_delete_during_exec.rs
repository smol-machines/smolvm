//! A streamed command that a delete cuts off reports the delete, and the
//! machine no longer reads as running by the time the caller hears of it.
//! Before, the caller got a bare "connection closed" error event while
//! `state()` still said "running", so it could not tell the machine was gone.
//!
//! Boots a real machine, so it is `#[ignore]`d by default. Run on a host the
//! engine supports, with a signed boot binary:
//!   cargo build --release --bin smolvm   (codesign it with smolvm.entitlements on macOS)
//!   SMOLVM_BOOT_BINARY=$PWD/target/release/smolvm \
//!     cargo test --release --test embedded_delete_during_exec -- --ignored --test-threads=1

use smolvm::agent::{ExecEvent, VmResources};
use smolvm::embedded::{runtime, ExecCancel, ExecOptions, MachineSpec, StopOptions};
use smolvm::Error;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

#[test]
#[ignore = "boots a real machine"]
fn a_delete_during_a_streamed_command_reports_the_delete() {
    let name = "embedded-delete-during-exec";
    let runtime = runtime().expect("embedded runtime");
    let _ = runtime.delete_machine(name);
    let spec = MachineSpec {
        name: name.to_string(),
        resources: VmResources {
            cpus: 1,
            memory_mib: 512,
            ..Default::default()
        },
        ..Default::default()
    };
    runtime
        .create_machine_with_workload(spec, Vec::new(), None, None)
        .expect("create machine");
    runtime.start_machine(name).expect("start machine");

    let (started, wait_started) = mpsc::channel();
    let streaming = {
        let runtime = runtime.clone();
        thread::spawn(move || {
            let mut errors = Vec::new();
            let mut announced = false;
            let result = runtime.exec_streaming_with_options(
                name,
                vec!["sh".into(), "-c".into(), "echo up; sleep 60".into()],
                ExecOptions::default(),
                &ExecCancel::default(),
                |event| match event {
                    ExecEvent::Stdout(_) if !announced => {
                        announced = true;
                        let _ = started.send(());
                    }
                    ExecEvent::Error(message) => errors.push(message),
                    _ => {}
                },
            );
            // What a caller does next: ask whether the machine is still there.
            let state = runtime.state(name);
            (result, errors, state)
        })
    };

    wait_started
        .recv_timeout(Duration::from_secs(60))
        .expect("the command started");
    runtime
        .delete_machine_with(name, &StopOptions::default())
        .expect("delete machine");

    let (result, errors, state) = streaming.join().expect("streaming thread");
    assert!(
        errors.is_empty(),
        "the cut-off is reported as the delete, not as an error event: {errors:?}"
    );
    match result {
        Err(Error::Interrupted { by, .. }) => assert_eq!(by, "deleted"),
        other => panic!("expected the delete to interrupt the command, got {other:?}"),
    }
    assert_ne!(
        state, "running",
        "a machine being deleted does not read as running"
    );
}
