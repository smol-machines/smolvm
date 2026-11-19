use super::*;
use std::path::PathBuf;

#[test]
#[ignore = "requires isolated runtime assets and hardware virtualization"]
fn failed_cached_stop_and_delete_preserve_the_guest_for_retry() {
    let root =
        PathBuf::from(std::env::var_os("SMOL_TRANSFER_TEST_ROOT").expect("isolated fixture root"));
    let engine =
        PathBuf::from(std::env::var_os("SMOL_TRANSFER_TEST_ENGINE").expect("reviewed engine"));
    assert_eq!(
        std::env::var_os("SMOLVM_DATA_DIR").unwrap(),
        root.join("data").as_os_str()
    );
    assert!(SmolvmDb::default_path()
        .unwrap()
        .starts_with(root.join("data")));
    crate::embedded::bundle::set_bundle(crate::embedded::bundle::Bundle {
        boot_binary: Some(engine),
        ..Default::default()
    })
    .unwrap();
    smolvm_pack::assets::add_template_root(root.clone());
    let runtime = EmbeddedRuntime::new().unwrap();
    assert!(runtime.db.list_vms().unwrap().is_empty());
    let host = root.join("staged-host");
    std::fs::create_dir(&host).unwrap();
    std::fs::write(host.join("value"), "host").unwrap();
    let name = "cached-stop";
    let mut spec = MachineSpec {
        name: name.into(),
        persistent: true,
        ..Default::default()
    };
    spec.resources.cpus = 1;
    spec.resources.memory_mib = 256;
    spec.resources.storage_gib = Some(1);
    spec.resources.overlay_gib = Some(1);
    spec.mounts = crate::HostMount::parse(&[format!("{}:/staged:staged", host.display())]).unwrap();
    runtime.create_machine(spec).unwrap();
    let exec = |script: &str| {
        let (code, out, err) = runtime
            .exec(
                name,
                vec!["sh".into(), "-c".into(), script.into()],
                vec![],
                None,
                Some(Duration::from_secs(20)),
            )
            .unwrap();
        assert_eq!(code, 0, "{}", String::from_utf8_lossy(&err));
        out
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        runtime.start_machine(name).unwrap();
        let before = runtime.db.get_vm(name).unwrap().unwrap();
        let handle = runtime.cached_handle(name).unwrap().unwrap();
        exec("printf guest > /staged/value; mkfifo /staged/unsupported");
        for deleting in [false, true] {
            let error = if deleting {
                runtime.delete_machine(name)
            } else {
                runtime.stop_machine(name)
            }
            .unwrap_err();
            assert!(error.to_string().contains("special file"), "{error}");
            assert!(Arc::ptr_eq(
                &handle,
                &runtime
                    .cached_handle(name)
                    .unwrap()
                    .expect("cached handle retained after failure")
            ));
            let after = runtime.db.get_vm(name).unwrap().unwrap();
            assert_eq!(
                (after.pid, after.pid_start_time),
                (before.pid, before.pid_start_time)
            );
            assert!(after.is_process_alive());
            assert!(!after.restart.user_stopped);
            assert_eq!(std::fs::read_to_string(host.join("value")).unwrap(), "host");
            assert_eq!(exec("cat /staged/value"), b"guest");
            runtime.db.admit_machine_mutation(name).unwrap();
        }
        exec("rm /staged/unsupported");
        runtime.stop_machine(name).unwrap();
        assert!(runtime.cached_handle(name).unwrap().is_none());
        let stopped = runtime.db.get_vm(name).unwrap().unwrap();
        assert_eq!(stopped.pid, None);
        assert!(stopped.restart.user_stopped);
        assert_eq!(
            std::fs::read_to_string(host.join("value")).unwrap(),
            "guest"
        );
        runtime.stop_machine(name).unwrap();
        runtime.start_machine(name).unwrap();
        exec("printf retry > /staged/value");
        runtime.delete_machine(name).unwrap();
        assert_eq!(
            std::fs::read_to_string(host.join("value")).unwrap(),
            "retry"
        );
    }));
    if runtime.db.get_vm(name).unwrap().is_some() {
        let _ = runtime.exec(
            name,
            vec!["rm".into(), "-f".into(), "/staged/unsupported".into()],
            vec![],
            None,
            Some(Duration::from_secs(5)),
        );
        runtime.delete_machine(name).unwrap();
    }
    assert!(runtime.db.list_vms().unwrap().is_empty());
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}
