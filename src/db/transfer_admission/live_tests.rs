use super::*;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

// The runner supplies an isolated state root, runtime assets, and a copied
// signed engine. This test never discovers or uses a user's current machines.
#[test]
#[ignore = "requires isolated runtime assets and hardware virtualization"]
fn live_transfer_admission_preserves_guests_and_releases_shared_data_explicitly() {
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
        boot_binary: Some(engine.clone()),
        ..Default::default()
    })
    .unwrap();
    smolvm_pack::assets::add_template_root(root.clone());
    let db = SmolvmDb::open().unwrap();
    assert!(
        db.list_vms().unwrap().is_empty(),
        "fixture must start empty"
    );
    let volume = root.join("shared é= ");
    std::fs::create_dir(&volume).unwrap();
    std::fs::write(volume.join("sentinel"), b"before").unwrap();
    let names = ["admission-web", "admission-outside", "admission-new"];
    let mut serial = 0;
    let mut command = |args: &[&str]| {
        let out = root.join(format!("command-{serial}.out"));
        let err = root.join(format!("command-{serial}.err"));
        serial += 1;
        let mut child = Command::new(&engine)
            .arg("machine")
            .args(args)
            .stdin(Stdio::null())
            .stdout(File::create(&out).unwrap())
            .stderr(File::create(&err).unwrap())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(90);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("machine command exceeded its deadline: {args:?}");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        (
            status.success(),
            std::fs::read_to_string(out).unwrap(),
            std::fs::read_to_string(err).unwrap(),
        )
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        for name in &names[..2] {
            let (ok, _, error) = command(&[
                "create",
                "--name",
                name,
                "--cpus",
                "1",
                "--mem",
                "128",
                "--storage",
                "1",
                "--overlay",
                "1",
            ]);
            assert!(ok, "{error}");
            let (ok, _, error) = command(&["start", "--name", name]);
            assert!(ok, "{error}");
        }
        let mapping = format!("{}:/data", volume.display());
        let (ok, _, error) = command(&["mount", "add", "--name", names[0], "-v", &mapping]);
        assert!(ok, "{error}");
        let before = db.get_vm(names[0]).unwrap().unwrap();
        let outside = db.get_vm(names[1]).unwrap().unwrap();
        assert!(before.is_process_alive() && outside.is_process_alive());
        db.claim_workload_transfer(
            "live-move",
            vec![Member::from_record(names[0], &before)],
            std::slice::from_ref(&volume),
        )
        .unwrap();

        // The claim itself is not quiescence: observing the real VMM still
        // reports running until the coordinator explicitly freezes it.
        assert_eq!(
            crate::agent::fork::control_socket_cmd(
                &crate::agent::fork::control_socket_path(names[0]),
                "STATUS",
            )
            .unwrap(),
            "OK running"
        );
        let (ok, _, error) = command(&["ls", "--json"]);
        assert!(ok, "{error}");
        assert_eq!(std::fs::read(volume.join("sentinel")).unwrap(), b"before");
        for operation in ["start", "pause", "resume", "stop", "delete"] {
            let mut args = vec![operation, "--name", names[0]];
            if operation == "delete" {
                args.push("--force");
            }
            let (ok, _, error) = command(&args);
            assert!(
                !ok && error.contains("environment is moving"),
                "{operation}: {error}"
            );
        }
        for suffix in ["", ":ro"] {
            let mapping = format!("{}:/data{suffix}", volume.display());
            let (ok, _, error) = command(&["mount", "add", "--name", names[1], "-v", &mapping]);
            assert!(
                !ok && error.contains("active environment transfer"),
                "{error}"
            );
        }
        let (ok, _, error) = command(&[
            "create",
            "--name",
            names[2],
            "--cpus",
            "1",
            "--mem",
            "128",
            "--storage",
            "1",
            "--overlay",
            "1",
            "-v",
            &mapping,
        ]);
        assert!(ok, "{error}");
        let (ok, _, error) = command(&["start", "--name", names[2]]);
        assert!(
            !ok && error.contains("active environment transfer"),
            "{error}"
        );
        assert!(db.get_vm(names[2]).unwrap().unwrap().pid.is_none());
        assert_eq!(
            Member::from_record(names[0], &before),
            Member::from_record(names[0], &db.get_vm(names[0]).unwrap().unwrap())
        );
        assert_eq!(
            Member::from_record(names[1], &outside),
            Member::from_record(names[1], &db.get_vm(names[1]).unwrap().unwrap())
        );
        assert!(crate::attach::shared_directories(names[1], false)
            .unwrap()
            .is_empty());
        assert!(crate::attach::shared_directories(names[1], true)
            .unwrap()
            .is_empty());

        // A server restart during a transfer must keep every environment
        // visible, including one whose shared data is owned by another member.
        let state = std::sync::Arc::new(crate::api::state::ApiState::with_db(db.clone()));
        let loaded = state.load_persisted_machines();
        for name in names {
            assert!(loaded.iter().any(|loaded| loaded == name));
        }
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            use axum::extract::{State, Path, Query};
            use crate::api::handlers::machines;
            let error = machines::start_machine(State(state.clone()), Path(names[0].into()), Query(Default::default()), Default::default(), axum::body::Bytes::new()).await.unwrap_err();
            assert!(matches!(error, crate::api::error::ApiError::Conflict(ref message) if message.contains("environment is moving")), "{error:?}");
            let error = machines::stop_machine(State(state.clone()), Path(names[0].into()), Query(Default::default())).await.unwrap_err();
            assert!(matches!(error, crate::api::error::ApiError::Conflict(ref message) if message.contains("environment is moving")), "{error:?}");
            let error = machines::delete_machine(State(state.clone()), Path(names[0].into()), Query(Default::default())).await.unwrap_err();
            assert!(matches!(error, crate::api::error::ApiError::Conflict(ref message) if message.contains("environment is moving")), "{error:?}");
            let entry = state.get_machine(names[2]).unwrap();
            let error = crate::api::state::ensure_running_and_persist(&state, names[2], &entry).await.unwrap_err();
            assert!(error.to_string().contains("active environment transfer"), "{error}");
        });
        assert!(db.get_vm(names[2]).unwrap().unwrap().pid.is_none());
        assert_eq!(
            Member::from_record(names[0], &before),
            Member::from_record(names[0], &db.get_vm(names[0]).unwrap().unwrap())
        );

        db.retire_workload_transfer("live-move").unwrap();
        let (ok, _, error) = command(&["mount", "add", "--name", names[1], "-v", &mapping]);
        assert!(ok, "{error}");
        let (ok, _, error) = command(&[
            "exec",
            "--name",
            names[1],
            "--",
            "/bin/sh",
            "-c",
            "printf after > /data/sentinel",
        ]);
        assert!(ok, "{error}");
        let (ok, output, error) =
            command(&["exec", "--name", names[0], "--", "cat", "/data/sentinel"]);
        assert!(ok && output.trim() == "after", "{output} {error}");
        runtime.block_on(async {
            let entry = state.get_machine(names[2]).unwrap();
            crate::api::state::ensure_running_and_persist(&state, names[2], &entry)
                .await
                .unwrap();
            assert!(db.get_vm(names[2]).unwrap().unwrap().is_process_alive());
            use crate::api::handlers::machines;
            use axum::extract::{Path, Query, State};
            let stopped = machines::stop_machine(
                State(state.clone()),
                Path(names[2].into()),
                Query(Default::default()),
            )
            .await
            .unwrap();
            assert_eq!(stopped.state, "stopped");
            let started = machines::start_machine(
                State(state.clone()),
                Path(names[2].into()),
                Query(Default::default()),
                Default::default(),
                axum::body::Bytes::new(),
            )
            .await
            .unwrap();
            assert_eq!(started.state, "running");
            assert!(db.get_vm(names[2]).unwrap().unwrap().is_process_alive());
        });
    }));
    let _ = db.retire_workload_transfer("live-move");
    for name in names {
        if db.get_vm(name).unwrap().is_some() {
            let (ok, _, error) = command(&["delete", "--name", name, "--force"]);
            assert!(ok, "cleanup {name}: {error}");
        }
    }
    assert!(db.list_vms().unwrap().is_empty());
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}
