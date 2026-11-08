//! The merge rules, and the parity matrix: every option on every creation
//! path, applied or refused by name, never dropped.

use super::*;
use crate::config::VmRecord;
use crate::embedded::MachineSpec;
use smolvm_pack::format::{CheckpointNetwork, CheckpointPort, CheckpointWorkload};

const IMAGE: &str = "example/image:1";
const PACKED_IMAGE: &str = "example/packed:1";

/// A pack whose defaults differ from every value the cases ask for.
fn pack_manifest() -> PackManifest {
    let mut manifest = PackManifest::new(
        PACKED_IMAGE.into(),
        "sha256:00".into(),
        "linux/amd64".into(),
        String::new(),
    );
    manifest.cpus = 2;
    manifest.mem = 2048;
    manifest.env = vec!["PACKED=1".into(), "SHARED=pack".into()];
    manifest.workdir = Some("/packed".into());
    manifest.entrypoint = vec!["/pack-entry".into()];
    manifest.cmd = vec!["pack-cmd".into()];
    manifest
}

/// A live checkpoint of an image machine with a network and one published
/// port, captured on virtio-net.
fn checkpoint_manifest() -> PackManifest {
    let mut manifest = pack_manifest();
    let mut checkpoint = crate::portable_checkpoint::test_checkpoint_manifest();
    checkpoint.network = Some(CheckpointNetwork {
        enabled: true,
        backend: Some("virtio-net".into()),
        ports: vec![CheckpointPort {
            host: 8080,
            guest: 80,
        }],
        ..Default::default()
    });
    checkpoint.workload = Some(CheckpointWorkload {
        image: PACKED_IMAGE.into(),
        user: None,
        overlay_owner: "captured".into(),
        restart_policy: "never".into(),
        restart_max_retries: 0,
        restart_max_backoff_secs: 0,
    });
    manifest.checkpoint = Some(checkpoint);
    manifest
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Src {
    Image,
    Pack,
    Checkpoint,
}

const SOURCES: [Src; 3] = [Src::Image, Src::Pack, Src::Checkpoint];

fn resolve_from(src: Src, spec: CreateSpec, caller: Caller) -> Result<VmRecord> {
    let pack = pack_manifest();
    let checkpoint = checkpoint_manifest();
    let source = match src {
        Src::Image => SpecSource::Image(IMAGE),
        Src::Pack => SpecSource::from_manifest(&pack),
        Src::Checkpoint => SpecSource::from_manifest(&checkpoint),
    };
    resolve(source, spec, caller)?.to_record("m")
}

fn fresh(spec: CreateSpec, src: Src) -> VmRecord {
    resolve_from(src, spec, Caller::Cli).unwrap()
}

fn refusal(spec: CreateSpec, src: Src) -> String {
    resolve_from(src, spec, Caller::Cli)
        .expect_err("should be refused")
        .to_string()
}

// ---------------------------------------------------------------------------
// Merge rules
// ---------------------------------------------------------------------------

#[test]
fn a_pack_supplies_defaults_and_explicit_options_override_them() {
    let defaults = fresh(CreateSpec::default(), Src::Pack);
    assert_eq!((defaults.cpus, defaults.mem), (2, 2048));
    assert_eq!(defaults.image.as_deref(), Some(PACKED_IMAGE));
    assert_eq!(defaults.entrypoint, ["/pack-entry"]);
    assert_eq!(defaults.cmd, ["pack-cmd"]);
    assert_eq!(defaults.workdir.as_deref(), Some("/packed"));

    let explicit = fresh(
        CreateSpec {
            cpus: Some(4),
            mem: Some(1024),
            cmd: Some(vec!["mine".into()]),
            workdir: Some("/mine".into()),
            env: vec![("SHARED".into(), "mine".into())],
            ..Default::default()
        },
        Src::Pack,
    );
    assert_eq!((explicit.cpus, explicit.mem), (4, 1024));
    // An explicit command replaces the packed entrypoint and command together.
    assert!(explicit.entrypoint.is_empty());
    assert_eq!(explicit.cmd, ["mine"]);
    assert_eq!(explicit.workdir.as_deref(), Some("/mine"));
    // Environment merges by name, the explicit value winning.
    assert_eq!(
        explicit.env,
        [
            ("PACKED".to_string(), "1".to_string()),
            ("SHARED".to_string(), "mine".to_string())
        ]
    );
}

#[test]
fn a_pack_turns_on_the_devices_and_network_it_was_made_with() {
    let mut manifest = pack_manifest();
    manifest.network = true;
    manifest.gpu = true;
    manifest.cuda = true;
    manifest.user = Some("1000:1000".into());
    let record = resolve(
        SpecSource::Pack(&manifest),
        CreateSpec::default(),
        Caller::Api,
    )
    .unwrap()
    .to_record("m")
    .unwrap();
    assert!(record.network);
    assert_eq!(record.gpu, Some(true));
    assert!(record.cuda);
    assert_eq!(record.user.as_deref(), Some("1000:1000"));
}

#[test]
fn a_vm_mode_pack_is_not_an_image_machine() {
    let mut manifest = pack_manifest();
    manifest.mode = PackMode::Vm;
    let record = resolve(
        SpecSource::Pack(&manifest),
        CreateSpec::default(),
        Caller::Cli,
    )
    .unwrap()
    .to_record("m")
    .unwrap();
    assert_eq!(record.image, None);
}

#[test]
fn a_packed_secret_reference_must_be_bound_by_the_caller() {
    let mut manifest = pack_manifest();
    manifest
        .secret_refs
        .insert("TOKEN".into(), crate::secrets::env_ref("TOKEN"));
    let unbound = resolve(
        SpecSource::Pack(&manifest),
        CreateSpec::default(),
        Caller::Cli,
    )
    .unwrap_err()
    .to_string();
    assert!(unbound.contains("secret 'TOKEN'"), "{unbound}");

    let mut spec = CreateSpec::default();
    spec.secret_refs
        .insert("TOKEN".into(), crate::secrets::env_ref("HOST_TOKEN"));
    let bound = resolve(SpecSource::Pack(&manifest), spec, Caller::Cli)
        .unwrap()
        .to_record("m")
        .unwrap();
    assert_eq!(
        bound.secret_refs["TOKEN"].from_env.as_deref(),
        Some("HOST_TOKEN")
    );
}

#[test]
fn an_api_caller_may_not_name_host_secrets() {
    let mut spec = CreateSpec::default();
    spec.secret_refs
        .insert("TOKEN".into(), crate::secrets::env_ref("HOST_TOKEN"));
    assert!(resolve(SpecSource::Image(IMAGE), spec, Caller::Api).is_err());
}

#[test]
fn options_that_need_a_network_turn_it_on() {
    for spec in [
        CreateSpec {
            block_private: Some(Vec::new()),
            ..Default::default()
        },
        CreateSpec {
            allowed_cidrs: Some(vec!["10.0.0.0/8".into()]),
            ..Default::default()
        },
        CreateSpec {
            guest_subnet: Some("10.200.0.0/30".into()),
            ..Default::default()
        },
    ] {
        assert!(fresh(spec, Src::Image).network);
    }
    assert!(!fresh(CreateSpec::default(), Src::Image).network);
}

#[test]
fn keeping_an_identity_needs_a_checkpoint() {
    let spec = CreateSpec {
        keep_identity: true,
        ..Default::default()
    };
    assert!(refusal(spec.clone(), Src::Image).contains("checkpoint"));
    assert!(refusal(spec.clone(), Src::Pack).contains("checkpoint"));
    assert!(fresh(spec, Src::Checkpoint).keep_identity);
}

#[test]
fn a_checkpoint_restores_what_it_captured() {
    let record = fresh(CreateSpec::default(), Src::Checkpoint);
    assert_eq!((record.cpus, record.mem), (1, 512));
    assert!(record.network);
    assert_eq!(record.network_backend, Some(NetworkBackend::VirtioNet));
    assert_eq!(record.ports, [(8080, 80)]);
    assert_eq!(record.image.as_deref(), Some(PACKED_IMAGE));
    assert_eq!(record.fork_overlay_owner.as_deref(), Some("captured"));
    assert!(
        record.init_completed,
        "the captured guest already ran its init"
    );
    assert!(record.forkable);
    assert_eq!(record.host_uid_owner.as_deref(), Some("m"));
}

#[test]
fn a_checkpoint_keeps_block_private_udp_ports_and_its_settings() {
    let mut manifest = checkpoint_manifest();
    let checkpoint = manifest.checkpoint.as_mut().unwrap();
    let network = checkpoint.network.as_mut().unwrap();
    network.block_private = Some(vec!["100.64.0.0/10".into()]);
    network.udp_ports = vec![CheckpointPort {
        host: 5353,
        guest: 53,
    }];
    checkpoint.nested_virt = true;
    checkpoint.settings.stop_signal = Some("SIGINT".into());
    checkpoint.settings.health_cmd = Some(vec!["true".into()]);
    let record = resolve(
        SpecSource::from_manifest(&manifest),
        CreateSpec::default(),
        Caller::Embedded,
    )
    .unwrap()
    .to_record("m")
    .unwrap();
    assert_eq!(record.block_private, Some(vec!["100.64.0.0/10".into()]));
    assert_eq!(record.udp_ports, [(5353, 53)]);
    assert_eq!(record.nested_virt, Some(true));
    assert_eq!(record.stop_signal.as_deref(), Some("SIGINT"));
    assert_eq!(record.health_cmd, Some(vec!["true".to_string()]));
}

#[test]
fn a_checkpoint_refuses_a_network_it_was_captured_without() {
    let mut manifest = checkpoint_manifest();
    let checkpoint = manifest.checkpoint.as_mut().unwrap();
    checkpoint.network = Some(CheckpointNetwork::default());
    for spec in [
        CreateSpec {
            net: true,
            ..Default::default()
        },
        CreateSpec {
            allowed_cidrs: Some(Vec::new()),
            ..Default::default()
        },
        CreateSpec {
            block_private: Some(Vec::new()),
            ..Default::default()
        },
    ] {
        let error = resolve(SpecSource::from_manifest(&manifest), spec, Caller::Cli)
            .unwrap_err()
            .to_string();
        assert!(error.contains("networking"), "{error}");
    }
}

#[test]
fn a_tsi_checkpoint_refuses_an_egress_policy() {
    let mut manifest = checkpoint_manifest();
    let checkpoint = manifest.checkpoint.as_mut().unwrap();
    checkpoint.network = Some(CheckpointNetwork {
        enabled: true,
        backend: Some("tsi".into()),
        ..Default::default()
    });
    let error = resolve(
        SpecSource::from_manifest(&manifest),
        CreateSpec {
            allowed_cidrs: Some(vec!["10.0.0.0/8".into()]),
            ..Default::default()
        },
        Caller::Cli,
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("egress policy"), "{error}");
}

#[test]
fn a_checkpoint_moves_host_ports_but_keeps_its_guest_ports() {
    let moved = fresh(
        CreateSpec {
            ports: vec![PortMapping::new(9090, 80)],
            ..Default::default()
        },
        Src::Checkpoint,
    );
    assert_eq!(moved.ports, [(9090, 80)]);
    for ports in [
        vec![PortMapping::new(9090, 81)],
        vec![PortMapping::new(9090, 80), PortMapping::new(9091, 81)],
    ] {
        let error = refusal(
            CreateSpec {
                ports,
                ..Default::default()
            },
            Src::Checkpoint,
        );
        assert!(error.contains("ports"), "{error}");
    }
}

#[test]
fn a_checkpoint_with_bindings_keeps_its_placeholders_and_takes_supplied_values() {
    let mut manifest = checkpoint_manifest();
    let network = manifest
        .checkpoint
        .as_mut()
        .unwrap()
        .network
        .as_mut()
        .unwrap();
    network.dns_filter_hosts = Some(vec!["api.example.com".into()]);
    network.credential_policy = Some(
        serde_json::from_str(r#"{"credentials":[{"name":"api","environment_variable":"API","allowed_hosts":["api.example.com"]}]}"#)
            .unwrap(),
    );
    network
        .credential_placeholders
        .insert("api".into(), "placeholder".into());
    let record = resolve(
        SpecSource::from_manifest(&manifest),
        CreateSpec::default(),
        Caller::Cli,
    )
    .unwrap()
    .to_record("m")
    .unwrap();
    assert_eq!(record.credential_placeholders["api"], "placeholder");
    assert!(record.credentials_supplied_by_api);
}

#[test]
fn a_checkpoint_with_a_mediator_needs_it_rebound() {
    let mut manifest = checkpoint_manifest();
    manifest
        .checkpoint
        .as_mut()
        .unwrap()
        .network
        .as_mut()
        .unwrap()
        .mediated_egress_required = true;
    let record = resolve(
        SpecSource::from_manifest(&manifest),
        CreateSpec::default(),
        Caller::Cli,
    )
    .unwrap()
    .to_record("m")
    .unwrap();
    assert!(record.mediated_egress_required);
    assert!(record.external_interceptor_required);
}

#[test]
fn cli_credential_values_come_from_the_host_and_others_are_supplied() {
    let policy: CredentialPolicy = serde_json::from_str(
        r#"{"credentials":[{"name":"api","environment_variable":"API","allowed_hosts":["api.example.com"]}]}"#,
    )
    .unwrap();
    let spec = CreateSpec {
        credentials: Some(policy),
        ..Default::default()
    };
    let cli = resolve(SpecSource::Image(IMAGE), spec.clone(), Caller::Cli)
        .unwrap()
        .to_record("m")
        .unwrap();
    assert!(!cli.credentials_supplied_by_api);
    assert!(cli.network, "a binding implies networking");
    assert!(cli.credential_placeholders.contains_key("api"));
    let api = resolve(SpecSource::Image(IMAGE), spec.clone(), Caller::Api)
        .unwrap()
        .to_record("m")
        .unwrap();
    assert!(api.credentials_supplied_by_api);
    let embedded = resolve(
        SpecSource::Image(IMAGE),
        CreateSpec {
            credentials_supplied_only: true,
            ..spec
        },
        Caller::Embedded,
    )
    .unwrap()
    .to_record("m")
    .unwrap();
    assert!(embedded.credentials_supplied_by_api);
}

#[test]
fn overlay_lays_flags_over_a_base_spec() {
    let base = CreateSpec {
        cpus: Some(2),
        env: vec![("A".into(), "base".into()), ("B".into(), "base".into())],
        labels: [("owner".to_string(), "sdk".to_string())].into(),
        cmd: Some(vec!["base".into()]),
        ..Default::default()
    };
    let top = CreateSpec {
        cpus: Some(3),
        env: vec![("B".into(), "top".into())],
        labels: [("run".to_string(), "1".to_string())].into(),
        gpu: true,
        ..Default::default()
    };
    let merged = base.overlay(top);
    assert_eq!(merged.cpus, Some(3));
    assert_eq!(
        merged.env,
        [
            ("A".to_string(), "base".to_string()),
            ("B".to_string(), "top".to_string())
        ]
    );
    assert_eq!(merged.labels.len(), 2);
    assert!(merged.gpu);
    assert_eq!(merged.cmd, Some(vec!["base".to_string()]));
    // The spec an embedder sends survives the trip over stdin.
    let json = serde_json::to_string(&merged).unwrap();
    assert_eq!(serde_json::from_str::<CreateSpec>(&json).unwrap(), merged);
}

// ---------------------------------------------------------------------------
// The parity matrix
// ---------------------------------------------------------------------------

/// What a path does with an option.
#[derive(Clone, Copy, Debug)]
enum Outcome {
    /// The record carries it.
    Applied,
    /// Refused with an error naming it (a lowercase fragment of the message).
    Refused(&'static str),
}
use Outcome::{Applied, Refused};

/// How `machine create` sets an option.
enum Cli {
    /// Flags; `{tmp}` is a scratch directory with a file `{tmp}/file`.
    Flags(&'static [&'static str]),
    /// A Smolfile's contents, for options only a Smolfile sets.
    Smolfile(&'static str),
    /// `machine create` has no way to set it.
    No,
}

/// How the serve API's create request sets an option.
enum Api {
    /// A request body (`{tmp}` substituted), and the cache disk the server
    /// would have resolved from it.
    Json(fn(&str) -> (serde_json::Value, Option<CacheDisk>)),
    No,
}

/// What an SDK hands the embedded runtime: a machine spec plus the workload
/// settings and credential bindings it passes beside it.
struct EmbeddedIn {
    spec: MachineSpec,
    env: Vec<(String, String)>,
    workdir: Option<String>,
    user: Option<String>,
    credentials: Option<CredentialPolicy>,
}

enum Embedded {
    Set(fn(&mut EmbeddedIn, &str)),
    No,
}

struct Case {
    field: &'static str,
    cli: Cli,
    api: Api,
    /// The API's own answer when it differs from the source's.
    api_outcome: Option<Outcome>,
    embedded: Embedded,
    /// The option set directly on the spec, as an SDK sends it for a pack.
    spec: fn(&mut CreateSpec, &str),
    /// Whether a record carries the option.
    applied: fn(&VmRecord) -> bool,
    /// What an image or a pack does with it.
    fresh: Outcome,
    /// What a live checkpoint does with it.
    checkpoint: Outcome,
}

impl Case {
    fn new(
        field: &'static str,
        spec: fn(&mut CreateSpec, &str),
        applied: fn(&VmRecord) -> bool,
    ) -> Self {
        Self {
            field,
            cli: Cli::No,
            api: Api::No,
            api_outcome: None,
            embedded: Embedded::No,
            spec,
            applied,
            fresh: Applied,
            checkpoint: Applied,
        }
    }
    fn cli(mut self, flags: &'static [&'static str]) -> Self {
        self.cli = Cli::Flags(flags);
        self
    }
    fn smolfile(mut self, contents: &'static str) -> Self {
        self.cli = Cli::Smolfile(contents);
        self
    }
    fn api(mut self, body: fn(&str) -> (serde_json::Value, Option<CacheDisk>)) -> Self {
        self.api = Api::Json(body);
        self
    }
    fn api_outcome(mut self, outcome: Outcome) -> Self {
        self.api_outcome = Some(outcome);
        self
    }
    fn embedded(mut self, set: fn(&mut EmbeddedIn, &str)) -> Self {
        self.embedded = Embedded::Set(set);
        self
    }
    fn fresh(mut self, outcome: Outcome) -> Self {
        self.fresh = outcome;
        self
    }
    fn checkpoint(mut self, outcome: Outcome) -> Self {
        self.checkpoint = outcome;
        self
    }
}

fn json(value: serde_json::Value) -> (serde_json::Value, Option<CacheDisk>) {
    (value, None)
}

fn policy(environment_variable: &str) -> CredentialPolicy {
    serde_json::from_str(&format!(
        r#"{{"credentials":[{{"name":"gh","environment_variable":"{environment_variable}","allowed_hosts":["api.github.com"]}}]}}"#
    ))
    .unwrap()
}

fn test_cache_disk(tmp: &str) -> CacheDisk {
    CacheDisk::parse(&format!("{tmp}/file:/cache")).unwrap()
}

/// One case per option. `CreateSpec` is destructured without `..` and every
/// binding must be used, so a new option fails to compile here until it has
/// a case saying how every path applies or refuses it.
#[deny(unused_variables)]
fn cases() -> Vec<Case> {
    let CreateSpec {
        entrypoint,
        cmd,
        env,
        workdir,
        user,
        init,
        secret_refs,
        restart_policy,
        restart_max_retries,
        restart_max_backoff_secs,
        health_cmd,
        health_interval_secs,
        health_timeout_secs,
        health_retries,
        health_startup_grace_secs,
        stop_on_exit,
        stop_signal,
        stop_timeout_secs,
        shm_size,
        cpus,
        mem,
        storage_gb,
        overlay_gb,
        block_io,
        disk_durability,
        disks,
        cache_disk,
        mounts,
        remote_volumes,
        disk_volumes,
        net,
        network_backend,
        dns,
        dns_options,
        network_name,
        guest_subnet,
        ports,
        allowed_cidrs,
        allowed_hosts,
        block_private,
        egress_rules,
        credentials,
        credentials_supplied_only,
        published_sockets,
        gpu,
        gpu_vram_mib,
        rosetta,
        nested_virt,
        cuda,
        docker_socket,
        ssh_agent,
        forkable,
        cuda_fork_pool_size,
        cuda_vram_limit_mib,
        keep_identity,
        ephemeral,
        detached,
        runtime_managed,
        labels,
    } = CreateSpec::default();
    macro_rules! case {
        ($field:ident, $spec:expr, $applied:expr) => {{
            let _ = &$field;
            Case::new(stringify!($field), $spec, $applied)
        }};
    }
    let async_io = if cfg!(target_os = "linux") {
        Applied
    } else {
        Refused("async block i/o")
    };
    vec![
        // Workload.
        case!(entrypoint, |s, _| s.entrypoint = Some(vec!["/ep".into()]), |r| r.entrypoint == ["/ep"])
            .smolfile("entrypoint = [\"/ep\"]\n")
            .api(|_| json(serde_json::json!({"entrypoint": ["/ep"]})))
            .checkpoint(Refused("workload command")),
        case!(cmd, |s, _| s.cmd = Some(vec!["run".into()]), |r| r.cmd == ["run"])
            .cli(&["--", "run"])
            .api(|_| json(serde_json::json!({"cmd": ["run"]})))
            .embedded(|e, _| e.spec.command = vec!["run".into()])
            .checkpoint(Refused("workload command")),
        case!(env, |s, _| s.env = vec![("K".into(), "v".into())], |r| r
            .env
            .contains(&("K".into(), "v".into())))
        .cli(&["-e", "K=v"])
        .api(|_| json(serde_json::json!({"env": [{"name": "K", "value": "v"}]})))
        .embedded(|e, _| e.env = vec![("K".into(), "v".into())]),
        case!(workdir, |s, _| s.workdir = Some("/srv".into()), |r| r.workdir.as_deref()
            == Some("/srv"))
        .cli(&["-w", "/srv"])
        .api(|_| json(serde_json::json!({"workdir": "/srv"})))
        .embedded(|e, _| e.workdir = Some("/srv".into())),
        case!(user, |s, _| s.user = Some("1000".into()), |r| r.user.as_deref() == Some("1000"))
            .cli(&["-u", "1000"])
            .embedded(|e, _| e.user = Some("1000".into()))
            .checkpoint(Refused("workload user")),
        case!(init, |s, _| s.init = vec!["echo hi".into()], |r| r.init == ["echo hi"])
            .cli(&["--init", "echo hi"])
            .checkpoint(Refused("init")),
        case!(
            secret_refs,
            |s, _| {
                s.secret_refs
                    .insert("TOKEN".into(), crate::secrets::env_ref("HOST_TOKEN"));
            },
            |r| r.secret_refs.contains_key("TOKEN")
        )
        .cli(&["--secret-env", "TOKEN=HOST_TOKEN"])
        .api(|_| json(serde_json::json!({"secrets": {"TOKEN": {"from_env": "HOST_TOKEN"}}})))
        .api_outcome(Refused("secret")),
        case!(
            restart_policy,
            |s, _| s.restart_policy = Some(RestartPolicy::Always),
            |r| r.restart.policy == RestartPolicy::Always
        )
        .smolfile("[restart]\npolicy = \"always\"\n")
        .api(|_| json(serde_json::json!({"restart": {"policy": "always"}}))),
        case!(
            restart_max_retries,
            |s, _| s.restart_max_retries = Some(7),
            |r| r.restart.max_retries == 7
        )
        .smolfile("[restart]\nmax_retries = 7\n")
        .api(|_| json(serde_json::json!({"restart": {"maxRetries": 7}}))),
        case!(
            restart_max_backoff_secs,
            |s, _| s.restart_max_backoff_secs = Some(90),
            |r| r.restart.max_backoff_secs == 90
        )
        .smolfile("[restart]\nmax_backoff = \"90s\"\n"),
        case!(health_cmd, |s, _| s.health_cmd = Some(vec!["true".into()]), |r| r
            .health_cmd
            .is_some())
        .smolfile("[health]\nexec = [\"true\"]\n"),
        case!(
            health_interval_secs,
            |s, _| s.health_interval_secs = Some(11),
            |r| r.health_interval_secs == Some(11)
        )
        .smolfile("[health]\nexec = [\"true\"]\ninterval = \"11s\"\n"),
        case!(
            health_timeout_secs,
            |s, _| s.health_timeout_secs = Some(3),
            |r| r.health_timeout_secs == Some(3)
        )
        .smolfile("[health]\nexec = [\"true\"]\ntimeout = \"3s\"\n"),
        case!(
            health_retries,
            |s, _| s.health_retries = Some(4),
            |r| r.health_retries == Some(4)
        )
        .smolfile("[health]\nexec = [\"true\"]\nretries = 4\n"),
        case!(
            health_startup_grace_secs,
            |s, _| s.health_startup_grace_secs = Some(20),
            |r| r.health_startup_grace_secs == Some(20)
        )
        .smolfile("[health]\nexec = [\"true\"]\nstartup_grace = \"20s\"\n"),
        case!(stop_on_exit, |s, _| s.stop_on_exit = true, |r| r.stop_on_exit).cli(&["--stop-on-exit"]),
        case!(
            stop_signal,
            |s, _| s.stop_signal = Some("SIGINT".into()),
            |r| r.stop_signal.as_deref() == Some("SIGINT")
        )
        .cli(&["--stop-signal", "SIGINT"])
        .api(|_| json(serde_json::json!({"stopSignal": "SIGINT"}))),
        case!(
            stop_timeout_secs,
            |s, _| s.stop_timeout_secs = Some(45),
            |r| r.stop_timeout_secs == Some(45)
        )
        .cli(&["--stop-timeout", "45"])
        .api(|_| json(serde_json::json!({"stopTimeoutSecs": 45}))),
        case!(shm_size, |s, _| s.shm_size = Some("1g".into()), |r| r.shm_size.as_deref()
            == Some("1g"))
        .cli(&["--shm-size", "1g"])
        .embedded(|e, _| e.spec.resources.shm_size = Some("1g".into()))
        .checkpoint(Refused("/dev/shm")),
        // Resources.
        case!(cpus, |s, _| s.cpus = Some(3), |r| r.cpus == 3)
            .cli(&["--cpus", "3"])
            .api(|_| json(serde_json::json!({"cpus": 3})))
            .embedded(|e, _| e.spec.resources.cpus = 3)
            .checkpoint(Refused("cpus")),
        case!(mem, |s, _| s.mem = Some(3072), |r| r.mem == 3072)
            .cli(&["--mem", "3072"])
            .api(|_| json(serde_json::json!({"memoryMb": 3072})))
            .embedded(|e, _| e.spec.resources.memory_mib = 3072)
            .checkpoint(Refused("memory")),
        case!(storage_gb, |s, _| s.storage_gb = Some(33), |r| r.storage_gb == Some(33))
            .cli(&["--storage", "33"])
            .api(|_| json(serde_json::json!({"storageGb": 33})))
            .embedded(|e, _| e.spec.resources.storage_gib = Some(33))
            .checkpoint(Refused("storage disk size")),
        case!(overlay_gb, |s, _| s.overlay_gb = Some(12), |r| r.overlay_gb == Some(12))
            .cli(&["--overlay", "12"])
            .api(|_| json(serde_json::json!({"overlayGb": 12})))
            .embedded(|e, _| e.spec.resources.overlay_gib = Some(12))
            .checkpoint(Refused("overlay disk size")),
        case!(
            block_io,
            |s, _| s.block_io = Some(BlockIoEngine::Async),
            |r| r.block_io == BlockIoEngine::Async
        )
        .cli(&["--block-io", "async"])
        .api(|_| json(serde_json::json!({"blockIo": "async"})))
        .embedded(|e, _| e.spec.resources.block_io = BlockIoEngine::Async)
        .fresh(async_io)
        .checkpoint(async_io),
        case!(
            disk_durability,
            |s, _| s.disk_durability = Some(DiskDurability::Deferred),
            |r| r.disk_durability == DiskDurability::Deferred
        )
        .cli(&["--disk-durability", "deferred"])
        .api(|_| json(serde_json::json!({"diskDurability": "deferred"})))
        .embedded(|e, _| e.spec.resources.disk_durability = DiskDurability::Deferred),
        case!(
            disks,
            |s, tmp| s.disks = vec![AttachedDisk::parse(&format!("{tmp}/file:ro")).unwrap()],
            |r| r.disks.len() == 1
        )
        .cli(&["--disk", "{tmp}/file:ro"])
        .embedded(|e, tmp| {
            e.spec.resources.disks = vec![AttachedDisk::parse(&format!("{tmp}/file:ro")).unwrap()]
        })
        .checkpoint(Refused("attached disks")),
        case!(cache_disk, |s, tmp| s.cache_disk = Some(test_cache_disk(tmp)), |r| r
            .cache_disk
            .is_some())
        .cli(&["--cache-disk", "{tmp}/file:/cache"])
        .api(|tmp| (serde_json::json!({}), Some(test_cache_disk(tmp))))
        .embedded(|e, tmp| e.spec.resources.cache_disk = Some(test_cache_disk(tmp))),
        // Filesystems.
        case!(
            mounts,
            |s, tmp| {
                s.mounts = vec![HostMount {
                    source: tmp.into(),
                    target: "/data".into(),
                    read_only: true,
                    staged: false,
                }]
            },
            |r| r.mounts.len() == 1
        )
        .cli(&["-v", "{tmp}:/data:ro"])
        .api(|tmp| json(serde_json::json!({"mounts": [{"source": tmp, "target": "/data", "readonly": true}]})))
        .embedded(|e, tmp| {
            e.spec.mounts = vec![HostMount {
                source: tmp.into(),
                target: "/data".into(),
                read_only: true,
                staged: false,
            }]
        })
        .checkpoint(Refused("volume mounts")),
        case!(
            remote_volumes,
            |s, _| {
                s.net = true;
                s.remote_volumes = vec![crate::remote_volume::from_parts("s3://bucket/p", "/s3", true).unwrap()];
            },
            |r| r.remote_volumes.len() == 1
        )
        .cli(&["--net", "-v", "s3://bucket/p:/s3:ro"])
        .api(|_| json(serde_json::json!({"network": true, "mounts": [{"source": "s3://bucket/p", "target": "/s3", "readonly": true}]})))
        .embedded(|e, _| {
            e.spec.resources.network = true;
            e.spec.remote_volumes = vec![crate::remote_volume::from_parts("s3://bucket/p", "/s3", true).unwrap()];
        })
        .checkpoint(Refused("remote volumes")),
        case!(
            disk_volumes,
            |s, _| s.disk_volumes = vec!["/var/lib/docker".into()],
            |r| r.disk_volumes == ["/var/lib/docker"]
        )
        .cli(&["-v", "/var/lib/docker"])
        .api(|_| json(serde_json::json!({"diskVolumes": ["/var/lib/docker"]})))
        .embedded(|e, _| e.spec.resources.disk_volumes = vec!["/var/lib/docker".into()])
        .checkpoint(Refused("disk volumes")),
        // Network.
        case!(net, |s, _| s.net = true, |r| r.network)
            .cli(&["--net"])
            .api(|_| json(serde_json::json!({"network": true})))
            .embedded(|e, _| e.spec.resources.network = true),
        case!(
            network_backend,
            |s, _| {
                s.net = true;
                s.network_backend = Some(NetworkBackend::Tsi);
            },
            |r| r.network_backend == Some(NetworkBackend::Tsi)
        )
        .cli(&["--net", "--net-backend", "tsi"])
        .api(|_| json(serde_json::json!({"network": true, "networkBackend": "tsi"})))
        .embedded(|e, _| {
            e.spec.resources.network = true;
            e.spec.resources.network_backend = Some(NetworkBackend::Tsi);
        })
        .checkpoint(Refused("network backend")),
        case!(dns, |s, _| s.dns = Some([1, 1, 1, 1].into()), |r| r.dns == Some([1, 1, 1, 1].into()))
            .cli(&["--dns", "1.1.1.1"])
            .embedded(|e, _| e.spec.resources.dns = Some([1, 1, 1, 1].into()))
            .checkpoint(Refused("dns resolver")),
        case!(
            dns_options,
            |s, _| s.dns_options = vec!["ndots:2".into()],
            |r| r.dns_options == ["ndots:2"]
        )
        .cli(&["--dns-option", "ndots:2"])
        .embedded(|e, _| e.spec.resources.dns_options = vec!["ndots:2".into()])
        .checkpoint(Refused("dns options")),
        case!(
            network_name,
            |s, _| s.network_name = Some("fabric".into()),
            |r| r.network_name.as_deref() == Some("fabric")
        )
        .cli(&["--network", "fabric"])
        .embedded(|e, _| e.spec.resources.network_name = Some("fabric".into()))
        .checkpoint(Refused("named network")),
        case!(
            guest_subnet,
            |s, _| s.guest_subnet = Some("10.200.0.0/30".into()),
            |r| r.guest_subnet.as_deref() == Some("10.200.0.0/30")
        )
        .cli(&["--guest-subnet", "10.200.0.0/30"])
        .api(|_| json(serde_json::json!({"guestSubnet": "10.200.0.0/30"})))
        .embedded(|e, _| e.spec.resources.guest_subnet = Some("10.200.0.0/30".into()))
        .checkpoint(Refused("guest subnet")),
        case!(ports, |s, _| s.ports = vec![PortMapping::new(8081, 81)], |r| r.ports
            == [(8081, 81)])
        .cli(&["-p", "8081:81"])
        .api(|_| json(serde_json::json!({"ports": [{"host": 8081, "guest": 81}]})))
        .embedded(|e, _| e.spec.ports = vec![PortMapping::new(8081, 81)])
        .checkpoint(Refused("ports")),
        case!(
            allowed_cidrs,
            |s, _| s.allowed_cidrs = Some(vec!["10.0.0.0/8".into()]),
            |r| r.allowed_cidrs == Some(vec!["10.0.0.0/8".into()])
        )
        .cli(&["--allow-cidr", "10.0.0.0/8"])
        .api(|_| json(serde_json::json!({"network": true, "allowedCidrs": ["10.0.0.0/8"]})))
        .embedded(|e, _| e.spec.resources.allowed_cidrs = Some(vec!["10.0.0.0/8".into()])),
        case!(
            allowed_hosts,
            |s, _| s.allowed_hosts = Some(vec!["example.com".into()]),
            |r| r.dns_filter_hosts.is_some()
        )
        .cli(&["--allow-host-pattern", "example.com"])
        .api(|_| json(serde_json::json!({"network": true, "allowedHosts": ["example.com"]})))
        .embedded(|e, _| e.spec.allowed_hosts = vec!["example.com".into()]),
        case!(
            block_private,
            |s, _| s.block_private = Some(vec!["10.1.0.0/16".into()]),
            |r| r.block_private == Some(vec!["10.1.0.0/16".into()])
        )
        .cli(&["--block-private", "--allow-private", "10.1.0.0/16"])
        .embedded(|e, _| e.spec.resources.block_private = Some(vec!["10.1.0.0/16".into()])),
        case!(
            egress_rules,
            |s, _| s.egress_rules = crate::cli::vm_common::deny_cidr_rules(&["192.0.2.0/24".into()]),
            |r| r.egress_rules.len() == 1
        )
        .cli(&["--deny-cidr", "192.0.2.0/24"])
        .api(|_| json(serde_json::json!({"network": true, "egressRules": [{"cidr": "192.0.2.0/24", "action": "deny"}]})))
        .embedded(|e, _| {
            e.spec.resources.egress_rules =
                crate::cli::vm_common::deny_cidr_rules(&["192.0.2.0/24".into()])
        }),
        case!(credentials, |s, _| s.credentials = Some(policy("GH_TOKEN")), |r| r
            .credential_policy
            .is_some())
        .cli(&["--credential", "gh=GH_TOKEN@api.github.com"])
        .api(|_| json(serde_json::json!({"credentials": {"credentials": [{"name": "gh", "environment_variable": "GH_TOKEN", "allowed_hosts": ["api.github.com"]}]}})))
        .embedded(|e, _| e.spec.credentials = Some(policy("GH_TOKEN")))
        .checkpoint(Refused("credential bindings")),
        case!(
            credentials_supplied_only,
            |s, _| {
                s.credentials = Some(policy("GH_TOKEN"));
                s.credentials_supplied_only = true;
            },
            |r| r.credentials_supplied_by_api
        )
        .api(|_| json(serde_json::json!({"credentials": {"credentials": [{"name": "gh", "environment_variable": "GH_TOKEN", "allowed_hosts": ["api.github.com"]}]}})))
        .embedded(|e, _| {
            e.spec.resources.network = true;
            e.credentials = Some(policy("GH_TOKEN"));
        })
        .checkpoint(Refused("credential bindings")),
        case!(
            published_sockets,
            |s, _| {
                s.published_sockets = vec![PublishedSocketConfig {
                    guest_path: "/run/app.sock".into(),
                    host_path: None,
                    direction: crate::config::SocketDirection::Expose,
                }]
            },
            |r| r.published_sockets.len() == 1
        )
        .cli(&["--expose-socket", "/run/app.sock"])
        .checkpoint(Refused("published sockets")),
        // Devices.
        case!(gpu, |s, _| s.gpu = true, |r| r.gpu == Some(true))
            .cli(&["--gpu"])
            .api(|_| json(serde_json::json!({"gpu": true})))
            .embedded(|e, _| e.spec.resources.gpu = true)
            .checkpoint(Refused("gpu")),
        case!(
            gpu_vram_mib,
            |s, _| {
                s.gpu = true;
                s.gpu_vram_mib = Some(2048);
            },
            |r| r.gpu_vram_mib == Some(2048)
        )
        .cli(&["--gpu", "--gpu-vram", "2048"])
        .embedded(|e, _| {
            e.spec.resources.gpu = true;
            e.spec.resources.gpu_vram_mib = Some(2048);
        })
        .checkpoint(Refused("gpu")),
        case!(rosetta, |s, _| s.rosetta = true, |r| r.rosetta == Some(true))
            .cli(&["--rosetta"])
            .embedded(|e, _| e.spec.resources.rosetta = true)
            .checkpoint(Refused("rosetta")),
        case!(nested_virt, |s, _| s.nested_virt = true, |r| r.nested_virt == Some(true))
            .cli(&["--nested"])
            .api(|_| json(serde_json::json!({"nestedVirt": true})))
            .embedded(|e, _| e.spec.resources.nested_virt = true)
            .checkpoint(Refused("nested virtualization")),
        case!(cuda, |s, _| s.cuda = true, |r| r.cuda)
            .cli(&["--cuda"])
            .api(|_| json(serde_json::json!({"cuda": true})))
            .embedded(|e, _| e.spec.resources.cuda = true)
            .checkpoint(Refused("cuda")),
        case!(docker_socket, |s, _| s.docker_socket = true, |r| r.docker_socket)
            .cli(&["--docker-socket"])
            .api(|_| json(serde_json::json!({"dockerSocket": true})))
            .checkpoint(Refused("docker socket")),
        case!(ssh_agent, |s, _| s.ssh_agent = true, |r| r.ssh_agent)
            .cli(&["--ssh-agent"])
            .checkpoint(Refused("ssh agent")),
        // Branching and lifecycle.
        case!(forkable, |s, _| s.forkable = true, |r| r.forkable)
            .smolfile("[fork]\nenabled = true\n")
            .embedded(|e, _| e.spec.forkable = true),
        case!(
            cuda_fork_pool_size,
            |s, _| {
                s.cuda = true;
                s.cuda_fork_pool_size = Some(2);
            },
            |r| r.cuda_fork_pool_size == Some(2)
        )
        .smolfile("cuda = true\n[fork]\npool_size = 2\n")
        .checkpoint(Refused("cuda")),
        case!(
            cuda_vram_limit_mib,
            |s, _| {
                s.cuda = true;
                s.cuda_fork_pool_size = Some(2);
                s.cuda_vram_limit_mib = Some(4096);
            },
            |r| r.cuda_vram_limit_mib == Some(4096)
        )
        .smolfile("cuda = true\n[fork]\npool_size = 2\ncuda_vram_limit_mib = 4096\n")
        .checkpoint(Refused("cuda")),
        case!(keep_identity, |s, _| s.keep_identity = true, |r| r.keep_identity)
            .cli(&["--keep-identity"])
            .fresh(Refused("checkpoint")),
        case!(ephemeral, |s, _| s.ephemeral = true, |r| r.ephemeral)
            .embedded(|e, _| e.spec.persistent = false),
        case!(detached, |s, _| s.detached = true, |r| r.detached)
            .embedded(|e, _| e.spec.detached = true),
        case!(runtime_managed, |s, _| s.runtime_managed = true, |r| r.runtime_managed)
            .embedded(|e, _| e.spec.runtime_managed = true),
        case!(
            labels,
            |s, _| {
                s.labels.insert("owner".into(), "ci".into());
            },
            |r| r.labels.get("owner").map(String::as_str) == Some("ci")
        )
        .cli(&["--label", "owner=ci"])
        .embedded(|e, _| {
            e.spec.labels.insert("owner".into(), "ci".into());
        }),
    ]
}

#[derive(clap::Parser)]
struct Harness {
    #[command(subcommand)]
    command: crate::cli::machine::MachineCmd,
}

/// `machine create` with `args`, as far as its spec: the flags merged over a
/// Smolfile, exactly as the command builds it.
fn cli_spec(args: &[String]) -> Result<(CreateSpec, Caller)> {
    use clap::Parser;
    let mut argv: Vec<String> = ["smolvm", "create", "--name", "m"]
        .into_iter()
        .map(String::from)
        .collect();
    argv.extend(args.iter().cloned());
    let crate::cli::machine::MachineCmd::Create(cmd) = Harness::try_parse_from(argv)
        .map_err(|e| Error::config("parse", e.to_string()))?
        .command
    else {
        panic!("expected machine create");
    };
    let (_, spec, caller) = cmd.create_spec()?;
    Ok((spec, caller))
}

/// The spec an embedder's SDK sends for a pack: serialized over stdin to
/// `machine create --spec-stdin`, with no flags on top.
fn over_stdin(spec: CreateSpec) -> CreateSpec {
    let sent = serde_json::to_vec(&spec).unwrap();
    let received: CreateSpec = serde_json::from_slice(&sent).unwrap();
    let (no_flags, _) = cli_spec(&[]).unwrap();
    received.overlay(no_flags)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Front {
    Cli,
    Api,
    Embedded,
    Spec,
}

fn front_spec(
    case: &Case,
    front: Front,
    src: Src,
    tmp: &str,
) -> Option<Result<(CreateSpec, Caller)>> {
    let sub = |s: &str| s.replace("{tmp}", tmp);
    Some(match front {
        Front::Cli => match &case.cli {
            Cli::Flags(flags) => cli_spec(&flags.iter().map(|f| sub(f)).collect::<Vec<_>>()),
            Cli::Smolfile(contents) => {
                let path = format!("{tmp}/Smolfile");
                std::fs::write(&path, contents).unwrap();
                cli_spec(&["-s".to_string(), path])
            }
            Cli::No => return None,
        },
        Front::Api => match &case.api {
            Api::Json(body) => {
                let (mut value, cache) = body(tmp);
                value["name"] = "m".into();
                let request: crate::api::types::CreateMachineRequest =
                    serde_json::from_value(value).unwrap();
                crate::api::handlers::machines::create_spec_from_request(&request, cache)
                    .map(|spec| (spec, Caller::Api))
                    .map_err(|e| Error::config("api", format!("{e:?}")))
            }
            Api::No => return None,
        },
        Front::Embedded => match &case.embedded {
            Embedded::Set(set) => {
                let mut input = EmbeddedIn {
                    spec: MachineSpec {
                        name: "m".into(),
                        image: (src == Src::Image).then(|| IMAGE.to_string()),
                        persistent: true,
                        resources: crate::data::resources::VmResources {
                            cpus: crate::data::resources::DEFAULT_MICROVM_CPU_COUNT,
                            memory_mib: crate::data::resources::default_microvm_memory_mib(),
                            ..Default::default()
                        },
                        ..Default::default()
                    },
                    env: Vec::new(),
                    workdir: None,
                    user: None,
                    credentials: None,
                };
                set(&mut input, tmp);
                let EmbeddedIn {
                    spec,
                    env,
                    workdir,
                    user,
                    credentials,
                } = input;
                spec.create_spec_with(env, workdir, user, credentials.as_ref())
                    .map(|create| {
                        let mut create = create;
                        if src != Src::Image {
                            // A machine spec always carries resources; an SDK
                            // sends a pack only the ones its caller set.
                            if case.field != "cpus" {
                                create.cpus = None;
                            }
                            if case.field != "mem" {
                                create.mem = None;
                            }
                            create = over_stdin(create);
                        }
                        (create, Caller::Embedded)
                    })
            }
            Embedded::No => return None,
        },
        Front::Spec => {
            let mut spec = CreateSpec::default();
            (case.spec)(&mut spec, tmp);
            Ok((over_stdin(spec), Caller::Embedded))
        }
    })
}

/// Every option, on every creation path (`machine create` flags and
/// Smolfile, the serve API's create request, the embedded runtime the SDKs
/// drive, and the spec an SDK sends for a pack), from every source (an
/// image, a pack, a live checkpoint): the record carries it, or the path
/// refuses it with an error naming it. A path that has no way to set an
/// option is listed as such in the case.
#[test]
fn every_option_is_applied_or_refused_on_every_path() {
    let tmp = tempfile::tempdir().unwrap();
    let tmp_path = tmp.path().to_str().unwrap().to_string();
    std::fs::write(tmp.path().join("file"), b"disk").unwrap();
    let mut checked = 0;
    let mut table = Vec::new();
    for case in cases() {
        // The check must tell the option apart from a machine without it.
        let baseline = fresh(CreateSpec::default(), Src::Image);
        assert!(
            !(case.applied)(&baseline),
            "{}: the check passes without the option",
            case.field
        );
        let mut row = vec![case.field.to_string()];
        for front in [Front::Cli, Front::Api, Front::Embedded, Front::Spec] {
            for src in SOURCES {
                let Some(spec) = front_spec(&case, front, src, &tmp_path) else {
                    row.push("-".into());
                    continue;
                };
                let expected = match (front, case.api_outcome) {
                    (Front::Api, Some(outcome)) => outcome,
                    _ if src == Src::Checkpoint => case.checkpoint,
                    _ => case.fresh,
                };
                let result = spec.and_then(|(spec, caller)| resolve_from(src, spec, caller));
                let at = format!("{} via {front:?} from {src:?}", case.field);
                row.push(match expected {
                    Applied => "applied".into(),
                    Refused(_) => "refused".into(),
                });
                match (expected, result) {
                    (Applied, Ok(record)) => {
                        assert!((case.applied)(&record), "{at}: dropped")
                    }
                    (Refused(why), Err(error)) => {
                        let message = error.to_string().to_lowercase();
                        assert!(message.contains(why), "{at}: refused with {message:?}");
                    }
                    (Applied, Err(error)) => panic!("{at}: refused: {error}"),
                    (Refused(why), Ok(_)) => panic!("{at}: applied, expected a refusal ({why})"),
                }
                checked += 1;
            }
        }
        table.push(row);
    }
    // `SMOLVM_PRINT_PARITY=1 cargo test every_option -- --nocapture` prints
    // the matrix: option, then CLI, API, embedded and spec paths, each from an
    // image, a pack and a checkpoint (`-`: the path has no way to set it).
    if std::env::var_os("SMOLVM_PRINT_PARITY").is_some() {
        for row in &table {
            println!("{}", row.join("\t"));
        }
    }
    assert!(checked > 300, "only {checked} cells checked");
}

/// Every record field is either written from the spec or named as state a
/// path owns; [`ResolvedSpec::to_record`] builds the record with a literal,
/// so a new field fails to compile there until it is decided.
#[test]
fn the_record_carries_every_resolved_setting() {
    let record = fresh(
        CreateSpec {
            labels: [("a".to_string(), "b".to_string())].into(),
            ..Default::default()
        },
        Src::Image,
    );
    assert_eq!(record.name, "m");
    assert_eq!(record.state, crate::config::RecordState::Created);
    assert_eq!(record.labels["a"], "b");
}
