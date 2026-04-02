//! Conversions between the public MicroVm types and the internal VmRecord
//! persistence format.

use crate::data::mount::HostMount;
use crate::data::network::PortMapping;
use crate::data::resources::VmResources;
use crate::data::vm::{MicroVm, VmPhase, VmSpec, VmStatus};
use crate::internal::config::{RecordState, VmRecord};

/// Convert a VmRecord (DB row) into a MicroVm (public type).
pub(crate) fn record_to_vm(record: &VmRecord) -> MicroVm {
    MicroVm {
        name: record.name.clone(),
        spec: VmSpec {
            resources: VmResources {
                cpus: record.cpus,
                memory_mib: record.mem,
                network: record.network,
                storage_gib: record.storage_gb,
                overlay_gib: record.overlay_gb,
                allowed_cidrs: record.allowed_cidrs.clone(),
            },
            mounts: record
                .mounts
                .iter()
                .map(|(h, g, ro)| HostMount::from_storage_tuple(h.clone(), g.clone(), *ro))
                .collect(),
            ports: record
                .ports
                .iter()
                .map(|(h, g)| PortMapping::new(*h, *g))
                .collect(),
            image: record.image.clone(),
            entrypoint: record.entrypoint.clone(),
            cmd: record.cmd.clone(),
            env: record.env.clone(),
            workdir: record.workdir.clone(),
            init: record.init.clone(),
        },
        status: Some(VmStatus {
            phase: record_state_to_phase(&record.actual_state()),
            pid: record.pid,
            pid_start_time: record.pid_start_time,
            created_at: record.created_at.clone(),
            last_exit_code: record.last_exit_code,
        }),
    }
}

/// Convert a MicroVm (public type) into a VmRecord (for DB writes).
///
/// If `status` is `None`, defaults to `RecordState::Created` with no PID.
pub(crate) fn vm_to_record(vm: &MicroVm) -> VmRecord {
    let (state, pid, pid_start_time, created_at, last_exit_code) = match &vm.status {
        Some(status) => (
            phase_to_record_state(status.phase),
            status.pid,
            status.pid_start_time,
            status.created_at.clone(),
            status.last_exit_code,
        ),
        None => (
            RecordState::Created,
            None,
            None,
            crate::internal::util::current_timestamp(),
            None,
        ),
    };

    let mut record = VmRecord::new(
        vm.name.clone(),
        vm.spec.resources.cpus,
        vm.spec.resources.memory_mib,
        vm.spec
            .mounts
            .iter()
            .map(|m| m.to_storage_tuple())
            .collect(),
        vm.spec.ports.iter().map(|p| (p.host, p.guest)).collect(),
        vm.spec.resources.network,
    );

    record.state = state;
    record.pid = pid;
    record.pid_start_time = pid_start_time;
    record.created_at = created_at;
    record.last_exit_code = last_exit_code;
    record.storage_gb = vm.spec.resources.storage_gib;
    record.overlay_gb = vm.spec.resources.overlay_gib;
    record.allowed_cidrs = vm.spec.resources.allowed_cidrs.clone();
    record.image = vm.spec.image.clone();
    record.entrypoint = vm.spec.entrypoint.clone();
    record.cmd = vm.spec.cmd.clone();
    record.env = vm.spec.env.clone();
    record.workdir = vm.spec.workdir.clone();
    record.init = vm.spec.init.clone();

    record
}

/// Map RecordState → VmPhase.
pub(crate) fn record_state_to_phase(state: &RecordState) -> VmPhase {
    match state {
        RecordState::Created => VmPhase::Created,
        RecordState::Running => VmPhase::Running,
        RecordState::Stopped => VmPhase::Stopped,
        RecordState::Failed => VmPhase::Failed,
    }
}

/// Map VmPhase → RecordState.
pub(crate) fn phase_to_record_state(phase: VmPhase) -> RecordState {
    match phase {
        VmPhase::Created => RecordState::Created,
        VmPhase::Running => RecordState::Running,
        VmPhase::Stopped => RecordState::Stopped,
        VmPhase::Failed => RecordState::Failed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_trip_default_microvm() {
        let vm = MicroVm {
            name: "test-vm".into(),
            spec: VmSpec::default(),
            status: None,
        };

        let record = vm_to_record(&vm);
        assert_eq!(record.name, "test-vm");
        assert_eq!(record.state, RecordState::Created);
        assert!(record.pid.is_none());

        let back = record_to_vm(&record);
        assert_eq!(back.name, "test-vm");
        assert!(back.status.is_some());
        assert_eq!(back.status.as_ref().unwrap().phase, VmPhase::Created);
    }

    #[test]
    fn test_round_trip_with_spec_fields() {
        let vm = MicroVm {
            name: "full-vm".into(),
            spec: VmSpec {
                resources: VmResources {
                    cpus: 4,
                    memory_mib: 2048,
                    network: true,
                    storage_gib: Some(50),
                    overlay_gib: Some(20),
                    allowed_cidrs: Some(vec!["10.0.0.0/8".into()]),
                },
                image: Some("alpine:latest".into()),
                entrypoint: vec!["/bin/sh".into()],
                cmd: vec!["-c".into(), "echo hi".into()],
                env: vec![("FOO".into(), "bar".into())],
                workdir: Some("/app".into()),
                init: vec!["apk update".into()],
                ..Default::default()
            },
            status: None,
        };

        let record = vm_to_record(&vm);
        assert_eq!(record.cpus, 4);
        assert_eq!(record.mem, 2048);
        assert!(record.network);
        assert_eq!(record.storage_gb, Some(50));
        assert_eq!(record.image, Some("alpine:latest".into()));
        assert_eq!(record.env, vec![("FOO".into(), "bar".into())]);
        assert_eq!(record.allowed_cidrs, Some(vec!["10.0.0.0/8".into()]));

        let back = record_to_vm(&record);
        assert_eq!(back.spec.resources.cpus, 4);
        assert_eq!(back.spec.image, Some("alpine:latest".into()));
        assert_eq!(back.spec.env, vec![("FOO".into(), "bar".into())]);
        assert_eq!(
            back.spec.resources.allowed_cidrs,
            Some(vec!["10.0.0.0/8".into()])
        );
    }

    #[test]
    fn test_phase_round_trip() {
        for phase in [
            VmPhase::Created,
            VmPhase::Running,
            VmPhase::Stopped,
            VmPhase::Failed,
        ] {
            let state = phase_to_record_state(phase);
            let back = record_state_to_phase(&state);
            assert_eq!(back, phase);
        }
    }
}
