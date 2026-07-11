//! Guest-side CUDA forwarding wiring for the workload container.
//!
//! When a VM is launched with `--cuda`, the launcher sets `SMOLVM_CUDA_ZEROCOPY`
//! in the agent's (PID 1) environment. The workload container gets its env from
//! the image plus the request — not from the agent's own env — so the zero-copy
//! opt-in has to be forwarded into the container spec explicitly, the same way
//! [`crate::ssh_agent`] forwards `SSH_AUTH_SOCK`.
//!
//! With the flag set, the guest CUDA shim (`libcudart.so`) backs
//! `cudaHostAlloc`/`cudaMallocHost` with page-locked guest RAM whose
//! guest-physical frames it reads from `/proc/self/pagemap`, so a memcpy ships
//! only a guest-physical descriptor and the host DMAs straight from guest RAM.
//! It degrades to byte-shipping wherever that path is unavailable (no
//! `CAP_SYS_ADMIN`, older libkrun), so forwarding it is always safe.

/// The env var the launcher sets on the agent, and that the guest shim reads.
const ZEROCOPY_ENV: &str = "SMOLVM_CUDA_ZEROCOPY";

/// Whether CUDA guest-RAM zero-copy was requested for this VM.
pub fn zerocopy_enabled() -> bool {
    std::env::var(ZEROCOPY_ENV).as_deref() == Ok("1")
}

/// Forward the CUDA zero-copy opt-in from the agent env into the workload
/// container spec. Used on the fresh-container path (`crun run`/`create`, which
/// reads env from the bundle spec). No-op unless CUDA zero-copy was requested.
pub fn inject_into_container(spec: &mut crate::oci::OciSpec) {
    inject_into_container_if(spec, zerocopy_enabled());
}

/// Testable core of [`inject_into_container`]: sets the env var when `enabled`.
fn inject_into_container_if(spec: &mut crate::oci::OciSpec, enabled: bool) {
    if !enabled {
        return;
    }
    spec.add_env(ZEROCOPY_ENV, "1");
}

/// Append the CUDA zero-copy opt-in to an explicit exec env when enabled. Used
/// on the `crun exec` path (joining a persistent machine's keep-alive
/// container), where the workload env is passed via `--env` rather than
/// inherited from the container spec, so the spec injection above doesn't reach
/// it. No-op when disabled or already present.
pub fn augment_exec_env(mut env: Vec<(String, String)>) -> Vec<(String, String)> {
    if zerocopy_enabled() && !env.iter().any(|(k, _)| k == ZEROCOPY_ENV) {
        env.push((ZEROCOPY_ENV.to_string(), "1".to_string()));
    }
    env
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oci::{OciSpec, ProcessIdentity};

    fn spec() -> OciSpec {
        OciSpec::new(
            &["true".to_string()],
            &[],
            "/",
            false,
            &ProcessIdentity::root(),
            false,
        )
    }

    #[test]
    fn injects_when_enabled() {
        let mut s = spec();
        inject_into_container_if(&mut s, true);
        assert!(s.process.env.iter().any(|e| e == "SMOLVM_CUDA_ZEROCOPY=1"));
    }

    #[test]
    fn noop_when_disabled() {
        let mut s = spec();
        inject_into_container_if(&mut s, false);
        assert!(!s
            .process
            .env
            .iter()
            .any(|e| e.starts_with("SMOLVM_CUDA_ZEROCOPY")));
    }

    #[test]
    fn augment_exec_env_is_idempotent() {
        let base = vec![("SMOLVM_CUDA_ZEROCOPY".to_string(), "1".to_string())];
        // Already present → unchanged regardless of gate.
        assert_eq!(augment_exec_env(base.clone()), base);
    }
}
