//! Endpoint configuration for the guest shims, read from the environment.
//!
//! De-branded so the shims are usable as a standalone "forward CUDA to another
//! host" tool without smolvm: a consumer sets `CUDA_REMOTE_ENDPOINT`. The
//! legacy `SMOLVM_CUDA_RPC` name is still honored (smolvm sets it), so existing
//! deployments keep working.

/// The transport spec, e.g. `tcp:HOST:PORT`, `unix:/path`, or `vsock`.
/// Checks `CUDA_REMOTE_ENDPOINT` first, then `SMOLVM_CUDA_RPC`. Empty = the
/// default vsock transport (in-guest).
pub fn transport_spec() -> String {
    std::env::var("CUDA_REMOTE_ENDPOINT")
        .or_else(|_| std::env::var("SMOLVM_CUDA_RPC"))
        .unwrap_or_default()
}

/// Default AF_VSOCK `(cid, port)` for the in-guest transport. Overridable via
/// `CUDA_REMOTE_VSOCK=<cid>:<port>`; defaults to host CID 2, port 7000.
pub fn vsock_default() -> (u32, u32) {
    const DEFAULT_CID: u32 = 2;
    const DEFAULT_PORT: u32 = 7000;
    match std::env::var("CUDA_REMOTE_VSOCK") {
        Ok(v) => {
            let mut parts = v.splitn(2, ':');
            let cid = parts
                .next()
                .and_then(|s| s.parse().ok())
                .unwrap_or(DEFAULT_CID);
            let port = parts
                .next()
                .and_then(|s| s.parse().ok())
                .unwrap_or(DEFAULT_PORT);
            (cid, port)
        }
        Err(_) => (DEFAULT_CID, DEFAULT_PORT),
    }
}
