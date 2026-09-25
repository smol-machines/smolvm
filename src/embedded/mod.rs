//! Language-neutral embedded runtime support for SDK bindings.

mod control;
mod handle;
mod runtime;

pub use control::MachineSpec;
pub use runtime::{runtime, EmbeddedRuntime};

/// Parse the trusted loopback interceptor binding supplied by an SDK caller.
/// The token is per launch and is never written to a machine record.
pub fn interceptor_endpoint(
    address: &str,
    token_hex: &str,
) -> crate::Result<smolvm_protocol::InterceptEndpoint> {
    let addr = address
        .parse::<std::net::SocketAddr>()
        .map_err(|_| crate::Error::config("egress interceptor", "invalid socket address"))?;
    let mut token = [0; smolvm_protocol::intercept::TOKEN_LEN];
    if hex::decode_to_slice(token_hex, &mut token).is_err() || token == [0; 32] {
        return Err(crate::Error::config(
            "egress interceptor",
            "token must contain 64 hex digits and must not be all zeros",
        ));
    }
    if !addr.ip().is_loopback() || addr.port() == 0 {
        return Err(crate::Error::config(
            "egress interceptor",
            "address must be a loopback socket with a nonzero port",
        ));
    }
    Ok(smolvm_protocol::InterceptEndpoint { addr, token })
}

#[cfg(test)]
mod interceptor_tests {
    use super::interceptor_endpoint;

    #[test]
    fn binding_requires_loopback_and_random_hex_token() {
        let good = "a5".repeat(32);
        assert!(interceptor_endpoint("127.0.0.1:9000", &good).is_ok());
        assert!(interceptor_endpoint("[::1]:9000", &good).is_ok());
        assert!(interceptor_endpoint("0.0.0.0:9000", &good).is_err());
        assert!(interceptor_endpoint("127.0.0.1:0", &good).is_err());
        assert!(interceptor_endpoint("127.0.0.1:9000", &"0".repeat(64)).is_err());
        assert!(interceptor_endpoint("127.0.0.1:9000", "abc").is_err());
    }
}
