//! Smolfile support for smolvm.
//!
//! Re-exports all types and parsing from the standalone [`smolfile`] crate,
//! plus smolvm-specific helpers (file loading with smolvm error types,
//! CIDR validation).
//!
//! See the [`smolfile`] crate documentation for the full Smolfile specification.

// Re-export everything from the standalone crate.
pub use smolfile::*;

use std::path::Path;

// ============================================================================
// smolvm-specific loading (wraps crate error into smolvm::Error)
// ============================================================================

/// Load and parse a Smolfile from the given path.
///
/// This is a convenience wrapper that converts [`smolfile::SmolfileError`]
/// into [`crate::Error`] for use within smolvm.
pub fn load(path: &Path) -> crate::Result<Smolfile> {
    smolfile::load(path).map_err(|e| crate::Error::config("load smolfile", e.to_string()))
}

// ============================================================================
// Network helpers (smolvm-specific, depend on ipnet and std::net)
// ============================================================================

/// Parse and validate a CIDR specification (e.g., `"10.0.0.0/8"`, `"1.1.1.1"`).
///
/// Accepts `IP/prefix` or bare `IP` (auto-appends /32 for IPv4, /128 for IPv6).
/// Returns the normalized CIDR string.
pub fn parse_cidr(s: &str) -> Result<String, String> {
    use ipnet::IpNet;
    use std::net::IpAddr;

    let net: IpNet = match s.parse::<IpNet>() {
        Ok(net) => net,
        Err(_) => match s.parse::<IpAddr>() {
            Ok(ip) => IpNet::from(ip),
            Err(_) => {
                return Err(format!(
                    "invalid CIDR '{}': expected format like 10.0.0.0/8 or 1.1.1.1",
                    s
                ))
            }
        },
    };

    Ok(net.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cidr_valid() {
        assert_eq!(parse_cidr("10.0.0.0/8").unwrap(), "10.0.0.0/8");
        assert_eq!(parse_cidr("1.1.1.1").unwrap(), "1.1.1.1/32");
    }

    #[test]
    fn parse_cidr_invalid() {
        assert!(parse_cidr("not-a-cidr").is_err());
    }

    #[test]
    fn load_basic_smolfile() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Smolfile");
        std::fs::write(
            &path,
            r#"
image = "alpine"
cpus = 2
memory = 1024
net = true

[dev]
volumes = ["./src:/app"]
init = ["echo hello"]
"#,
        )
        .unwrap();
        let sf = load(&path).unwrap();
        assert_eq!(sf.image.as_deref(), Some("alpine"));
        assert_eq!(sf.cpus, Some(2));
        assert_eq!(sf.dev.unwrap().volumes, vec!["./src:/app"]);
    }

    #[test]
    fn smolfile_gpu_field() {
        let dir = tempfile::tempdir().unwrap();

        // With gpu = true
        let path = dir.path().join("gpu.smolfile");
        std::fs::write(&path, "image = \"alpine\"\ngpu = true\n").unwrap();
        let sf = load(&path).unwrap();
        assert_eq!(sf.gpu, Some(true));

        // Without gpu field (defaults to None)
        let path = dir.path().join("nogpu.smolfile");
        std::fs::write(&path, "image = \"alpine\"\n").unwrap();
        let sf = load(&path).unwrap();
        assert_eq!(sf.gpu, None);

        // With gpu = false
        let path = dir.path().join("gpuoff.smolfile");
        std::fs::write(&path, "image = \"alpine\"\ngpu = false\n").unwrap();
        let sf = load(&path).unwrap();
        assert_eq!(sf.gpu, Some(false));
    }
}
