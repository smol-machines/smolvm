//! Pin non-secret state/runtime paths before CLI startup resolves directories.
use anyhow::{ensure, Context as _, Result};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, ffi::OsString, path::PathBuf, sync::OnceLock};

static APPLIED: OnceLock<String> = OnceLock::new();
const VARIABLES: &[&str] = &[
    "SMOLVM_DATA_DIR",
    "SMOLVM_CONFIG",
    "SMOLVM_AGENT_ROOTFS",
    "SMOLVM_LIB_DIR",
    "XDG_CACHE_HOME",
    "XDG_DATA_HOME",
    "XDG_CONFIG_HOME",
    "XDG_RUNTIME_DIR",
];
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Context {
    version: u8,
    pub machine: String,
    pub host_key: String,
    paths: BTreeMap<String, Option<PathBuf>>,
}
impl Context {
    pub fn capture(machine: &str, host_key: &russh::keys::PublicKey) -> Result<String> {
        let mut paths = BTreeMap::new();
        for name in VARIABLES {
            let path = std::env::var_os(name)
                .map(std::path::absolute)
                .transpose()?;
            paths.insert((*name).to_string(), path);
        }
        // Default platform directories are pinned too, so a different shell's
        // XDG overrides cannot select another machine with the same name.
        for (name, path) in [
            ("XDG_CACHE_HOME", smolvm_paths::cache_dir()),
            ("XDG_DATA_HOME", smolvm_paths::data_local_dir()),
            ("XDG_CONFIG_HOME", smolvm_paths::config_dir()),
            ("XDG_RUNTIME_DIR", smolvm_paths::runtime_dir()),
        ] {
            paths.insert(name.into(), path);
        }
        Ok(hex::encode(serde_json::to_vec(&Self {
            version: 1,
            machine: machine.into(),
            host_key: host_key.to_openssh()?,
            paths,
        })?))
    }
    pub fn decode(encoded: &str) -> Result<Self> {
        ensure!(encoded.len() <= 32768, "SSH context is too large");
        let value: Self = serde_json::from_slice(&hex::decode(encoded)?)?;
        ensure!(
            value.version == 1
                && !value.machine.is_empty()
                && value.machine.len() <= 1024
                && !value.machine.contains('\0'),
            "invalid SSH machine context"
        );
        ensure!(
            value.paths.len() == VARIABLES.len()
                && VARIABLES.iter().all(|name| value.paths.contains_key(*name)),
            "invalid SSH context variables"
        );
        for path in value.paths.values().flatten() {
            ensure!(path.is_absolute(), "SSH context paths must be absolute");
        }
        russh::keys::PublicKey::from_openssh(&value.host_key)
            .context("invalid SSH machine identity")?;
        Ok(value)
    }
    pub fn applied(encoded: &str) -> Result<Self> {
        ensure!(
            APPLIED.get().is_some_and(|s| s == encoded),
            "SSH proxy must use its generated startup context"
        );
        Self::decode(encoded)
    }
}
pub(super) fn apply(args: &[OsString]) -> Result<()> {
    if args.first().and_then(|s| s.to_str()) != Some("machine")
        || args.get(1).and_then(|s| s.to_str()) != Some("ssh-proxy")
    {
        return Ok(());
    }
    ensure!(
        args.len() == 4 && args[2] == "--context-hex",
        "use the generated SSH proxy command"
    );
    let encoded = args[3].to_str().context("invalid SSH startup context")?;
    let value = Context::decode(encoded)?;
    ensure!(
        APPLIED.get().is_none(),
        "SSH startup context was already applied"
    );
    for (name, path) in value.paths {
        match path {
            Some(path) => std::env::set_var(name, path),
            None => std::env::remove_var(name),
        }
    }
    APPLIED
        .set(encoded.to_owned())
        .map_err(|_| anyhow::anyhow!("SSH context already applied"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_rejects_environment_injection_relative_paths_and_unknown_versions() {
        let key =
            russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
                .unwrap();
        let encoded = Context::capture("machine with spaces", key.public_key()).unwrap();
        assert_eq!(
            Context::decode(&encoded).unwrap().machine,
            "machine with spaces"
        );
        let original: serde_json::Value =
            serde_json::from_slice(&hex::decode(&encoded).unwrap()).unwrap();
        for mutation in [0, 1, 2, 3, 4] {
            let mut value = original.clone();
            match mutation {
                0 => value["paths"]["LD_PRELOAD"] = "/tmp/injected.so".into(),
                1 => value["paths"]["SMOLVM_DATA_DIR"] = "relative".into(),
                2 => value["version"] = 2.into(),
                3 => value["machine"] = "\0".into(),
                _ => value["host_key"] = "invalid public key".into(),
            }
            assert!(Context::decode(&hex::encode(serde_json::to_vec(&value).unwrap())).is_err());
        }
        assert!(Context::decode(&"a".repeat(32769)).is_err());
    }
}
