//! Carry this host's network trust into a machine: its proxy and the
//! certificates it trusts.
//!
//! Behind a corporate firewall the host is already set up — a proxy to go out
//! through, and often a TLS-inspection root certificate installed by IT — but a
//! machine starts with neither, so its tools fail to connect or fail
//! certificate checks. Two opt-in flags fix that:
//!
//! - `--use-host-proxy`: the host's `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY`
//!   / `NO_PROXY`, or on macOS the system proxy when none is set, become the
//!   workload's proxy environment (both cases). A proxy on the host's loopback
//!   is rewritten to an address the guest can reach.
//! - `--trust-host-certs`: the certificates the host trusts (on macOS the
//!   system roots plus the System keychain, where managed devices get their
//!   corporate root; on Linux the system bundle) are written to a bundle,
//!   mounted read-only into the machine, and the usual trust variables
//!   (`SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, …) point at
//!   it. The guest image pull uses the same bundle before the workload starts.
//!   Opt-in because it widens what the machine trusts to what the host does.
//!
//! The machine receives environment and a volume, so a value passed with `-e`
//! still wins and `machine create` persists them like any other. Host-side
//! registry requests also use the host's trust store.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Where the host bundle is mounted in the machine. Under `/etc` rather than
/// `/run`, which containers often cover with a tmpfs.
pub const GUEST_TRUST_DIR: &str = "/etc/smolvm-host-trust";
const BUNDLE_FILE: &str = "ca-bundle.pem";

/// Variables tools read for a CA bundle. Each points at the full host bundle,
/// which already includes the public roots, so replacing a tool's own store
/// keeps public sites working.
const TRUST_VARS: &[&str] = &[
    "SSL_CERT_FILE",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "NODE_EXTRA_CA_CERTS",
    "GIT_SSL_CAINFO",
    "DENO_CERT",
    "AWS_CA_BUNDLE",
    "PIP_CERT",
    "CARGO_HTTP_CAINFO",
];

/// Linux system bundles, most common first.
#[cfg(target_os = "linux")]
const LINUX_BUNDLES: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
    "/etc/ssl/cert.pem",
];

/// Hosts that must never go through the proxy from inside a machine.
const GUEST_NO_PROXY: &[&str] = &["localhost", "127.0.0.1", "::1"];

/// What the flags add to a machine.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct HostNetwork {
    /// `KEY=VALUE` entries, placed before the user's `-e` so those win.
    pub env: Vec<String>,
    /// `HOST:GUEST:ro` volume specs.
    pub volumes: Vec<String>,
    /// The HTTPS proxy, for the image pull when `--proxy` was not given.
    pub pull_proxy: Option<String>,
}

impl HostNetwork {
    /// Resolve the flags against this host. Fails loudly when a flag was asked
    /// for but the host has nothing to give, rather than starting a machine
    /// that would fail later with an opaque connection or certificate error.
    pub fn resolve(
        use_host_proxy: bool,
        trust_host_certs: bool,
        has_credentials: bool,
    ) -> smolvm::Result<Self> {
        let mut out = HostNetwork::default();
        if use_host_proxy {
            let proxy = HostProxy::detect()?.ok_or_else(|| {
                smolvm::Error::config(
                    "--use-host-proxy",
                    "this host has no proxy configured (no HTTPS_PROXY/HTTP_PROXY/ALL_PROXY, \
                     and no system proxy); set HTTPS_PROXY or pass -e https_proxy=…",
                )
            })?;
            let proxy = proxy.reachable_from_guest()?;
            out.pull_proxy = proxy.https.clone().or_else(|| proxy.all.clone());
            out.env.extend(proxy.env());
        }
        if trust_host_certs {
            if has_credentials {
                // Credential substitution points the same variables at its own
                // bundle (image roots + the machine CA); the two cannot both win.
                return Err(smolvm::Error::config(
                    "--trust-host-certs",
                    "cannot be combined with --credential yet: both set the machine's trust bundle",
                ));
            }
            let pem = host_trust_bundle()?;
            let dir = stage_bundle(&pem)?;
            out.volumes
                .push(format!("{}:{GUEST_TRUST_DIR}:ro", dir.display()));
            out.env.extend(trust_env());
        }
        Ok(out)
    }
}

/// The trust variables, all pointing at the mounted bundle.
pub fn trust_env() -> Vec<String> {
    TRUST_VARS
        .iter()
        .map(|var| format!("{var}={GUEST_TRUST_DIR}/{BUNDLE_FILE}"))
        .collect()
}

/// A host's proxy settings.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct HostProxy {
    pub https: Option<String>,
    pub http: Option<String>,
    pub all: Option<String>,
    pub no_proxy: Vec<String>,
}

impl HostProxy {
    /// From the environment, else (macOS) the system proxy.
    pub fn detect() -> smolvm::Result<Option<Self>> {
        let env: BTreeMap<String, String> = std::env::vars().collect();
        if let Some(proxy) = Self::from_env(&env) {
            return Ok(Some(proxy));
        }
        #[cfg(target_os = "macos")]
        {
            if let Ok(out) = std::process::Command::new("/usr/sbin/scutil")
                .arg("--proxy")
                .output()
            {
                return Self::from_scutil(&String::from_utf8_lossy(&out.stdout));
            }
        }
        Ok(None)
    }

    /// Proxy variables, upper- or lower-case (lower wins, as curl reads it).
    pub fn from_env(env: &BTreeMap<String, String>) -> Option<Self> {
        let get = |name: &str| {
            env.get(&name.to_ascii_lowercase())
                .or_else(|| env.get(name))
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };
        let proxy = HostProxy {
            https: get("HTTPS_PROXY"),
            http: get("HTTP_PROXY"),
            all: get("ALL_PROXY"),
            no_proxy: get("NO_PROXY")
                .map(|v| split_no_proxy(&v))
                .unwrap_or_default(),
        };
        (proxy.https.is_some() || proxy.http.is_some() || proxy.all.is_some()).then_some(proxy)
    }

    /// macOS `scutil --proxy` output. A proxy auto-config (PAC) file cannot be
    /// evaluated here, so a PAC-only setup is an error with what to do instead.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub fn from_scutil(out: &str) -> smolvm::Result<Option<Self>> {
        let field = |key: &str| {
            out.lines().find_map(|line| {
                let (k, v) = line.trim().split_once(':')?;
                (k.trim() == key).then(|| v.trim().to_string())
            })
        };
        let enabled = |key: &str| field(key).as_deref() == Some("1");
        let endpoint = |on: &str, host: &str, port: &str| {
            if !enabled(on) {
                return None;
            }
            let host = field(host).filter(|h| !h.is_empty())?;
            let port = field(port).filter(|p| !p.is_empty());
            Some(match port {
                Some(port) => format!("http://{host}:{port}"),
                None => format!("http://{host}"),
            })
        };
        let https = endpoint("HTTPSEnable", "HTTPSProxy", "HTTPSPort");
        let http = endpoint("HTTPEnable", "HTTPProxy", "HTTPPort");
        if https.is_none() && http.is_none() {
            if enabled("ProxyAutoConfigEnable") {
                return Err(smolvm::Error::config(
                    "--use-host-proxy",
                    "this Mac's proxy is a PAC file, which smolvm cannot evaluate; set HTTPS_PROXY \
                     to the proxy it resolves to (e.g. http://proxy.corp:8080)",
                ));
            }
            return Ok(None);
        }
        // ExceptionsList : <array> { 0 : *.local  1 : 169.254/16 }
        let mut no_proxy = Vec::new();
        let mut in_exceptions = false;
        for line in out.lines() {
            let line = line.trim();
            if line.starts_with("ExceptionsList") {
                in_exceptions = true;
                continue;
            }
            if in_exceptions {
                if line.starts_with('}') {
                    break;
                }
                if let Some((_, v)) = line.split_once(':') {
                    let v = v.trim().trim_start_matches('*');
                    if !v.is_empty() {
                        no_proxy.push(v.to_string());
                    }
                }
            }
        }
        Ok(Some(HostProxy {
            https,
            http,
            all: None,
            no_proxy,
        }))
    }

    /// Rewrite a proxy on the host's loopback to an address the guest reaches.
    pub fn reachable_from_guest(self) -> smolvm::Result<Self> {
        let fix = |v: Option<String>| -> smolvm::Result<Option<String>> {
            v.map(|u| crate::cli::proxy_opts::resolve_loopback_proxy(&u))
                .transpose()
        };
        Ok(HostProxy {
            https: fix(self.https)?,
            http: fix(self.http)?,
            all: fix(self.all)?,
            no_proxy: self.no_proxy,
        })
    }

    /// The workload environment: each variable in both cases, and a NO_PROXY
    /// that always keeps the guest's own loopback direct.
    pub fn env(&self) -> Vec<String> {
        let mut env = Vec::new();
        let mut both = |name: &str, value: &str| {
            env.push(format!("{name}={value}"));
            env.push(format!("{}={value}", name.to_ascii_lowercase()));
        };
        if let Some(v) = &self.https {
            both("HTTPS_PROXY", v);
        }
        if let Some(v) = &self.http {
            both("HTTP_PROXY", v);
        }
        if let Some(v) = &self.all {
            both("ALL_PROXY", v);
        }
        let mut no_proxy = self.no_proxy.clone();
        for host in GUEST_NO_PROXY {
            if !no_proxy.iter().any(|h| h == host) {
                no_proxy.push(host.to_string());
            }
        }
        both("NO_PROXY", &no_proxy.join(","));
        env
    }
}

fn split_no_proxy(v: &str) -> Vec<String> {
    v.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// Overrides where `--trust-host-certs` reads the host's certificates from, for
/// hosts whose trust store is not the system default (Nix, a custom bundle).
pub const HOST_CA_BUNDLE_ENV: &str = "SMOLVM_HOST_CA_BUNDLE";

/// The certificates this host trusts, as one PEM bundle.
pub fn host_trust_bundle() -> smolvm::Result<String> {
    let pem = match std::env::var_os(HOST_CA_BUNDLE_ENV) {
        Some(path) => std::fs::read_to_string(&path).map_err(|e| {
            smolvm::Error::config(
                "--trust-host-certs",
                format!("{HOST_CA_BUNDLE_ENV}={}: {e}", Path::new(&path).display()),
            )
        })?,
        None => read_host_bundle()?,
    };
    let count = pem.matches("-----BEGIN CERTIFICATE-----").count();
    if count == 0 {
        return Err(smolvm::Error::config(
            "--trust-host-certs",
            "found no certificates in this host's trust store",
        ));
    }
    tracing::info!(
        certificates = count,
        "trusting the host's certificates in the machine"
    );
    Ok(pem)
}

#[cfg(target_os = "macos")]
fn read_host_bundle() -> smolvm::Result<String> {
    // System roots, plus the System keychain where admin- and MDM-installed
    // roots (a corporate TLS-inspection CA) live.
    let mut pem = String::new();
    for keychain in [
        "/System/Library/Keychains/SystemRootCertificates.keychain",
        "/Library/Keychains/System.keychain",
    ] {
        let out = std::process::Command::new("/usr/bin/security")
            .args(["find-certificate", "-a", "-p", keychain])
            .output()
            .map_err(|e| {
                smolvm::Error::config("--trust-host-certs", format!("read {keychain}: {e}"))
            })?;
        if out.status.success() {
            pem.push_str(&String::from_utf8_lossy(&out.stdout));
        }
    }
    Ok(pem)
}

#[cfg(target_os = "linux")]
fn read_host_bundle() -> smolvm::Result<String> {
    for path in LINUX_BUNDLES {
        if let Ok(pem) = std::fs::read_to_string(path) {
            return Ok(pem);
        }
    }
    Err(smolvm::Error::config(
        "--trust-host-certs",
        format!(
            "no system CA bundle found (looked in {})",
            LINUX_BUNDLES.join(", ")
        ),
    ))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn read_host_bundle() -> smolvm::Result<String> {
    Err(smolvm::Error::config(
        "--trust-host-certs",
        "not supported on this host yet",
    ))
}

/// Write the bundle under smolvm's cache, named by its content, so a machine
/// that persists the mount keeps pointing at the same bytes.
fn stage_bundle(pem: &str) -> smolvm::Result<PathBuf> {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(pem.as_bytes());
    let name: String = digest.iter().take(8).map(|b| format!("{b:02x}")).collect();
    let root = smolvm::agent::cache_root().join("host-trust");
    let dir = root.join(name);
    let file = dir.join(BUNDLE_FILE);
    if !file.exists() {
        std::fs::create_dir_all(&dir).map_err(|e| {
            smolvm::Error::config("--trust-host-certs", format!("{}: {e}", dir.display()))
        })?;
        let staging = dir.join(format!(".{BUNDLE_FILE}.{}", std::process::id()));
        std::fs::write(&staging, pem)
            .and_then(|()| std::fs::rename(&staging, &file))
            .map_err(|e| {
                smolvm::Error::config("--trust-host-certs", format!("{}: {e}", file.display()))
            })?;
    }
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn proxy_env_reads_either_case_and_keeps_guest_loopback_direct() {
        let p = HostProxy::from_env(&env(&[
            ("HTTPS_PROXY", "http://proxy.corp:3128"),
            ("no_proxy", "internal.corp, .svc"),
        ]))
        .unwrap();
        assert_eq!(p.https.as_deref(), Some("http://proxy.corp:3128"));
        let out = p.env();
        assert!(out.contains(&"HTTPS_PROXY=http://proxy.corp:3128".to_string()));
        assert!(out.contains(&"https_proxy=http://proxy.corp:3128".to_string()));
        let no_proxy = out.iter().find(|e| e.starts_with("no_proxy=")).unwrap();
        assert_eq!(
            no_proxy,
            "no_proxy=internal.corp,.svc,localhost,127.0.0.1,::1"
        );
        assert!(HostProxy::from_env(&env(&[("NO_PROXY", "x")])).is_none());
    }

    #[test]
    fn a_macos_system_proxy_is_read_from_scutil() {
        let out = "<dictionary> {\n  ExceptionsList : <array> {\n    0 : *.local\n    1 : 169.254/16\n  }\n  HTTPEnable : 1\n  HTTPPort : 8080\n  HTTPProxy : proxy.corp\n  HTTPSEnable : 1\n  HTTPSPort : 8443\n  HTTPSProxy : proxy.corp\n}\n";
        let p = HostProxy::from_scutil(out).unwrap().unwrap();
        assert_eq!(p.https.as_deref(), Some("http://proxy.corp:8443"));
        assert_eq!(p.http.as_deref(), Some("http://proxy.corp:8080"));
        assert_eq!(
            p.no_proxy,
            vec![".local".to_string(), "169.254/16".to_string()]
        );
    }

    #[test]
    fn a_pac_only_mac_is_an_actionable_error_and_no_proxy_is_none() {
        let pac = "<dictionary> {\n  ProxyAutoConfigEnable : 1\n  ProxyAutoConfigURLString : http://wpad/proxy.pac\n}\n";
        assert!(HostProxy::from_scutil(pac).is_err());
        let none = "<dictionary> {\n  HTTPEnable : 0\n}\n";
        assert!(HostProxy::from_scutil(none).unwrap().is_none());
    }

    #[test]
    fn trust_variables_point_at_the_mounted_bundle() {
        let env = trust_env();
        assert!(env.contains(&"SSL_CERT_FILE=/etc/smolvm-host-trust/ca-bundle.pem".to_string()));
        assert!(
            env.contains(&"NODE_EXTRA_CA_CERTS=/etc/smolvm-host-trust/ca-bundle.pem".to_string())
        );
    }

    #[test]
    fn trusting_host_certs_is_refused_alongside_credentials() {
        assert!(HostNetwork::resolve(false, true, true).is_err());
    }

    #[test]
    fn the_staged_bundle_is_content_addressed() {
        let a =
            stage_bundle("-----BEGIN CERTIFICATE-----\nA\n-----END CERTIFICATE-----\n").unwrap();
        let b =
            stage_bundle("-----BEGIN CERTIFICATE-----\nA\n-----END CERTIFICATE-----\n").unwrap();
        let c =
            stage_bundle("-----BEGIN CERTIFICATE-----\nB\n-----END CERTIFICATE-----\n").unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(a.join(BUNDLE_FILE).exists());
    }
}
