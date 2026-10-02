//! Credential substitution for machines.
//!
//! A machine's `[[network.credentials]]` bindings are persisted on its record
//! together with the placeholders minted for them. At start the host mounts
//! the machine's public CA into the guest, hands the workload the placeholders
//! in the bound environment variables, and — inside the boot process, next to
//! the network stack — runs the interceptor that swaps placeholders for real
//! values on the way out. See `smolvm-credentials` for the mechanism.

use crate::config::VmRecord;
use crate::data::storage::HostMount;
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use smolvm_credentials::{
    CredentialRequest, CredentialResolver, Interceptor, InterceptorConfig, MachineCa, ResolveError,
};
pub use smolvm_protocol::credentials::{
    CredentialBinding, CredentialPolicy, GUEST_CA_DIR, GUEST_TRUST_ENV,
};
use smolvm_protocol::SecretRef;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

/// Name of the directory inside a machine's data dir that holds its
/// credential CA.
pub const CA_DIR_NAME: &str = "credentials";

/// Per-machine directory holding the credential CA (`ca.key` + `guest/ca.pem`).
pub fn ca_dir(machine: &str) -> PathBuf {
    crate::agent::vm_data_dir(machine).join(CA_DIR_NAME)
}

/// Validate a policy against the machine's hostname allow-list and mint its
/// placeholders. Called once, at create.
pub fn prepare_policy(
    policy: &CredentialPolicy,
    allow_hosts: Option<&[String]>,
) -> Result<BTreeMap<String, String>> {
    policy
        .validate(allow_hosts)
        .map_err(|e| Error::config("credentials", e.to_string()))?;
    Ok(smolvm_credentials::generate_placeholders(policy))
}

/// Split a workload's secret references from its credential environment. A
/// variable bound to a credential never carries plaintext into the guest: its
/// reference feeds the interceptor, and the guest gets the placeholder plus
/// the variables pointing HTTP clients at the machine CA. Returns the refs to
/// resolve into the environment and the credential variables to add.
pub fn workload_env(
    policy: Option<&CredentialPolicy>,
    placeholders: &BTreeMap<String, String>,
    secret_refs: &BTreeMap<String, SecretRef>,
) -> (BTreeMap<String, SecretRef>, Vec<(String, String)>) {
    let Some(policy) = policy.filter(|p| !p.is_empty()) else {
        return (secret_refs.clone(), Vec::new());
    };
    let refs = secret_refs
        .iter()
        .filter(|(name, _)| {
            !policy
                .credentials
                .iter()
                .any(|b| &b.environment_variable == *name)
        })
        .map(|(name, r)| (name.clone(), r.clone()))
        .collect();
    let mut env: Vec<(String, String)> = policy.guest_env(placeholders).collect();
    env.extend(
        GUEST_TRUST_ENV
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string())),
    );
    // Git's credential helper returns the opaque placeholder as the HTTP
    // password. The interceptor recognizes its Basic header and inserts the
    // real value after the request leaves the guest. Reset any inherited
    // helper for this host so an unrelated helper cannot supply a PAT first.
    if policy.credentials.iter().any(|binding| {
        binding.environment_variable == "GITHUB_TOKEN"
            && binding
                .allowed_hosts
                .iter()
                .any(|host| host == "github.com")
    }) {
        env.extend([
            ("GIT_CONFIG_COUNT".into(), "2".into()),
            (
                "GIT_CONFIG_KEY_0".into(),
                "credential.https://github.com.helper".into(),
            ),
            ("GIT_CONFIG_VALUE_0".into(), String::new()),
            (
                "GIT_CONFIG_KEY_1".into(),
                "credential.https://github.com.helper".into(),
            ),
            (
                "GIT_CONFIG_VALUE_1".into(),
                "!f() { [ \"$1\" = get ] || exit 0; host=; protocol=; while IFS= read -r line; do case \"$line\" in host=*) host=${line#host=} ;; protocol=*) protocol=${line#protocol=} ;; esac; done; [ \"$host\" = github.com ] && [ \"$protocol\" = https ] && [ -n \"$GITHUB_TOKEN\" ] || exit 0; printf \"username=x-access-token\\npassword=%s\\n\" \"$GITHUB_TOKEN\"; }; f".into(),
            ),
        ]);
    }
    (refs, env)
}

/// Everything the boot process needs to run a machine's interceptor. Carried
/// in the boot config; holds references, never values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialLaunch {
    /// Machine name, passed to the resolver as the requesting identity.
    pub machine: String,
    /// Bindings to enforce.
    pub policy: CredentialPolicy,
    /// Binding name → placeholder, as persisted on the record.
    pub placeholders: BTreeMap<String, String>,
    /// Machine whose CA this lineage shares (the golden for a fork clone).
    pub ca_owner: String,
    /// Host directory written by [`MachineCa::save`].
    pub ca_dir: PathBuf,
    /// Binding name → where the host resolves its value. A binding whose bound
    /// variable has a `[secrets]` reference uses it; otherwise the host
    /// environment variable of the same name (the `dotenvx run -- smolvm …`
    /// path).
    pub sources: BTreeMap<String, SecretRef>,
    /// Values come only from [`supply_values`], never from this host's
    /// environment (bindings that arrived over the HTTP API).
    #[serde(default)]
    pub supplied_only: bool,
}

impl CredentialLaunch {
    /// Describe the launch for a record. `None` when the machine has no
    /// credential policy. Pure: the CA is created by [`Self::ensure_ca`].
    pub fn for_record(machine: &str, record: &VmRecord) -> Option<Self> {
        let mut launch = Self::from_parts(
            machine,
            record.credential_policy.as_ref()?,
            &record.credential_placeholders,
            &record.secret_refs,
            record.golden.as_deref(),
        )?;
        launch.supplied_only = record.credentials_supplied_by_api;
        Some(launch)
    }

    /// Describe a launch from its parts — the ephemeral `machine run` path has
    /// no record yet when it boots. `None` for an empty policy.
    pub fn from_parts(
        machine: &str,
        policy: &CredentialPolicy,
        placeholders: &BTreeMap<String, String>,
        secret_refs: &BTreeMap<String, SecretRef>,
        golden: Option<&str>,
    ) -> Option<Self> {
        if policy.is_empty() {
            return None;
        }
        // A fork clone restores guest state that already trusts its golden's
        // CA and holds the golden's placeholders, so the lineage shares one CA.
        // The clone still resolves under its own name: revoking one branch
        // never has to touch its siblings.
        let ca_owner = golden.unwrap_or(machine);
        let ca_dir = ca_dir(ca_owner);
        let sources = policy
            .credentials
            .iter()
            .map(|b| {
                let source = secret_refs
                    .get(&b.environment_variable)
                    .cloned()
                    .unwrap_or_else(|| crate::secrets::env_ref(b.environment_variable.clone()));
                (b.name.clone(), source)
            })
            .collect();
        Some(Self {
            machine: machine.to_string(),
            policy: policy.clone(),
            placeholders: placeholders.clone(),
            ca_owner: ca_owner.to_string(),
            ca_dir,
            sources,
            supplied_only: false,
        })
    }

    /// Create the lineage's CA on first use. Called by the launcher before the
    /// guest CA directory is mounted.
    pub fn ensure_ca(&self) -> Result<()> {
        if MachineCa::exists(&self.ca_dir) {
            return Ok(());
        }
        let hosts: Vec<String> = self
            .policy
            .credentials
            .iter()
            .flat_map(|binding| binding.allowed_hosts.iter().cloned())
            .collect();
        MachineCa::generate(&self.ca_owner, &hosts)
            .and_then(|ca| ca.save(&self.ca_dir))
            .map_err(|e| Error::config("credentials", format!("machine CA: {e:#}")))
    }

    /// Read-only mount exposing only the public CA to the guest.
    pub fn guest_ca_mount(&self) -> HostMount {
        HostMount {
            source: MachineCa::guest_dir(&self.ca_dir),
            target: PathBuf::from(GUEST_CA_DIR),
            read_only: true,
            staged: false,
        }
    }

    /// Start the interceptor for this machine. The returned handle must live
    /// as long as the VM; dropping it stops substitution.
    pub fn start_interceptor(&self) -> Result<Interceptor> {
        let ca = MachineCa::load(&self.ca_dir, &self.ca_owner)
            .map_err(|e| Error::config("credentials", format!("load machine CA: {e:#}")))?;
        let resolver: Arc<dyn CredentialResolver> = if self.supplied_only {
            #[cfg(unix)]
            {
                Arc::new(SuppliedResolver)
            }
            #[cfg(not(unix))]
            {
                Arc::new(SecretRefResolver(self.sources.clone()))
            }
        } else {
            Arc::new(SecretRefResolver(self.sources.clone()))
        };
        Interceptor::spawn(
            InterceptorConfig {
                machine: self.machine.clone(),
                policy: self.policy.clone(),
                placeholders: self.placeholders.clone(),
                ca,
                upstream_roots_pem: Vec::new(),
            },
            resolver,
        )
        .map_err(|e| Error::config("credentials", format!("start interceptor: {e:#}")))
    }
}

/// Values handed to the API process for its machines' bindings, by machine name
/// then binding name. Held in memory only, outside the guest and checkpoint.
type SuppliedValues = BTreeMap<String, zeroize::Zeroizing<String>>;

static SUPPLIED: std::sync::LazyLock<std::sync::Mutex<BTreeMap<String, SuppliedValues>>> =
    std::sync::LazyLock::new(Default::default);

/// Hold `values` (binding name → value) for `machine`'s next boots, replacing
/// any held before.
pub fn supply_values(machine: &str, values: SuppliedValues) -> Result<()> {
    #[cfg(unix)]
    if !values.is_empty() {
        ensure_resolver_server(machine)?;
    }
    let mut held = SUPPLIED.lock().unwrap_or_else(|e| e.into_inner());
    if values.is_empty() {
        held.remove(machine);
    } else {
        held.insert(machine.to_string(), values);
    }
    Ok(())
}

/// Drop whatever was supplied for `machine`.
pub fn forget_values(machine: &str) {
    let _ = supply_values(machine, BTreeMap::new());
    #[cfg(unix)]
    {
        if let Some(handle) = RESOLVERS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(machine)
        {
            handle.abort();
        }
        let _ = std::fs::remove_file(resolver_socket_path(machine));
    }
}

/// One host-only resolver socket per machine, inside that machine's data dir.
/// This matters under Landlock: a confined VM host process can reach its own
/// socket, but not another VM's socket and therefore not its credentials.
#[cfg(unix)]
fn resolver_socket_path(machine: &str) -> PathBuf {
    crate::agent::vm_data_dir(machine).join("credential-resolver.sock")
}

#[cfg(unix)]
static RESOLVERS: std::sync::LazyLock<
    std::sync::Mutex<BTreeMap<String, tokio::task::JoinHandle<()>>>,
> = std::sync::LazyLock::new(Default::default);

#[cfg(unix)]
fn ensure_resolver_server(machine: &str) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::os::unix::net::UnixStream;
    let mut resolvers = RESOLVERS.lock().unwrap_or_else(|e| e.into_inner());
    if resolvers.contains_key(machine) {
        return Ok(());
    }
    let path = resolver_socket_path(machine);
    std::fs::create_dir_all(path.parent().expect("socket has a parent"))
        .map_err(|e| Error::config("credentials", format!("create resolver directory: {e}")))?;
    if UnixStream::connect(&path).is_ok() {
        return Err(Error::config(
            "credentials",
            "another resolver owns this machine socket",
        ));
    }
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(Error::config(
                "credentials",
                format!("remove stale resolver socket: {error}"),
            ))
        }
    }
    let listener = tokio::net::UnixListener::bind(&path)
        .map_err(|e| Error::config("credentials", format!("bind resolver socket: {e}")))?;
    // The per-VM data directory is chowned to a dedicated UID when a root
    // node starts the VM. On an API restart the new socket is created by root
    // again, so give it back to that VM's UID before serving requests.
    if unsafe { libc::geteuid() } == 0 {
        let owner = std::fs::metadata(path.parent().expect("socket has a parent"))
            .map_err(|e| Error::config("credentials", format!("stat resolver directory: {e}")))?;
        let cpath = std::ffi::CString::new(path.as_os_str().as_bytes())
            .map_err(|e| Error::config("credentials", format!("invalid resolver path: {e}")))?;
        if unsafe { libc::lchown(cpath.as_ptr(), owner.uid(), owner.gid()) } != 0 {
            return Err(Error::config(
                "credentials",
                format!("chown resolver socket: {}", std::io::Error::last_os_error()),
            ));
        }
    }
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| Error::config("credentials", format!("protect resolver socket: {e}")))?;
    let machine_name = machine.to_string();
    let handle = tokio::runtime::Handle::try_current()
        .map_err(|e| Error::config("credentials", format!("resolver runtime unavailable: {e}")))?
        .spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let machine = machine_name.clone();
                tokio::spawn(async move {
                    if let Err(error) = tokio::time::timeout(
                        std::time::Duration::from_secs(3),
                        serve_resolver_request(&machine, &mut stream),
                    )
                    .await
                    {
                        tracing::debug!(%error, "credential resolver request timed out");
                    }
                });
            }
        });
    resolvers.insert(machine.to_string(), handle);
    Ok(())
}

#[cfg(unix)]
async fn serve_resolver_request(
    machine: &str,
    stream: &mut tokio::net::UnixStream,
) -> std::io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut size = [0u8; 4];
    stream.read_exact(&mut size).await?;
    let size = u32::from_be_bytes(size) as usize;
    if size == 0 || size > 4096 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid request size",
        ));
    }
    let mut bytes = vec![0u8; size];
    stream.read_exact(&mut bytes).await?;
    let binding: String = serde_json::from_slice(&bytes)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let value = SUPPLIED
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(machine)
        .and_then(|bindings| bindings.get(&binding))
        .cloned();
    let Some(value) = value else {
        stream.write_all(&0u32.to_be_bytes()).await?;
        return Ok(());
    };
    let bytes = zeroize::Zeroizing::new(value.as_bytes().to_vec());
    let size = u32::try_from(bytes.len()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "credential too large")
    })?;
    stream.write_all(&size.to_be_bytes()).await?;
    stream.write_all(&bytes).await
}

#[cfg(unix)]
struct SuppliedResolver;

#[cfg(unix)]
impl CredentialResolver for SuppliedResolver {
    fn resolve(
        &self,
        request: &CredentialRequest,
    ) -> std::result::Result<zeroize::Zeroizing<String>, ResolveError> {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixStream;
        let mut stream =
            UnixStream::connect(resolver_socket_path(&request.machine)).map_err(|_| {
                ResolveError::Unavailable("node credential resolver unavailable".into())
            })?;
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(3)))
            .ok();
        stream
            .set_write_timeout(Some(std::time::Duration::from_secs(3)))
            .ok();
        let request = serde_json::to_vec(&request.binding)
            .map_err(|_| ResolveError::Unavailable("invalid credential request".into()))?;
        let size = u32::try_from(request.len())
            .map_err(|_| ResolveError::Unavailable("credential request too large".into()))?;
        stream
            .write_all(&size.to_be_bytes())
            .and_then(|_| stream.write_all(&request))
            .map_err(|_| {
                ResolveError::Unavailable("node credential resolver unavailable".into())
            })?;
        let mut size = [0u8; 4];
        stream.read_exact(&mut size).map_err(|_| {
            ResolveError::Unavailable("node credential resolver unavailable".into())
        })?;
        let size = u32::from_be_bytes(size) as usize;
        if size == 0 || size > 64 * 1024 {
            return Err(ResolveError::Unavailable("credential unavailable".into()));
        }
        let mut bytes = zeroize::Zeroizing::new(vec![0u8; size]);
        stream.read_exact(&mut bytes).map_err(|_| {
            ResolveError::Unavailable("node credential resolver unavailable".into())
        })?;
        String::from_utf8(std::mem::take(&mut *bytes))
            .map(zeroize::Zeroizing::new)
            .map_err(|_| ResolveError::Unavailable("invalid credential value".into()))
    }
}

/// Name of the variable carrying a supplied value into the boot process.
fn supplied_var(index: usize) -> String {
    format!("SMOLVM_CREDENTIAL_{index}")
}

impl CredentialLaunch {
    /// Point bindings at the values supplied for this machine, and return the
    /// environment the boot process needs for it: `Some(value)` to set,
    /// `None` to remove. A supplied value travels in a variable private to the
    /// boot process, so it never lands in the boot config on disk. A
    /// `supplied_only` binding with no value is pointed at a variable that is
    /// removed, so it resolves to nothing rather than to a host variable.
    pub fn child_env(&mut self) -> Vec<(String, Option<zeroize::Zeroizing<String>>)> {
        // On Unix the boot process asks the API process's node-local socket on
        // every request. No supplied value needs to enter its environment, and
        // PUT /credential-values changes a running VM immediately.
        #[cfg(unix)]
        if self.supplied_only {
            return Vec::new();
        }
        let held = SUPPLIED.lock().unwrap_or_else(|e| e.into_inner());
        let supplied = held.get(&self.machine);
        let mut env = Vec::new();
        for (index, binding) in self.policy.credentials.iter().enumerate() {
            let value = supplied
                .and_then(|values| values.get(&binding.name))
                .cloned();
            if value.is_none() && !self.supplied_only {
                continue;
            }
            let var = supplied_var(index);
            self.sources
                .insert(binding.name.clone(), crate::secrets::env_ref(var.clone()));
            env.push((var, value));
        }
        env
    }
}

/// Resolves each binding from its secret reference on every request, through
/// the same reader (and audit trail) as every other machine secret, so a
/// rotated file or variable takes effect on the next request.
struct SecretRefResolver(BTreeMap<String, SecretRef>);

impl CredentialResolver for SecretRefResolver {
    fn resolve(
        &self,
        request: &CredentialRequest,
    ) -> std::result::Result<zeroize::Zeroizing<String>, ResolveError> {
        let source = self.0.get(&request.binding).ok_or(ResolveError::Unknown)?;
        crate::secrets::resolve_secret_ref_classified(
            &request.binding,
            source,
            crate::secrets::ResolutionScope::RecordReplay,
        )
        .map_err(|failure| ResolveError::Unavailable(failure.as_str().to_string()))
    }
}

/// Parse a `--credential NAME=ENV_VAR@HOST[,HOST...]` flag.
pub fn parse_credential_flag(spec: &str) -> std::result::Result<CredentialBinding, String> {
    let usage = "expected NAME=ENV_VAR@HOST[,HOST...] (e.g. notion=NOTION_API_KEY@api.notion.com)";
    let (name, rest) = spec.split_once('=').ok_or(usage)?;
    let (env_var, hosts) = rest.split_once('@').ok_or(usage)?;
    let allowed_hosts: Vec<String> = hosts
        .split(',')
        .map(|h| h.trim().to_ascii_lowercase())
        .filter(|h| !h.is_empty())
        .collect();
    if name.is_empty() || env_var.is_empty() || allowed_hosts.is_empty() {
        return Err(usage.to_string());
    }
    Ok(CredentialBinding {
        name: name.trim().to_string(),
        environment_variable: env_var.trim().to_string(),
        allowed_hosts,
        injection_location: Default::default(),
        methods: smolvm_protocol::credentials::DEFAULT_METHODS
            .iter()
            .map(|m| m.to_string())
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_flag_parses_name_variable_and_hosts() {
        let b = parse_credential_flag("notion=NOTION_API_KEY@api.notion.com, Files.Notion.com")
            .unwrap();
        assert_eq!(b.name, "notion");
        assert_eq!(b.environment_variable, "NOTION_API_KEY");
        assert_eq!(b.allowed_hosts, vec!["api.notion.com", "files.notion.com"]);
        assert!(parse_credential_flag("notion=NOTION_API_KEY").is_err());
        assert!(parse_credential_flag("=X@h").is_err());
    }

    fn launch(machine: &str, supplied_only: bool) -> CredentialLaunch {
        let policy = CredentialPolicy {
            credentials: vec![
                parse_credential_flag("a=A_KEY@api.a.com").unwrap(),
                parse_credential_flag("b=B_KEY@api.b.com").unwrap(),
            ],
        };
        let mut launch = CredentialLaunch::from_parts(
            machine,
            &policy,
            &BTreeMap::new(),
            &BTreeMap::new(),
            None,
        )
        .unwrap();
        launch.supplied_only = supplied_only;
        launch
    }

    #[tokio::test]
    async fn supplied_values_reach_only_the_boot_process() {
        let machine = "cred-test-supplied";
        supply_values(
            machine,
            [(
                "a".to_string(),
                zeroize::Zeroizing::new("value-a".to_string()),
            )]
            .into(),
        )
        .unwrap();
        let mut l = launch(machine, false);
        let env = l.child_env();
        // The supplied binding moves to a private variable carrying its value.
        assert_eq!(env.len(), 1);
        assert_eq!(env[0].0, "SMOLVM_CREDENTIAL_0");
        assert_eq!(env[0].1.as_deref().map(String::as_str), Some("value-a"));
        assert_eq!(
            l.sources["a"].from_env.as_deref(),
            Some("SMOLVM_CREDENTIAL_0")
        );
        // An unsupplied binding of a local machine keeps its host variable.
        assert_eq!(l.sources["b"].from_env.as_deref(), Some("B_KEY"));
        // The launch, as written to the boot config, names but never holds it.
        assert!(!serde_json::to_string(&l).unwrap().contains("value-a"));
        forget_values(machine);
        assert!(launch(machine, false).child_env().is_empty());
    }

    #[test]
    fn api_bindings_never_fall_back_to_host_variables() {
        let machine = "cred-test-api";
        forget_values(machine);
        let mut l = launch(machine, true);
        let env = l.child_env();
        #[cfg(unix)]
        {
            assert!(env.is_empty());
            assert_eq!(l.sources["a"].from_env.as_deref(), Some("A_KEY"));
            assert_eq!(l.sources["b"].from_env.as_deref(), Some("B_KEY"));
            return;
        }
        #[cfg(not(unix))]
        {
            // Nothing supplied: both bindings point at variables that are removed.
            assert_eq!(env.len(), 2);
            assert!(env
                .iter()
                .all(|(var, value)| var.starts_with("SMOLVM_CREDENTIAL_") && value.is_none()));
            assert_eq!(
                l.sources["a"].from_env.as_deref(),
                Some("SMOLVM_CREDENTIAL_0")
            );
            assert_eq!(
                l.sources["b"].from_env.as_deref(),
                Some("SMOLVM_CREDENTIAL_1")
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn api_supplied_value_rotates_and_revokes_while_resolver_is_running() {
        let machine = "cred-test-live-rotation";
        let request = CredentialRequest {
            machine: machine.into(),
            binding: "github".into(),
            host: "github.com".into(),
            port: 443,
            method: "GET".into(),
            path: "/org/repo.git/info/refs".into(),
        };
        supply_values(
            machine,
            [("github".into(), zeroize::Zeroizing::new("old".into()))].into(),
        )
        .unwrap();
        let resolver = SuppliedResolver;
        assert_eq!(resolver.resolve(&request).unwrap().as_str(), "old");
        supply_values(
            machine,
            [("github".into(), zeroize::Zeroizing::new("new".into()))].into(),
        )
        .unwrap();
        assert_eq!(resolver.resolve(&request).unwrap().as_str(), "new");
        forget_values(machine);
        assert!(resolver.resolve(&request).is_err());
        supply_values(
            machine,
            [("github".into(), zeroize::Zeroizing::new("rebound".into()))].into(),
        )
        .unwrap();
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let socket = resolver_socket_path(machine);
        let metadata = std::fs::metadata(&socket).unwrap();
        let parent = std::fs::metadata(socket.parent().unwrap()).unwrap();
        assert_eq!(metadata.uid(), parent.uid());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(resolver.resolve(&request).unwrap().as_str(), "rebound");
        forget_values(machine);
    }

    #[test]
    fn bound_variables_get_placeholders_never_their_secret() {
        let policy = CredentialPolicy {
            credentials: vec![parse_credential_flag("n=N_KEY@api.notion.com").unwrap()],
        };
        let placeholders = prepare_policy(&policy, Some(&["notion.com".to_string()])).unwrap();
        let refs: BTreeMap<String, SecretRef> = [
            ("N_KEY".to_string(), crate::secrets::env_ref("HOST_N_KEY")),
            ("OTHER".to_string(), crate::secrets::env_ref("HOST_OTHER")),
        ]
        .into_iter()
        .collect();
        let (refs, env) = workload_env(Some(&policy), &placeholders, &refs);
        assert_eq!(refs.keys().collect::<Vec<_>>(), vec!["OTHER"]);
        assert_eq!(env[0], ("N_KEY".to_string(), placeholders["n"].clone()));
        assert!(env
            .iter()
            .any(|(k, v)| k == "SSL_CERT_FILE" && v == "/run/smolvm/ca-bundle.pem"));
        assert!(env.iter().all(|(_, v)| !v.contains("secret")));
        assert!(prepare_policy(&policy, Some(&["github.com".to_string()])).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn github_binding_installs_git_helper_that_returns_only_the_placeholder() {
        use std::io::Write;
        use std::process::{Command, Stdio};
        let policy = CredentialPolicy {
            credentials: vec![parse_credential_flag(
                "github=GITHUB_TOKEN@github.com,api.github.com",
            )
            .unwrap()],
        };
        let placeholders = prepare_policy(&policy, None).unwrap();
        let (_, env) = workload_env(Some(&policy), &placeholders, &BTreeMap::new());
        let mut child = Command::new("git")
            .args(["credential", "fill"])
            .envs(env)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("git is required for the credential helper test");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"protocol=https\nhost=github.com\n\n")
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success());
        let output = String::from_utf8(output.stdout).unwrap();
        assert!(output.contains("username=x-access-token"));
        assert!(output.contains(&format!("password={}", placeholders["github"])));
    }
}
