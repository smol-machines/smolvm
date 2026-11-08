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
use smolvm_credentials::intercept::InterceptorControl;
use smolvm_credentials::{
    CredentialRequest, CredentialResolver, Interceptor, InterceptorConfig, MachineCa, ResolveError,
};
pub use smolvm_protocol::credentials::{
    CredentialBinding, CredentialPolicy, GUEST_CA_DIR, GUEST_TRUST_ENV,
};
use smolvm_protocol::SecretRef;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Socket in a running machine's data directory that takes new values for its
/// bindings, so a rotated credential reaches a machine without a restart, and
/// new bindings, so a running machine gains or loses them. See
/// [`LiveCredentials`] for the protocol.
pub const CREDENTIALS_SOCKET: &str = "credentials.sock";

/// Host the CA of a credential lineage is constrained to while it has no
/// binding at all: a reserved name (RFC 2606) no real certificate is for.
const NO_CREDENTIAL_HOST: &str = "credentials.invalid";

/// Largest request the credentials socket reads: every binding's value is at
/// most a few KiB.
const MAX_CREDENTIALS_REQUEST_BYTES: u64 = 1024 * 1024;

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

/// Require every binding to name the variable its value is read from, for a
/// machine whose values come from this host (the CLI) rather than being
/// supplied by an embedder or API caller. A binding naming none could never be
/// resolved and would fail every request to its hosts.
pub fn require_host_sources(policy: &CredentialPolicy) -> Result<()> {
    match policy
        .credentials
        .iter()
        .find(|b| b.environment_variable.is_empty())
    {
        Some(binding) => Err(Error::config(
            "credentials",
            format!(
                "credential {:?} names no environment_variable to read its value from",
                binding.name
            ),
        )),
        None => Ok(()),
    }
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
    /// The launcher mounts the CA read-only at [`GUEST_CA_DIR`] as a boot
    /// device. False when the boot restores saved memory whose device set had
    /// no such mount (the machine gained its bindings after that boot): the
    /// guest then gets the CA from the host through its agent instead.
    #[serde(default = "default_true")]
    pub ca_boot_mount: bool,
}

fn default_true() -> bool {
    true
}

impl CredentialLaunch {
    /// Describe the launch for a record. `None` when the machine has no
    /// credential policy. Pure: the CA is created by [`Self::ensure_ca`].
    ///
    /// A machine whose bindings were all removed keeps an empty policy, and
    /// gets a launch: its CA device and interceptor stay, so a checkpoint
    /// taken while it had bindings still restores, and bindings added later
    /// reach it live.
    pub fn for_record(machine: &str, record: &VmRecord) -> Option<Self> {
        let mut launch = Self::describe(
            machine,
            record.credential_policy.as_ref()?,
            &record.credential_placeholders,
            &record.secret_refs,
            record.golden.as_deref(),
        );
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
        Some(Self::describe(
            machine,
            policy,
            placeholders,
            secret_refs,
            golden,
        ))
    }

    fn describe(
        machine: &str,
        policy: &CredentialPolicy,
        placeholders: &BTreeMap<String, String>,
        secret_refs: &BTreeMap<String, SecretRef>,
        golden: Option<&str>,
    ) -> Self {
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
        Self {
            machine: machine.to_string(),
            policy: policy.clone(),
            placeholders: placeholders.clone(),
            ca_owner: ca_owner.to_string(),
            ca_dir,
            sources,
            supplied_only: false,
            ca_boot_mount: true,
        }
    }

    /// Who this launch resolves for, and where its lineage's CA lives.
    pub fn identity(&self) -> CredentialIdentity {
        CredentialIdentity {
            machine: self.machine.clone(),
            ca_owner: self.ca_owner.clone(),
            ca_dir: self.ca_dir.clone(),
        }
    }

    /// Create the lineage's CA on first use, or widen it to every host the
    /// policy names. Returns whether the certificate changed. Called only in
    /// the boot process, which runs as the machine's own user and owns the
    /// directory: by the launcher before the CA is mounted, and when a
    /// running machine is handed new bindings.
    ///
    /// Widening keeps the key, so leaves stay valid for processes that loaded
    /// the earlier certificate, and never narrows: branches share the CA, and
    /// a host a sibling still uses must stay permitted.
    pub fn ensure_ca(&self) -> Result<bool> {
        ensure_lineage_ca(&self.identity(), &self.policy).map(|(_, changed)| changed)
    }

    /// SHA-256 (hex) of a CA certificate PEM, as
    /// [`VmRecord::credential_ca_trusted`] keeps it.
    pub fn ca_fingerprint(pem: &str) -> String {
        use sha2::Digest;
        hex::encode(sha2::Sha256::digest(pem.as_bytes()))
    }

    /// The CA certificate the guest trusts, read by the host without
    /// following links (see [`read_ca_certificate`]).
    pub fn ca_certificate_pem(&self) -> Result<String> {
        read_ca_certificate(&self.ca_dir)
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
    /// as long as the VM; dropping it stops substitution. With the machine's
    /// data directory, it also serves [`CREDENTIALS_SOCKET`] there.
    pub fn start_interceptor(&self, vm_dir: Option<&Path>) -> Result<Interceptor> {
        let (interceptor, live) = self.spawn_interceptor(self.sources.clone())?;
        if let Some(dir) = vm_dir {
            live.serve(dir);
        }
        Ok(interceptor)
    }

    /// Spawn the interceptor resolving through `sources`, and the live state
    /// its credentials socket controls.
    fn spawn_interceptor(
        &self,
        sources: BTreeMap<String, SecretRef>,
    ) -> Result<(Interceptor, Arc<LiveCredentials>)> {
        let ca = MachineCa::load(&self.ca_dir, &self.ca_owner)
            .map_err(|e| Error::config("credentials", format!("load machine CA: {e:#}")))?;
        let resolver = Arc::new(SecretRefResolver::new(sources));
        let interceptor = Interceptor::spawn(
            InterceptorConfig {
                machine: self.machine.clone(),
                policy: self.policy.clone(),
                placeholders: self.placeholders.clone(),
                ca,
                upstream_roots_pem: Vec::new(),
            },
            resolver.clone(),
        )
        .map_err(|e| Error::config("credentials", format!("start interceptor: {e:#}")))?;
        let live = Arc::new(LiveCredentials {
            identity: self.identity(),
            late: None,
            state: Mutex::new(LiveState {
                policy: self.policy.clone(),
                placeholders: self.placeholders.clone(),
                supplied_only: self.supplied_only,
                running: Some(Running {
                    control: interceptor.control(),
                    resolver,
                    _owned: None,
                }),
                previous: None,
            }),
        });
        Ok((interceptor, live))
    }
}

/// Who a running boot process enforces bindings for and where the CA of its
/// lineage lives. Fixed when it boots, from the machine's record; never taken
/// from a message on its socket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialIdentity {
    /// Machine name, the identity the resolver is asked for.
    pub machine: String,
    /// Machine whose CA the lineage shares (the golden for a branch).
    pub ca_owner: String,
    /// The CA's host directory.
    pub ca_dir: PathBuf,
}

impl CredentialIdentity {
    /// The identity of machine `name`, branched from `golden` if it was.
    pub fn of(name: &str, golden: Option<&str>) -> Self {
        let ca_owner = golden.unwrap_or(name);
        Self {
            machine: name.to_string(),
            ca_owner: ca_owner.to_string(),
            ca_dir: ca_dir(ca_owner),
        }
    }
}

/// Create the CA of `identity`'s lineage on first use, or widen it to every
/// host `policy` names; returns it and whether it changed. Writes only when
/// it must, so a confined boot whose CA already covers its hosts only reads.
fn ensure_lineage_ca(
    identity: &CredentialIdentity,
    policy: &CredentialPolicy,
) -> Result<(MachineCa, bool)> {
    fn fail(e: impl std::fmt::Display) -> Error {
        Error::config("credentials", format!("machine CA: {e:#}"))
    }
    let dir = &identity.ca_dir;
    let hosts: Vec<String> = policy
        .credentials
        .iter()
        .flat_map(|binding| binding.allowed_hosts.iter())
        .map(|host| smolvm_protocol::credentials::host_subtree(host).to_string())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let covering = |ca: MachineCa| -> Result<Option<MachineCa>> {
        Ok(match ca.widened(&hosts).map_err(fail)? {
            None => Some(ca),
            Some(_) => None,
        })
    };
    if MachineCa::exists(dir) {
        if let Some(ca) = covering(MachineCa::load(dir, &identity.ca_owner).map_err(fail)?)? {
            return Ok((ca, false));
        }
    }
    std::fs::create_dir_all(dir).map_err(fail)?;
    // Branches of one lineage may widen the shared CA at once.
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(dir.join("ca.lock"))
        .map_err(fail)?;
    crate::agent::fork::lock_file_exclusive(&lock).map_err(fail)?;
    if !MachineCa::exists(dir) {
        let permitted = if hosts.is_empty() {
            vec![NO_CREDENTIAL_HOST.to_string()]
        } else {
            hosts.clone()
        };
        let ca = MachineCa::generate(&identity.ca_owner, &permitted).map_err(fail)?;
        ca.save(dir).map_err(fail)?;
        return Ok((ca, true));
    }
    let ca = MachineCa::load(dir, &identity.ca_owner).map_err(fail)?;
    match ca.widened(&hosts).map_err(fail)? {
        Some(wider) => {
            wider.save(dir).map_err(fail)?;
            tracing::info!(machine = %identity.machine, ca_owner = %identity.ca_owner, "credential CA widened to new hosts");
            Ok((wider, true))
        }
        None => Ok((ca, false)),
    }
}

/// Read the public CA certificate of a lineage from the host, for a process
/// that may run as another user than the directory's owner (root `serve`
/// beside a machine running under its own uid).
///
/// Each component below the machine's data directory is opened without
/// following links and must be a directory or a regular file, so a machine
/// that swapped one for a link cannot make the reader open something else;
/// and only the first certificate in the file is returned, re-encoded, so
/// nothing but a certificate ever reaches the guest it is handed to.
pub fn read_ca_certificate(ca_dir: &Path) -> Result<String> {
    let fail = |reason: String| Error::config("credentials", format!("read machine CA: {reason}"));
    let bytes = read_without_links(ca_dir, &[smolvm_credentials::ca::GUEST_SUBDIR, "ca.pem"])
        .map_err(|e| fail(e.to_string()))?;
    let der = rustls_pemfile::certs(&mut bytes.as_slice())
        .next()
        .ok_or_else(|| fail("no certificate".into()))?
        .map_err(|e| fail(e.to_string()))?;
    Ok(pem_certificate(&der))
}

/// PEM text for one DER certificate.
fn pem_certificate(der: &[u8]) -> String {
    use base64::Engine as _;
    let body = base64::engine::general_purpose::STANDARD.encode(der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in body.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}

/// Read `base/<components…>`: `base` itself and every component below it
/// opened without following a link, each directory with `O_DIRECTORY` and the
/// file required to be regular.
#[cfg(unix)]
fn read_without_links(base: &Path, components: &[&str]) -> std::io::Result<Vec<u8>> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    let open_at = |dir: Option<&OwnedFd>, name: &std::ffi::OsStr, flags: i32| {
        let name = std::ffi::CString::new(name.as_bytes())
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        let at = dir.map_or(libc::AT_FDCWD, |d| d.as_raw_fd());
        // SAFETY: a NUL-terminated path and a live directory descriptor.
        let fd = unsafe {
            libc::openat(
                at,
                name.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: openat returned a descriptor this function now owns.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    };
    let mut dir = open_at(None, base.as_os_str(), libc::O_RDONLY | libc::O_DIRECTORY)?;
    let (file, dirs) = components
        .split_last()
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    for name in dirs {
        dir = open_at(
            Some(&dir),
            std::ffi::OsStr::new(name),
            libc::O_RDONLY | libc::O_DIRECTORY,
        )?;
    }
    let file = std::fs::File::from(open_at(
        Some(&dir),
        std::ffi::OsStr::new(file),
        libc::O_RDONLY | libc::O_NONBLOCK,
    )?);
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other("not a regular file"));
    }
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut std::io::Read::take(&file, 64 * 1024), &mut bytes)?;
    Ok(bytes)
}

#[cfg(not(unix))]
fn read_without_links(base: &Path, components: &[&str]) -> std::io::Result<Vec<u8>> {
    let mut path = base.to_path_buf();
    for name in components {
        path.push(name);
        if std::fs::symlink_metadata(&path)?.file_type().is_symlink() {
            return Err(std::io::Error::other("is a link"));
        }
    }
    std::fs::read(path)
}

/// Serve [`CREDENTIALS_SOCKET`] in `vm_dir` for a machine that booted without
/// bindings on a network whose HTTPS flows can be redirected after boot: the
/// first bindings sent start the interceptor and publish it in `slot`.
pub fn serve_without_bindings(
    vm_dir: &Path,
    identity: CredentialIdentity,
    slot: smolvm_network::LateHttpsIntercept,
) {
    Arc::new(LiveCredentials {
        identity,
        late: Some(slot),
        state: Mutex::new(LiveState {
            policy: CredentialPolicy::default(),
            placeholders: BTreeMap::new(),
            supplied_only: false,
            running: None,
            previous: None,
        }),
    })
    .serve(vm_dir);
}

/// Why replacing a machine's bindings failed.
#[derive(Debug)]
pub enum BindingsError {
    /// The bindings are invalid for this machine, as create would refuse them.
    Invalid(Error),
    /// The machine is in a state, or runs in a way, that cannot take them now.
    Conflict(Error),
    /// Anything else (the database, the machine vanishing).
    Failed(Error),
}

impl From<BindingsError> for Error {
    fn from(error: BindingsError) -> Self {
        match error {
            BindingsError::Invalid(e) | BindingsError::Conflict(e) | BindingsError::Failed(e) => e,
        }
    }
}

impl std::fmt::Display for BindingsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BindingsError::Invalid(e) | BindingsError::Conflict(e) | BindingsError::Failed(e) => {
                e.fmt(f)
            }
        }
    }
}

/// Replace machine `name`'s credential bindings with `policy`, exactly: the
/// shared core of `PUT /machines/{name}/credentials`, `machine update
/// --credential` and the embedded `set_credential_bindings`.
///
/// Validated as create validates (see
/// [`VmRecord::with_credential_bindings`]), stored in the record so every
/// later start, resume, restore and branch uses them, and, on a running
/// machine, applied at once (see [`apply_live_bindings`]). A created,
/// stopped, failed or paused machine takes them at its next boot. Values
/// held for removed bindings are dropped. Returns the stored record.
pub fn set_bindings(
    db: &crate::db::SmolvmDb,
    name: &str,
    policy: CredentialPolicy,
    caller: crate::machine_spec::Caller,
) -> std::result::Result<VmRecord, BindingsError> {
    use crate::config::RecordState;
    let read = || {
        db.get_vm(name)
            .map_err(BindingsError::Failed)?
            .ok_or_else(|| BindingsError::Failed(Error::vm_not_found(name)))
    };
    let mut record = read()?;
    // Changes to a running machine are serialized across processes, so the
    // boot process and the record never see two of them interleaved.
    let _lock = if record.actual_state() == RecordState::Running {
        let lock = lock_bindings(name).map_err(BindingsError::Failed)?;
        record = read()?;
        Some(lock)
    } else {
        None
    };
    let running = match record.actual_state() {
        RecordState::Running => true,
        RecordState::Created | RecordState::Stopped | RecordState::Failed | RecordState::Paused => {
            false
        }
        other => {
            return Err(BindingsError::Conflict(Error::InvalidState {
                expected: "created, stopped, paused or running".into(),
                actual: format!("{other:?}"),
            }))
        }
    };
    let next = record
        .with_credential_bindings(policy, caller)
        .map_err(BindingsError::Invalid)?;
    let mut next = next;
    if running {
        if let Some(trusted) = apply_live_bindings(name, &record, &next)? {
            next.credential_ca_trusted = Some(trusted);
        }
    }
    let saved = db.update_vm(name, |r| r.take_credential_bindings(&next));
    match saved {
        Ok(Some(saved)) => {
            retain_values(
                name,
                saved
                    .credential_policy
                    .as_ref()
                    .unwrap_or(&CredentialPolicy::default()),
            );
            Ok(saved)
        }
        failed => {
            // The record keeps the old bindings, so the running machine must too.
            if running {
                roll_back_live_bindings(name);
            }
            Err(BindingsError::Failed(match failed {
                Err(e) => e,
                _ => Error::vm_not_found(name),
            }))
        }
    }
}

/// Serialize binding changes to one machine across processes.
fn lock_bindings(name: &str) -> Result<std::fs::File> {
    let dir = crate::agent::vm_data_dir(name);
    std::fs::create_dir_all(&dir)
        .map_err(|e| Error::agent("credentials update lock", e.to_string()))?;
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(dir.join("credentials-update.lock"))
        .map_err(|e| Error::agent("credentials update lock", e.to_string()))?;
    crate::agent::fork::lock_file_exclusive(&file)
        .map_err(|e| Error::agent("credentials update lock", e.to_string()))?;
    Ok(file)
}

/// Apply `next`'s bindings to running machine `name`, whose record is
/// `before`, and return the fingerprint of the CA its guest trusts afterwards.
///
/// The boot process, which owns the CA directory, creates or widens the CA
/// to cover every host, swaps policy, placeholders and resolver state in one
/// step (starting the interceptor when the machine booted without bindings),
/// and answers with the CA certificate. When the guest was last given another
/// certificate (by the record, not by what is on disk: a sibling branch may
/// have widened the shared CA, or an earlier attempt failed), the guest agent
/// installs it. A guest that cannot take it, or an install that fails, rolls
/// the boot process back to exactly what it had.
pub fn apply_live_bindings(
    name: &str,
    before: &VmRecord,
    next: &VmRecord,
) -> std::result::Result<Option<String>, BindingsError> {
    before
        .check_live_credentials(next)
        .map_err(BindingsError::Conflict)?;
    let Some(policy) = next.credential_policy.clone() else {
        return Ok(None);
    };
    let capable =
        crate::agent::supports_live_credential_trust(name).map_err(BindingsError::Conflict)?;
    let message = BindingsMessage {
        policy,
        placeholders: next.credential_placeholders.clone(),
        supplied_only: next.credentials_supplied_by_api,
    };
    let reply = crate::agent::apply_live_credential_policy(name, &message)
        .map_err(BindingsError::Conflict)?;
    let pem = rustls_pemfile::certs(&mut reply.ca_pem.as_bytes())
        .next()
        .and_then(|der| der.ok())
        .map(|der| pem_certificate(&der));
    let Some(pem) = pem else {
        roll_back_live_bindings(name);
        return Err(BindingsError::Failed(Error::config(
            "credentials",
            "the boot process answered without a CA certificate",
        )));
    };
    let fingerprint = CredentialLaunch::ca_fingerprint(&pem);
    if !guest_needs_ca(before, &pem) {
        return Ok(Some(fingerprint));
    }
    let installed = if capable {
        crate::agent::install_live_credential_trust(name, &pem)
    } else {
        Err(Error::config(
            "credentials",
            format!(
                "machine '{name}' runs a guest agent that cannot take a credential CA while it \
                 runs, which these bindings need; restart it to apply them"
            ),
        ))
    };
    match installed {
        Ok(()) => Ok(Some(fingerprint)),
        Err(error) => {
            roll_back_live_bindings(name);
            Err(BindingsError::Conflict(error))
        }
    }
}

/// Whether a running machine's guest must be handed CA certificate `pem`:
/// judged by the certificate its record says the guest was last given, never
/// by what is on disk, which a sibling branch may have widened or an earlier,
/// rolled-back attempt may have changed without the guest ever seeing it.
fn guest_needs_ca(before: &VmRecord, pem: &str) -> bool {
    before.credential_ca_trusted.as_deref() != Some(CredentialLaunch::ca_fingerprint(pem).as_str())
}

/// Return running machine `name`'s boot process to the bindings, sources and
/// values it had before the last bindings it was sent. Best effort: the error
/// that caused it is what the caller reports.
fn roll_back_live_bindings(name: &str) {
    if let Err(error) = crate::agent::roll_back_live_credential_policy(name) {
        tracing::warn!(machine = name, %error, "could not restore the previous credential bindings");
    }
}

/// Values handed to this process for its machines' bindings, by machine name
/// then binding name. Held in memory only: never written to a record, a boot
/// config or a checkpoint, and gone when the process exits, so whoever supplied
/// them supplies them again before the next boot.
type SuppliedValues = BTreeMap<String, zeroize::Zeroizing<String>>;

static SUPPLIED: std::sync::LazyLock<std::sync::Mutex<BTreeMap<String, SuppliedValues>>> =
    std::sync::LazyLock::new(Default::default);

/// Hold `values` (binding name → value) for `machine`'s next boots, replacing
/// any held before.
pub fn supply_values(machine: &str, values: SuppliedValues) {
    let mut held = SUPPLIED.lock().unwrap_or_else(|e| e.into_inner());
    if values.is_empty() {
        held.remove(machine);
    } else {
        held.insert(machine.to_string(), values);
    }
}

/// Drop whatever was supplied for `machine`.
pub fn forget_values(machine: &str) {
    supply_values(machine, BTreeMap::new());
}

/// Drop the values supplied for `machine`'s bindings other than `bindings`,
/// once those are all it has.
pub fn retain_values(machine: &str, bindings: &CredentialPolicy) {
    let mut held = SUPPLIED.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(values) = held.get_mut(machine) {
        values.retain(|name, _| bindings.binding(name).is_some());
        if values.is_empty() {
            held.remove(machine);
        }
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
        let held = SUPPLIED.lock().unwrap_or_else(|e| e.into_inner());
        // A branch uses its golden's values unless some were supplied for the
        // branch itself: it restores guest state that already relies on them,
        // and its own name is new to whoever supplied the golden's.
        let supplied = held.get(&self.machine).or_else(|| held.get(&self.ca_owner));
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

/// The bindings a host hands a running boot process: everything else (who
/// it resolves for, where the CA lives, where values come from) the boot
/// process knows itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindingsMessage {
    /// The bindings, exactly.
    pub policy: CredentialPolicy,
    /// Binding name → placeholder, as the record holds them.
    pub placeholders: BTreeMap<String, String>,
    /// Values come only from what is sent. Once set for a running machine it
    /// stays set until a rollback undoes the message that set it.
    #[serde(default)]
    pub supplied_only: bool,
}

/// What the boot process answers to a [`BindingsMessage`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BindingsReply {
    /// The lineage's CA certificate, now covering every bound host.
    pub ca_pem: String,
}

/// The credentials a running boot process enforces, as its
/// [`CREDENTIALS_SOCKET`] changes them.
///
/// The socket is private to the machine's user (mode `0600`). Each
/// connection sends one JSON object and reads back `ok` (followed, for
/// `bindings`, by one line of JSON) or `error: <reason>`:
///
/// - `{"values":{"<binding>":"<value>",…}}` replaces the values the machine
///   resolves for the bindings named, from its next request on. A name that is
///   not a current binding refuses the whole message.
/// - `{"bindings":{"policy":{…},"placeholders":{…},"supplied_only":bool}}`
///   replaces the bindings. The boot process creates or widens the CA itself
///   and answers `ok` plus `{"ca_pem":"…"}`. A binding unchanged in every
///   respect (the binding, its placeholder, and whether values are supplied)
///   keeps its source and value; any other binding starts with none: it
///   resolves from the boot process's own variable of its name on a machine
///   whose values come from this host, and on a supplied machine only from a
///   value sent for it. Policy, placeholders and resolver state change in one
///   step. On a machine that booted without bindings, the first ones start
///   the interceptor.
/// - `{"rollback":true}` restores exactly what the last `bindings` replaced:
///   policy, placeholders, sources, values, whether values are supplied, and
///   whether an interceptor ran at all.
pub struct LiveCredentials {
    identity: CredentialIdentity,
    /// Where an interceptor started after boot is published.
    late: Option<smolvm_network::LateHttpsIntercept>,
    state: Mutex<LiveState>,
}

struct LiveState {
    policy: CredentialPolicy,
    placeholders: BTreeMap<String, String>,
    supplied_only: bool,
    /// The interceptor, once there is one.
    running: Option<Running>,
    /// What the last `bindings` message replaced.
    previous: Option<Previous>,
}

struct Previous {
    policy: CredentialPolicy,
    placeholders: BTreeMap<String, String>,
    supplied_only: bool,
    /// The resolver's state, or `None` when no interceptor ran before.
    resolver: Option<ResolverState>,
}

struct Running {
    control: InterceptorControl,
    resolver: Arc<SecretRefResolver>,
    /// An interceptor started after boot, kept alive here.
    _owned: Option<Interceptor>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LiveRequest {
    #[serde(default)]
    values: Option<BTreeMap<String, String>>,
    #[serde(default)]
    bindings: Option<BindingsMessage>,
    #[serde(default)]
    rollback: Option<bool>,
}

impl LiveCredentials {
    fn serve(self: Arc<Self>, vm_dir: &Path) {
        let path = vm_dir.join(CREDENTIALS_SOCKET);
        let _ = std::fs::remove_file(&path);
        crate::network::launch::serve_control_socket_with_reply(
            path,
            "credentials-control",
            MAX_CREDENTIALS_REQUEST_BYTES,
            move |request| self.handle(request),
        );
    }

    fn handle(&self, request: &str) -> std::result::Result<String, String> {
        let request: LiveRequest =
            serde_json::from_str(request).map_err(|_| "malformed request".to_string())?;
        match (request.values, request.bindings, request.rollback) {
            (Some(values), None, None) => self.replace_values(values).map(|()| String::new()),
            (None, Some(bindings), None) => self
                .replace_bindings(bindings)
                .and_then(|reply| serde_json::to_string(&reply).map_err(|e| e.to_string())),
            (None, None, Some(true)) => self.roll_back().map(|()| String::new()),
            _ => Err("send exactly one of `values`, `bindings` and `rollback`".to_string()),
        }
    }

    fn replace_values(&self, values: BTreeMap<String, String>) -> std::result::Result<(), String> {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(unknown) = values.keys().find(|k| state.policy.binding(k).is_none()) {
            return Err(format!("no credential binding '{unknown}'"));
        }
        let Some(running) = &state.running else {
            // No binding at all, so `values` is empty.
            return Ok(());
        };
        let names: Vec<String> = values.keys().cloned().collect();
        running.resolver.lock().live.extend(
            values
                .into_iter()
                .map(|(name, value)| (name, zeroize::Zeroizing::new(value))),
        );
        tracing::info!(bindings = ?names, "credential values replaced");
        Ok(())
    }

    fn replace_bindings(
        &self,
        message: BindingsMessage,
    ) -> std::result::Result<BindingsReply, String> {
        message.policy.validate(None).map_err(|e| e.to_string())?;
        if let Some(missing) = message
            .policy
            .credentials
            .iter()
            .find(|b| !message.placeholders.contains_key(&b.name))
        {
            return Err(format!(
                "credential binding '{}' has no placeholder",
                missing.name
            ));
        }
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let (ca, _) =
            ensure_lineage_ca(&self.identity, &message.policy).map_err(|e| e.to_string())?;
        let reply = BindingsReply {
            ca_pem: ca.certificate_pem().to_string(),
        };
        let supplied_only = state.supplied_only || message.supplied_only;
        let unchanged = |binding: &CredentialBinding| {
            state.policy.binding(&binding.name) == Some(binding)
                && state.placeholders.get(&binding.name) == message.placeholders.get(&binding.name)
                && state.supplied_only == supplied_only
        };
        let kept: Vec<&str> = message
            .policy
            .credentials
            .iter()
            .filter(|b| unchanged(b))
            .map(|b| b.name.as_str())
            .collect();
        let fresh_source = |binding: &CredentialBinding| {
            (!supplied_only && !binding.environment_variable.is_empty())
                .then(|| crate::secrets::env_ref(binding.environment_variable.clone()))
        };
        match &state.running {
            Some(running) => {
                let mut resolver = running.resolver.lock();
                let previous_resolver = resolver.clone();
                let mut next = ResolverState::default();
                for binding in &message.policy.credentials {
                    let name = &binding.name;
                    if kept.contains(&name.as_str()) {
                        if let Some(source) = resolver.sources.get(name) {
                            next.sources.insert(name.clone(), source.clone());
                        }
                        if let Some(value) = resolver.live.get(name) {
                            next.live.insert(name.clone(), value.clone());
                        }
                    } else if let Some(source) = fresh_source(binding) {
                        next.sources.insert(name.clone(), source);
                    }
                }
                // Under the resolver's lock: no value is resolved between the
                // new bindings and their sources and values.
                running.control.replace_ca(ca);
                running
                    .control
                    .replace_bindings(message.policy.clone(), &message.placeholders);
                *resolver = next;
                drop(resolver);
                state.previous = Some(Previous {
                    policy: state.policy.clone(),
                    placeholders: state.placeholders.clone(),
                    supplied_only: state.supplied_only,
                    resolver: Some(previous_resolver),
                });
            }
            None => {
                let Some(slot) = self.late else {
                    return Err("this machine's network cannot route HTTPS through an \
                                interceptor started after boot; restart it"
                        .to_string());
                };
                let sources = message
                    .policy
                    .credentials
                    .iter()
                    .filter_map(|b| fresh_source(b).map(|source| (b.name.clone(), source)))
                    .collect();
                let resolver = Arc::new(SecretRefResolver::new(sources));
                let interceptor = Interceptor::spawn(
                    InterceptorConfig {
                        machine: self.identity.machine.clone(),
                        policy: message.policy.clone(),
                        placeholders: message.placeholders.clone(),
                        ca,
                        upstream_roots_pem: Vec::new(),
                    },
                    resolver.clone(),
                )
                .map_err(|e| format!("start interceptor: {e:#}"))?;
                slot.set(interceptor.endpoint());
                state.running = Some(Running {
                    control: interceptor.control(),
                    resolver,
                    _owned: Some(interceptor),
                });
                state.previous = Some(Previous {
                    policy: state.policy.clone(),
                    placeholders: state.placeholders.clone(),
                    supplied_only: state.supplied_only,
                    resolver: None,
                });
                tracing::info!("credential interceptor started on a running machine");
            }
        }
        let names: Vec<&str> = message
            .policy
            .credentials
            .iter()
            .map(|b| b.name.as_str())
            .collect();
        tracing::info!(bindings = ?names, kept = ?kept, "credential bindings replaced");
        state.policy = message.policy;
        state.placeholders = message.placeholders;
        state.supplied_only = supplied_only;
        Ok(reply)
    }

    fn roll_back(&self) -> std::result::Result<(), String> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let Some(previous) = state.previous.take() else {
            return Err("there are no replaced bindings to restore".to_string());
        };
        match previous.resolver {
            Some(resolver_state) => {
                if let Some(running) = &state.running {
                    let mut resolver = running.resolver.lock();
                    running
                        .control
                        .replace_bindings(previous.policy.clone(), &previous.placeholders);
                    *resolver = resolver_state;
                }
            }
            None => {
                // No interceptor ran before: stop the one started since.
                if let Some(slot) = self.late {
                    slot.clear();
                }
                state.running = None;
            }
        }
        state.policy = previous.policy;
        state.placeholders = previous.placeholders;
        state.supplied_only = previous.supplied_only;
        tracing::info!("credential bindings restored");
        Ok(())
    }
}

/// Where a running machine resolves each binding from: its source, and a
/// value handed to it through [`CREDENTIALS_SOCKET`], which wins.
#[derive(Clone, Default)]
struct ResolverState {
    sources: BTreeMap<String, SecretRef>,
    live: BTreeMap<String, zeroize::Zeroizing<String>>,
}

/// Resolves each binding from its secret reference on every request, through
/// the same reader (and audit trail) as every other machine secret, so a
/// rotated file or variable takes effect on the next request. A value handed
/// to the running machine through [`CREDENTIALS_SOCKET`] takes precedence.
struct SecretRefResolver {
    state: Mutex<ResolverState>,
}

impl SecretRefResolver {
    fn new(sources: BTreeMap<String, SecretRef>) -> Self {
        Self {
            state: Mutex::new(ResolverState {
                sources,
                live: BTreeMap::new(),
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ResolverState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl CredentialResolver for SecretRefResolver {
    fn resolve(
        &self,
        request: &CredentialRequest,
    ) -> std::result::Result<zeroize::Zeroizing<String>, ResolveError> {
        // Held while reading the source too, so a binding swap (made under
        // this lock) is never seen half-done.
        let state = self.lock();
        if let Some(value) = state.live.get(&request.binding) {
            return Ok(value.clone());
        }
        let source = state
            .sources
            .get(&request.binding)
            .ok_or(ResolveError::Unknown)?;
        crate::secrets::resolve_secret_ref_classified(
            &request.binding,
            source,
            crate::secrets::ResolutionScope::RecordReplay,
        )
        .map_err(|failure| ResolveError::Unavailable(failure.as_str().to_string()))
    }
}

/// Parse a `--credential NAME=ENV_VAR@HOST[,HOST...][:body][:set-header=HEADER]` flag.
pub fn parse_credential_flag(spec: &str) -> std::result::Result<CredentialBinding, String> {
    let usage = "expected NAME=ENV_VAR@HOST[,HOST...][:body][:set-header=HEADER] \
        (e.g. notion=NOTION_API_KEY@api.notion.com)";
    let (name, rest) = spec.split_once('=').ok_or(usage)?;
    let (env_var, hosts) = rest.split_once('@').ok_or(usage)?;
    let mut parts = hosts.split(':');
    let hosts = parts.next().expect("split always yields a first part");
    let mut body = false;
    let mut set_header = None;
    for modifier in parts {
        match modifier {
            "" => {
                return Err(format!(
                    "credential modifier is empty; use :body or :set-header=HEADER; {usage}"
                ));
            }
            "body" if body => return Err("credential modifier :body appears more than once".into()),
            "body" => body = true,
            modifier if modifier.starts_with("set-header=") => {
                if set_header.is_some() {
                    return Err(
                        "credential modifier :set-header=HEADER appears more than once".into(),
                    );
                }
                let header = &modifier["set-header=".len()..];
                if header.is_empty() {
                    return Err(
                        "credential modifier :set-header=HEADER requires a non-empty header name"
                            .into(),
                    );
                }
                // Header names are case-insensitive; store the lowercase form
                // the policy requires, as hosts are above.
                set_header = Some(header.to_ascii_lowercase());
            }
            modifier => {
                return Err(format!(
                    "unknown credential modifier :{modifier}; expected :body or :set-header=HEADER"
                ));
            }
        }
    }
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
        injection_location: smolvm_protocol::credentials::InjectionLocation {
            body,
            ..Default::default()
        },
        methods: smolvm_protocol::credentials::DEFAULT_METHODS
            .iter()
            .map(|m| m.to_string())
            .collect(),
        set_header,
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
        assert_eq!(b.set_header, None);
        let b = parse_credential_flag("oauth=REFRESH@auth.example.com:body").unwrap();
        assert!(b.injection_location.body);
        assert_eq!(b.allowed_hosts, vec!["auth.example.com"]);
        assert_eq!(b.set_header, None);
        assert!(parse_credential_flag("notion=NOTION_API_KEY").is_err());
        assert!(parse_credential_flag("=X@h").is_err());
    }

    #[test]
    fn credential_flag_sets_a_header_from_the_complete_host_value() {
        let binding = parse_credential_flag(
            "github=GITHUB_AUTH@github.com,*.github.com:set-header=Authorization",
        )
        .unwrap();

        assert_eq!(binding.set_header.as_deref(), Some("authorization"));
        assert!(!binding.injection_location.body);
        assert_eq!(binding.environment_variable, "GITHUB_AUTH");
    }

    #[test]
    fn credential_flag_accepts_body_and_set_header_in_either_order() {
        for spec in [
            "oauth=TOKEN@auth.example.com:body:set-header=authorization",
            "oauth=TOKEN@auth.example.com:set-header=authorization:body",
        ] {
            let binding = parse_credential_flag(spec).unwrap();
            assert!(binding.injection_location.body);
            assert_eq!(binding.set_header.as_deref(), Some("authorization"));
        }
    }

    #[test]
    fn credential_flag_rejects_empty_unknown_and_duplicate_modifiers() {
        let empty = parse_credential_flag("token=TOKEN@api.example.com:").unwrap_err();
        assert!(empty.contains("modifier is empty"), "{empty}");
        let empty_header =
            parse_credential_flag("token=TOKEN@api.example.com:set-header=").unwrap_err();
        assert!(
            empty_header.contains("non-empty header name"),
            "{empty_header}"
        );
        let unknown = parse_credential_flag("token=TOKEN@api.example.com:query").unwrap_err();
        assert!(
            unknown.contains("unknown credential modifier :query"),
            "{unknown}"
        );
        let duplicate = parse_credential_flag("token=TOKEN@api.example.com:body:body").unwrap_err();
        assert!(
            duplicate.contains(":body appears more than once"),
            "{duplicate}"
        );
        let duplicate_header = parse_credential_flag(
            "token=TOKEN@api.example.com:set-header=authorization:set-header=x-api-key",
        )
        .unwrap_err();
        assert!(
            duplicate_header.contains(":set-header=HEADER appears more than once"),
            "{duplicate_header}"
        );
    }

    fn send(dir: &Path, body: &str) -> String {
        use std::io::{Read, Write};
        let mut stream =
            crate::platform::uds::UdsStream::connect(dir.join(CREDENTIALS_SOCKET)).unwrap();
        stream.write_all(body.as_bytes()).unwrap();
        stream.shutdown(std::net::Shutdown::Write).unwrap();
        let mut reply = String::new();
        stream.read_to_string(&mut reply).unwrap();
        reply.trim().to_string()
    }

    fn request(binding: &str, host: &str) -> CredentialRequest {
        CredentialRequest {
            machine: "live-test".into(),
            binding: binding.into(),
            host: host.into(),
            port: 443,
            method: "GET".into(),
            path: "/".into(),
        }
    }

    /// A launch for `specs` whose CA lives in `dir`.
    fn launch_in(dir: &Path, specs: &[&str], supplied_only: bool) -> CredentialLaunch {
        let policy = CredentialPolicy {
            credentials: specs
                .iter()
                .map(|spec| parse_credential_flag(spec).unwrap())
                .collect(),
        };
        let placeholders = smolvm_credentials::generate_placeholders(&policy);
        let mut launch =
            CredentialLaunch::describe("live-test", &policy, &placeholders, &BTreeMap::new(), None);
        launch.ca_dir = dir.join("ca");
        launch.supplied_only = supplied_only;
        launch
    }

    fn resolver_of(live: &LiveCredentials) -> Arc<SecretRefResolver> {
        live.state
            .lock()
            .unwrap()
            .running
            .as_ref()
            .unwrap()
            .resolver
            .clone()
    }

    fn bindings_message(launch: &CredentialLaunch) -> String {
        serde_json::json!({
            "bindings": BindingsMessage {
                policy: launch.policy.clone(),
                placeholders: launch.placeholders.clone(),
                supplied_only: launch.supplied_only,
            }
        })
        .to_string()
    }

    /// A running machine takes a rotated value through its credentials socket
    /// and resolves it from the next request, over the value it booted with.
    #[test]
    fn values_sent_to_a_running_machine_replace_the_ones_it_booted_with() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        std::fs::write(&path, "booted").unwrap();
        let launch = launch_in(dir.path(), &["github=GH_TOKEN@github.com"], false);
        launch.ensure_ca().unwrap();
        let (_interceptor, live) = launch
            .spawn_interceptor([("github".into(), crate::secrets::file_ref(path))].into())
            .unwrap();
        live.clone().serve(dir.path());
        let resolver = resolver_of(&live);
        let github = request("github", "github.com");
        assert_eq!(resolver.resolve(&github).unwrap().as_str(), "booted");

        assert_eq!(send(dir.path(), r#"{"values":{"github":"rotated"}}"#), "ok");
        assert_eq!(resolver.resolve(&github).unwrap().as_str(), "rotated");

        let refused = send(dir.path(), r#"{"values":{"other":"x"}}"#);
        assert!(
            refused.contains("no credential binding 'other'"),
            "{refused}"
        );
        assert_eq!(resolver.resolve(&github).unwrap().as_str(), "rotated");
        assert!(send(dir.path(), "{}").starts_with("error:"));
        // Sources, the CA and the machine are the boot process's own; a
        // message cannot name them.
        let smuggled = send(
            dir.path(),
            r#"{"bindings":{"policy":{"credentials":[]},"placeholders":{},"sources":{}}}"#,
        );
        assert!(smuggled.starts_with("error:"), "{smuggled}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.path().join(CREDENTIALS_SOCKET))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "only the machine's user reaches it");
        }
    }

    /// New bindings reach a running machine whole: a binding unchanged in
    /// every respect keeps its source and value, a removed one loses both,
    /// and a new one resolves from its own variable, or, on a machine whose
    /// values are supplied, only from a value sent for it.
    #[test]
    fn bindings_sent_to_a_running_machine_replace_the_ones_it_booted_with() {
        for supplied_only in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let launch = launch_in(
                dir.path(),
                &["a=A_KEY@api.a.com", "b=B_KEY@api.b.com"],
                supplied_only,
            );
            launch.ensure_ca().unwrap();
            let boot_sources: BTreeMap<String, SecretRef> = [
                (
                    "a".to_string(),
                    crate::secrets::env_ref("SMOLVM_CREDENTIAL_0"),
                ),
                (
                    "b".to_string(),
                    crate::secrets::env_ref("SMOLVM_CREDENTIAL_1"),
                ),
            ]
            .into();
            let (_interceptor, live) = launch.spawn_interceptor(boot_sources).unwrap();
            live.clone().serve(dir.path());
            assert_eq!(send(dir.path(), r#"{"values":{"a":"va","b":"vb"}}"#), "ok");

            let mut next = launch_in(
                dir.path(),
                &["a=A_KEY@api.a.com", "c=C_KEY@api.c.com"],
                supplied_only,
            );
            next.placeholders
                .insert("a".into(), launch.placeholders["a"].clone());
            let reply = send(dir.path(), &bindings_message(&next));
            let (ok, data) = reply.split_once('\n').expect("ok and the CA");
            assert_eq!(ok, "ok");
            let reply: BindingsReply = serde_json::from_str(data).unwrap();
            assert!(reply.ca_pem.contains("BEGIN CERTIFICATE"));

            let resolver = resolver_of(&live);
            let state = resolver.lock().clone();
            assert_eq!(
                state.sources["a"].from_env.as_deref(),
                Some("SMOLVM_CREDENTIAL_0"),
                "an unchanged binding resolves where it did"
            );
            assert!(
                !state.sources.contains_key("b"),
                "a removed binding has no source"
            );
            assert_eq!(
                state.sources.get("c").and_then(|s| s.from_env.as_deref()),
                (!supplied_only).then_some("C_KEY"),
                "a new binding of a supplied machine never reads this host's environment"
            );
            assert_eq!(state.live.get("a").map(|v| v.as_str()), Some("va"));
            assert!(
                !state.live.contains_key("b"),
                "a removed binding drops its value"
            );
            assert!(matches!(
                resolver.resolve(&request("b", "api.b.com")),
                Err(ResolveError::Unknown)
            ));
            assert!(
                send(dir.path(), r#"{"values":{"b":"x"}}"#).contains("no credential binding 'b'")
            );
            assert_eq!(send(dir.path(), r#"{"values":{"c":"vc"}}"#), "ok");
            assert_eq!(
                resolver
                    .resolve(&request("c", "api.c.com"))
                    .unwrap()
                    .as_str(),
                "vc"
            );
        }
    }

    /// A binding whose hosts change, even under the same name and
    /// placeholder, is a new binding: it keeps neither the value nor the
    /// source it had, so a key bound to one service never reaches another.
    #[test]
    fn a_rebound_name_keeps_neither_value_nor_source() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("openai");
        std::fs::write(&path, "sk-openai").unwrap();
        let launch = launch_in(dir.path(), &["key=OPENAI_KEY@api.openai.com"], false);
        launch.ensure_ca().unwrap();
        let (_interceptor, live) = launch
            .spawn_interceptor([("key".into(), crate::secrets::file_ref(path))].into())
            .unwrap();
        live.clone().serve(dir.path());
        assert_eq!(send(dir.path(), r#"{"values":{"key":"sk-live"}}"#), "ok");

        let mut moved = launch_in(dir.path(), &["key=OPENAI_KEY@api.anthropic.com"], false);
        moved.placeholders = launch.placeholders.clone();
        assert!(send(dir.path(), &bindings_message(&moved)).starts_with("ok"));
        let state = resolver_of(&live).lock().clone();
        assert!(
            state.live.is_empty(),
            "the value sent for the old binding is gone"
        );
        assert_eq!(
            state.sources["key"].from_env.as_deref(),
            Some("OPENAI_KEY"),
            "the old file source is gone too"
        );
    }

    /// An API caller or embedder replacing an operator's binding, even with
    /// the very same binding, must never resolve it from this host: the
    /// machine becomes supplied, so every host source and every value goes.
    #[test]
    fn a_supplied_replacement_drops_every_host_source_and_value() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gh");
        std::fs::write(&path, "ghp_operator").unwrap();
        let launch = launch_in(dir.path(), &["gh=GH_TOKEN@github.com"], false);
        launch.ensure_ca().unwrap();
        let (_interceptor, live) = launch
            .spawn_interceptor([("gh".into(), crate::secrets::file_ref(path))].into())
            .unwrap();
        live.clone().serve(dir.path());
        assert_eq!(send(dir.path(), r#"{"values":{"gh":"ghp_cli"}}"#), "ok");

        let mut hijack = launch_in(dir.path(), &["gh=GH_TOKEN@attacker.example"], true);
        hijack.placeholders = launch.placeholders.clone();
        assert!(send(dir.path(), &bindings_message(&hijack)).starts_with("ok"));
        let resolver = resolver_of(&live);
        let state = resolver.lock().clone();
        assert!(state.sources.is_empty(), "{:?}", state.sources.keys());
        assert!(state.live.is_empty());
        assert!(matches!(
            resolver.resolve(&request("gh", "attacker.example")),
            Err(ResolveError::Unknown)
        ));
        // The same binding, unchanged but now supplied, is no different.
        let mut same = launch_in(dir.path(), &["gh=GH_TOKEN@github.com"], true);
        same.placeholders = launch.placeholders.clone();
        assert!(send(dir.path(), &bindings_message(&same)).starts_with("ok"));
        assert!(resolver.lock().sources.is_empty());
        // Once supplied, a message cannot make it read this host again.
        let mut back = launch_in(dir.path(), &["gh=GH_TOKEN@github.com"], false);
        back.placeholders = launch.placeholders.clone();
        assert!(send(dir.path(), &bindings_message(&back)).starts_with("ok"));
        assert!(resolver.lock().sources.is_empty());
    }

    /// A rollback restores exactly what the last bindings replaced: policy,
    /// placeholders, sources, values and whether values are supplied.
    #[test]
    fn a_rollback_restores_the_exact_previous_state() {
        let dir = tempfile::tempdir().unwrap();
        let launch = launch_in(
            dir.path(),
            &["a=A_KEY@api.a.com", "b=B_KEY@api.b.com"],
            false,
        );
        launch.ensure_ca().unwrap();
        let boot: BTreeMap<String, SecretRef> = [
            ("a".to_string(), crate::secrets::env_ref("A_KEY")),
            ("b".to_string(), crate::secrets::env_ref("B_KEY")),
        ]
        .into();
        let (_interceptor, live) = launch.spawn_interceptor(boot.clone()).unwrap();
        live.clone().serve(dir.path());
        assert_eq!(send(dir.path(), r#"{"values":{"a":"va","b":"vb"}}"#), "ok");
        let before = resolver_of(&live).lock().clone();

        let next = launch_in(dir.path(), &["c=C_KEY@api.c.com"], true);
        assert!(send(dir.path(), &bindings_message(&next)).starts_with("ok"));
        assert!(live.state.lock().unwrap().supplied_only);
        assert_eq!(send(dir.path(), r#"{"rollback":true}"#), "ok");

        let state = live.state.lock().unwrap();
        assert!(!state.supplied_only);
        assert_eq!(state.policy, launch.policy);
        assert_eq!(state.placeholders, launch.placeholders);
        drop(state);
        let after = resolver_of(&live).lock().clone();
        assert_eq!(after.sources, before.sources);
        assert_eq!(
            after
                .live
                .iter()
                .map(|(k, v)| (k.clone(), v.to_string()))
                .collect::<Vec<_>>(),
            before
                .live
                .iter()
                .map(|(k, v)| (k.clone(), v.to_string()))
                .collect::<Vec<_>>()
        );
        assert!(send(dir.path(), r#"{"rollback":true}"#).contains("no replaced bindings"));
    }

    /// A machine that booted without bindings serves the socket too. Its
    /// first bindings make the boot process (the machine's own user) create
    /// the CA in the machine's own directory and start the interceptor; a
    /// rollback stops it again.
    #[test]
    fn the_first_bindings_start_an_interceptor_on_a_running_machine() {
        let dir = tempfile::tempdir().unwrap();
        let slot = smolvm_network::LateHttpsIntercept::new();
        let identity = CredentialIdentity {
            machine: "live-test".into(),
            ca_owner: "live-test".into(),
            ca_dir: dir.path().join("ca"),
        };
        serve_without_bindings(dir.path(), identity.clone(), slot);
        assert!(send(dir.path(), r#"{"values":{"a":"x"}}"#).contains("no credential binding 'a'"));
        assert_eq!(send(dir.path(), r#"{"values":{}}"#), "ok");
        assert!(slot.get().is_none());
        assert!(!identity.ca_dir.exists(), "no CA before the first binding");

        let launch = launch_in(dir.path(), &["a=A_KEY@api.a.com"], true);
        let reply = send(dir.path(), &bindings_message(&launch));
        assert!(reply.starts_with("ok\n"), "{reply}");
        assert!(
            MachineCa::exists(&identity.ca_dir),
            "the boot process made the CA"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let key = std::fs::metadata(identity.ca_dir.join("ca.key")).unwrap();
            // SAFETY: getuid has no preconditions.
            assert_eq!(
                key.uid(),
                unsafe { libc::getuid() },
                "owned by the boot process's user"
            );
            assert_eq!(key.mode() & 0o777, 0o600);
        }
        assert!(
            slot.get().is_some(),
            "HTTPS now goes through the interceptor"
        );
        assert_eq!(send(dir.path(), r#"{"values":{"a":"x"}}"#), "ok");

        assert_eq!(send(dir.path(), r#"{"rollback":true}"#), "ok");
        assert!(slot.get().is_none(), "back to relaying directly");
        assert!(send(dir.path(), r#"{"values":{"a":"x"}}"#).contains("no credential binding 'a'"));
    }

    /// The guest is handed the CA unless its record says it already holds
    /// that very certificate: a CA widened on disk by a sibling branch, or by
    /// an attempt that was rolled back, still reaches it.
    #[test]
    fn the_guest_gets_the_ca_unless_it_holds_that_certificate() {
        let mut record = VmRecord::new("trust".into(), 1, 512, vec![], vec![], true);
        let first = MachineCa::generate("trust", &["api.a.com".to_string()]).unwrap();
        let pem = first.certificate_pem().to_string();
        assert!(guest_needs_ca(&record, &pem), "never given one");
        record.credential_ca_trusted = Some(CredentialLaunch::ca_fingerprint(&pem));
        assert!(!guest_needs_ca(&record, &pem));
        let widened = first.widened(&["api.b.com".to_string()]).unwrap().unwrap();
        assert!(
            guest_needs_ca(&record, widened.certificate_pem()),
            "a certificate widened elsewhere is new to this guest"
        );
    }

    /// The host reads the CA without following links: a machine that swapped
    /// any component for a link cannot make it read another file, and only a
    /// certificate ever comes back.
    #[cfg(unix)]
    #[test]
    fn the_host_reads_the_ca_without_following_links() {
        let dir = tempfile::tempdir().unwrap();
        let ca_dir = dir.path().join("credentials");
        let ca = MachineCa::generate("m", &["api.a.com".to_string()]).unwrap();
        ca.save(&ca_dir).unwrap();
        let pem = read_ca_certificate(&ca_dir).unwrap();
        assert_eq!(pem, ca.certificate_pem().replace("\r\n", "\n"));

        // Trailing data after the certificate never comes back.
        let guest = MachineCa::guest_dir(&ca_dir);
        let mut padded = ca.certificate_pem().as_bytes().to_vec();
        padded.extend_from_slice(b"SECRET-NOT-A-CERT\n");
        std::fs::write(guest.join("ca.pem"), &padded).unwrap();
        assert!(!read_ca_certificate(&ca_dir).unwrap().contains("SECRET"));

        let elsewhere = dir.path().join("elsewhere");
        ca.save(&elsewhere).unwrap();
        // The file, the guest directory, and the CA directory itself.
        std::fs::remove_file(guest.join("ca.pem")).unwrap();
        std::os::unix::fs::symlink(elsewhere.join("guest/ca.pem"), guest.join("ca.pem")).unwrap();
        assert!(read_ca_certificate(&ca_dir).is_err());
        std::fs::remove_dir_all(&guest).unwrap();
        std::os::unix::fs::symlink(elsewhere.join("guest"), &guest).unwrap();
        assert!(read_ca_certificate(&ca_dir).is_err());
        std::fs::remove_dir_all(&ca_dir).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &ca_dir).unwrap();
        assert!(read_ca_certificate(&ca_dir).is_err());
        // Not a regular file.
        std::fs::remove_file(&ca_dir).unwrap();
        std::fs::create_dir_all(MachineCa::guest_dir(&ca_dir).join("ca.pem")).unwrap();
        assert!(read_ca_certificate(&ca_dir).is_err());
    }

    /// The CA is created on first use and only widened afterwards, keeping
    /// its key, so a guest that trusts an earlier certificate keeps trusting
    /// the hosts it permitted.
    #[test]
    fn the_ca_widens_to_new_hosts_and_never_narrows() {
        let dir = tempfile::tempdir().unwrap();
        let first = launch_in(dir.path(), &["a=A_KEY@api.a.com"], false);
        assert!(first.ensure_ca().unwrap(), "created");
        assert!(!first.ensure_ca().unwrap(), "already covers its hosts");
        let original = MachineCa::load(&first.ca_dir, "live-test").unwrap();

        let wider = launch_in(dir.path(), &["b=B_KEY@*.b.example.com"], false);
        assert!(wider.ensure_ca().unwrap(), "widened");
        let widened = MachineCa::load(&first.ca_dir, "live-test").unwrap();
        let mut hosts = widened.permitted_hosts().unwrap();
        hosts.sort();
        assert_eq!(hosts, ["api.a.com", "b.example.com"]);
        assert_ne!(widened.certificate_pem(), original.certificate_pem());
        assert_eq!(
            std::fs::read_to_string(MachineCa::guest_dir(&first.ca_dir).join("ca.pem")).unwrap(),
            widened.certificate_pem(),
            "the guest's copy follows"
        );
        // The same key signs: a leaf for an old host chains to the old
        // certificate a running process may still hold.
        assert!(!first.ensure_ca().unwrap(), "removing a host never narrows");

        let empty = launch_in(dir.path(), &[], false);
        assert!(!empty.ensure_ca().unwrap());
        let fresh = tempfile::tempdir().unwrap();
        let none = launch_in(fresh.path(), &[], false);
        assert!(
            none.ensure_ca().unwrap(),
            "a CA with no host yet still exists"
        );
    }

    #[test]
    fn file_backed_credential_uses_the_latest_host_value() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("refresh-token");
        let source = crate::secrets::file_ref(path.clone());
        let resolver = SecretRefResolver::new([("refresh".into(), source)].into());
        let request = CredentialRequest {
            machine: "oauth-test".into(),
            binding: "refresh".into(),
            host: "auth.example.com".into(),
            port: 443,
            method: "POST".into(),
            path: "/token".into(),
        };
        std::fs::write(&path, "first").unwrap();
        assert_eq!(resolver.resolve(&request).unwrap().as_str(), "first");
        std::fs::write(&path, "second").unwrap();
        assert_eq!(resolver.resolve(&request).unwrap().as_str(), "second");
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

    #[test]
    fn supplied_values_reach_only_the_boot_process() {
        let machine = "cred-test-supplied";
        supply_values(
            machine,
            [(
                "a".to_string(),
                zeroize::Zeroizing::new("value-a".to_string()),
            )]
            .into(),
        );
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
    fn values_of_removed_bindings_are_dropped() {
        let machine = "cred-test-retain";
        supply_values(
            machine,
            [
                ("a".to_string(), zeroize::Zeroizing::new("va".to_string())),
                ("b".to_string(), zeroize::Zeroizing::new("vb".to_string())),
            ]
            .into(),
        );
        retain_values(
            machine,
            &CredentialPolicy {
                credentials: vec![parse_credential_flag("b=B_KEY@api.b.com").unwrap()],
            },
        );
        let mut l = launch(machine, true);
        let env = l.child_env();
        assert_eq!(env[0].1, None, "a's value is gone");
        assert_eq!(env[1].1.as_deref().map(String::as_str), Some("vb"));
        retain_values(machine, &CredentialPolicy::default());
        assert!(launch(machine, true)
            .child_env()
            .iter()
            .all(|(_, v)| v.is_none()));
    }

    #[test]
    fn a_branch_uses_its_goldens_values_until_given_its_own() {
        let golden = "cred-test-golden";
        let clone = "cred-test-golden-branch";
        supply_values(
            golden,
            [(
                "a".to_string(),
                zeroize::Zeroizing::new("golden-a".to_string()),
            )]
            .into(),
        );
        let policy = CredentialPolicy {
            credentials: vec![parse_credential_flag("a=A_KEY@api.a.com").unwrap()],
        };
        let mut l = CredentialLaunch::from_parts(
            clone,
            &policy,
            &BTreeMap::new(),
            &BTreeMap::new(),
            Some(golden),
        )
        .unwrap();
        l.supplied_only = true;
        let env = l.child_env();
        assert_eq!(env[0].1.as_deref().map(String::as_str), Some("golden-a"));
        supply_values(
            clone,
            [(
                "a".to_string(),
                zeroize::Zeroizing::new("branch-a".to_string()),
            )]
            .into(),
        );
        let env = l.child_env();
        assert_eq!(env[0].1.as_deref().map(String::as_str), Some("branch-a"));
        forget_values(golden);
        forget_values(clone);
    }

    #[test]
    fn api_bindings_never_fall_back_to_host_variables() {
        let machine = "cred-test-api";
        forget_values(machine);
        let mut l = launch(machine, true);
        let env = l.child_env();
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
}
