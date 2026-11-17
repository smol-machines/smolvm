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

/// Capability a server advertises in `GET /health` (`capabilities`) when it
/// serves `PUT /api/v1/machines/{name}/credentials`: bindings replaceable in
/// every state, live on a running machine.
pub const CREDENTIAL_BINDINGS_CAPABILITY: &str = "credential-bindings-v1";

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
            recorded_ownership: false,
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
        let ca = load_ca(&self.ca_dir, &self.ca_owner)?;
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
                replaced: false,
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
    /// The identity of machine `name`, whose record is `record`.
    pub fn of(name: &str, record: &VmRecord) -> Self {
        let ca_owner = record.golden.as_deref().unwrap_or(name);
        Self {
            machine: name.to_string(),
            ca_owner: ca_owner.to_string(),
            ca_dir: ca_dir(ca_owner),
        }
    }
}

impl CredentialLaunch {
    /// A launch with no binding, for a boot that must still recreate the CA
    /// device a saved guest was saved with.
    pub fn without_bindings(identity: &CredentialIdentity, supplied_only: bool) -> Self {
        Self {
            machine: identity.machine.clone(),
            policy: CredentialPolicy::default(),
            placeholders: BTreeMap::new(),
            ca_owner: identity.ca_owner.clone(),
            ca_dir: identity.ca_dir.clone(),
            sources: BTreeMap::new(),
            supplied_only,
            ca_boot_mount: true,
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
        if let Some(ca) = covering(load_ca(dir, &identity.ca_owner).map_err(fail)?)? {
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
    let ca = load_ca(dir, &identity.ca_owner).map_err(fail)?;
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

/// Load the CA of a lineage from `ca_dir` without following links, as
/// [`read_ca_certificate`] reads its certificate: a process that may run as
/// another user than the directory's owner (root capturing a checkpoint of a
/// machine running under its own uid) must never be made to load, and so
/// export, some other key the owner linked in its place.
pub fn load_ca(ca_dir: &Path, ca_owner: &str) -> Result<MachineCa> {
    MachineCa::load_with(ca_owner, |file| read_without_links(ca_dir, &[file]))
        .map_err(|e| Error::config("credentials", format!("load machine CA: {e:#}")))
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

/// Largest CA file the host reads: a name, a certificate or a key.
const MAX_CA_FILE_BYTES: u64 = 64 * 1024;

/// Read a file of a CA directory from the host without following links.
fn read_without_links(base: &Path, components: &[&str]) -> std::io::Result<Vec<u8>> {
    crate::nofollow::read(base, components, MAX_CA_FILE_BYTES)
}

/// Save `ca` as the CA in `<vm_data_dir>/credentials`, as [`MachineCa::save`]
/// does, but writing every file without following a link: for a host process
/// writing into a machine's directory, which the machine's user may own (a
/// checkpoint restored into a paused machine's directory).
pub fn save_ca_without_links(ca: &MachineCa, vm_data_dir: &Path) -> Result<()> {
    ca.save_with(|path, bytes, mode| {
        let mut components = vec![CA_DIR_NAME];
        components.extend_from_slice(path);
        crate::nofollow::write_replacing(vm_data_dir, &components, bytes, mode)
    })
    .map_err(|e| Error::config("credentials", format!("save machine CA: {e:#}")))
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
            replaced: false,
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
    /// The change failed and undoing it failed too: the running machine may
    /// enforce other bindings than its record holds until its bindings are
    /// set again or it restarts. The record says so
    /// ([`VmRecord::credential_bindings_unsettled`]), so the next change
    /// reaches the machine even if it changes nothing in the record.
    Unsettled(Error),
}

impl From<BindingsError> for Error {
    fn from(error: BindingsError) -> Self {
        match error {
            BindingsError::Invalid(e)
            | BindingsError::Conflict(e)
            | BindingsError::Failed(e)
            | BindingsError::Unsettled(e) => e,
        }
    }
}

impl std::fmt::Display for BindingsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BindingsError::Invalid(e)
            | BindingsError::Conflict(e)
            | BindingsError::Failed(e)
            | BindingsError::Unsettled(e) => e.fmt(f),
        }
    }
}

/// The error for a change that failed with `cause` and could not be undone
/// (`undo`): says the machine may be inconsistent, and how to bring it back.
fn unsettled(name: &str, cause: &dyn std::fmt::Display, undo: &[String]) -> BindingsError {
    BindingsError::Unsettled(Error::config(
        "credentials",
        format!(
            "changing machine '{name}''s credential bindings failed ({cause}), and restoring the \
             previous ones failed too ({}); its record and the running machine may now hold \
             different bindings. Set its bindings again (`smolvm machine update --name {name} \
             --credential …` or `--remove-credential …`, or PUT \
             /api/v1/machines/{name}/credentials), which reaches the running machine even if \
             the record already holds them, or restart it",
            undo.join("; ")
        ),
    ))
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
    set_bindings_with(
        db,
        name,
        caller,
        None,
        |_| Ok(policy),
        None,
        &BootProcess,
        |_, _, _| Ok(()),
    )
}

/// The CLI's `machine update --credential` / `--remove-credential`: `edit`
/// builds the new bindings from the machine's record as it is under the
/// change's lock, never from one read before it, so a change someone else
/// made meanwhile is neither lost nor undone; then `then(before, saved,
/// running)` runs while the change is still exclusive (the CLI hands a
/// running machine values for the bindings it just set, so none can reach a
/// binding someone else set meanwhile).
///
/// `named` are the bindings this command names. A binding becomes one whose
/// values come from this host only if it is named, or already was one: when
/// the record was emptied by an API caller meanwhile, nothing it once held
/// can come back reading this host's environment.
///
/// A `then` that fails undoes the change: the record and, on a running
/// machine, the boot process get back exactly the bindings they had, so a
/// command that reports failure has changed nothing.
///
/// `other` carries the command's other settings, when it changes any: they
/// are applied to the record as the lock finds it, the new bindings are
/// checked against the result (a network or allow list the same command
/// adds counts, one it removes no longer does), and bindings and settings
/// are written to the record together, once.
pub fn edit_bindings_from_cli(
    db: &crate::db::SmolvmDb,
    name: &str,
    named: &std::collections::BTreeSet<String>,
    edit: impl FnOnce(&VmRecord) -> Result<CredentialPolicy>,
    other: Option<OtherSettings<'_>>,
    then: impl FnOnce(&VmRecord, &VmRecord, bool) -> Result<()>,
) -> std::result::Result<VmRecord, BindingsError> {
    set_bindings_with(
        db,
        name,
        crate::machine_spec::Caller::Cli,
        Some(named),
        edit,
        other,
        &BootProcess,
        then,
    )
}

/// Changes to a stopped machine's other settings, written in the same record
/// write as its new bindings (`machine update` with other flags beside
/// `--credential`).
pub struct OtherSettings<'a> {
    /// Apply the settings to a record, given its new bindings: to a copy of
    /// the record as the lock finds it, which the bindings are then checked
    /// against, and again in the write. An error refuses the whole change.
    pub apply: &'a dyn Fn(&mut VmRecord, &CredentialPolicy) -> Result<()>,
    /// Work outside the record (growing disks), run inside the record's write
    /// once nothing else can refuse it: an error writes nothing. It must not
    /// use the database.
    pub prepare: PrepareSettings<'a>,
}

/// [`OtherSettings::prepare`].
pub type PrepareSettings<'a> = Box<dyn FnOnce(&VmRecord) -> Result<()> + 'a>;

/// Where [`set_bindings_with`] sends a running machine its new bindings: the
/// machine's boot process, or a stand-in in tests.
trait LiveBindings {
    /// [`apply_live_bindings`].
    fn apply(
        &self,
        name: &str,
        before: &VmRecord,
        next: &VmRecord,
    ) -> std::result::Result<LiveOutcome, BindingsError>;
    /// [`roll_back_live_bindings`].
    fn roll_back(&self, name: &str) -> Result<()>;
}

/// The running machine's boot process, over its [`CREDENTIALS_SOCKET`].
struct BootProcess;

impl LiveBindings for BootProcess {
    fn apply(
        &self,
        name: &str,
        before: &VmRecord,
        next: &VmRecord,
    ) -> std::result::Result<LiveOutcome, BindingsError> {
        apply_live_bindings(name, before, next)
    }

    fn roll_back(&self, name: &str) -> Result<()> {
        roll_back_live_bindings(name)
    }
}

/// Refuse to make a binding read this host's values unless the operator
/// names it now, or it already read them: `named` are the bindings this CLI
/// command names; `before` is the record as the change found it.
fn check_named_host_bindings(
    before: &VmRecord,
    next: &VmRecord,
    named: &std::collections::BTreeSet<String>,
) -> Result<()> {
    if next.credentials_supplied_by_api {
        // A binding named here would never be given a value: this machine
        // takes its values only from whoever supplies them.
        if let Some(binding) = named.iter().next() {
            return Err(Error::config(
                "credentials",
                format!(
                    "machine '{name}' takes its credential values only from the API caller or \
                     embedder that set its bindings (or the checkpoint it was restored from), \
                     never from this host, so credential '{binding}' would never get a value; \
                     supply values with PUT /api/v1/machines/{name}/credential-values, or \
                     remove its bindings (--remove-credential) first so the machine reads this \
                     host's values",
                    name = before.name
                ),
            ));
        }
        return Ok(());
    }
    let was_host_sourced = !before.credentials_supplied_by_api;
    for binding in next
        .credential_policy
        .iter()
        .flat_map(|p| p.credentials.iter())
    {
        let already = was_host_sourced
            && before
                .credential_policy
                .as_ref()
                .and_then(|p| p.binding(&binding.name))
                == Some(binding);
        if !already && !named.contains(&binding.name) {
            return Err(Error::config(
                "credentials",
                format!(
                    "credential binding '{}' of machine '{}' was not set from this host and this \
                     command does not name it, so it cannot start reading this host's values; \
                     name it with --credential to bind it here",
                    binding.name, before.name
                ),
            ));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn set_bindings_with(
    db: &crate::db::SmolvmDb,
    name: &str,
    caller: crate::machine_spec::Caller,
    named: Option<&std::collections::BTreeSet<String>>,
    build: impl FnOnce(&VmRecord) -> Result<CredentialPolicy>,
    other: Option<OtherSettings<'_>>,
    live: &dyn LiveBindings,
    then: impl FnOnce(&VmRecord, &VmRecord, bool) -> Result<()>,
) -> std::result::Result<VmRecord, BindingsError> {
    use crate::config::RecordState;
    // A machine that does not exist is refused before anything is created
    // for it, not even its lock.
    if db.get_vm(name).map_err(BindingsError::Failed)?.is_none() {
        return Err(BindingsError::Failed(Error::vm_not_found(name)));
    }
    // Every change to one machine's bindings, and every start of it, is
    // serialized across processes: a start never boots bindings a change is
    // replacing, and the boot process and the record never see two changes
    // interleaved.
    let _lock = lock_bindings(name).map_err(BindingsError::Failed)?;
    let record = db
        .get_vm(name)
        .map_err(BindingsError::Failed)?
        .ok_or_else(|| BindingsError::Failed(Error::vm_not_found(name)))?;
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
    // Built from the record as it is now, under the lock.
    let policy = build(&record).map_err(BindingsError::Invalid)?;
    // Other settings go with the bindings only on a stopped machine: a
    // running one takes bindings live and nothing else with them.
    if running && other.is_some() {
        return Err(BindingsError::Conflict(Error::config(
            "credentials",
            "a running machine takes credential binding changes on their own; run the other \
             changes separately",
        )));
    }
    let (apply, prepare) = match other {
        Some(other) => (Some(other.apply), Some(other.prepare)),
        None => (None, None),
    };
    // The bindings are checked against the record as the other settings
    // leave it.
    let mut staged = record.clone();
    if let Some(apply) = apply {
        apply(&mut staged, &policy).map_err(BindingsError::Invalid)?;
    }
    let mut next = staged
        .with_credential_bindings(policy.clone(), caller)
        .map_err(|error| match error {
            Error::Agent { .. } => BindingsError::Conflict(error),
            other => BindingsError::Invalid(other),
        })?;
    if let Some(named) = named {
        check_named_host_bindings(&record, &next, named).map_err(BindingsError::Conflict)?;
    }
    // A change that lands settles the machine: the record holds what the
    // machine runs, or what it boots next.
    next.credential_bindings_unsettled = false;
    let mark_unsettled = || {
        if let Err(error) = db.update_vm(name, |r| r.credential_bindings_unsettled = true) {
            tracing::warn!(machine = name, %error, "could not record that the machine's credential bindings are unsettled");
        }
    };
    // Whether the running machine's boot process took the change, and so
    // must be told to undo it if the change fails from here on.
    let mut sent = false;
    if running {
        match live.apply(name, &record, &next) {
            Ok(outcome) => {
                sent = outcome.sent;
                if let Some(trusted) = outcome.trusted {
                    next.credential_ca_trusted = Some(trusted);
                }
            }
            Err(error @ BindingsError::Unsettled(_)) => {
                mark_unsettled();
                return Err(error);
            }
            Err(error) => return Err(error),
        }
    }
    // One write: the other settings and the bindings land together, or,
    // when a setting no longer applies to the record the write finds,
    // neither does. Work outside the record (growing disks) runs inside it,
    // last, once nothing can refuse the write any more; if it fails, nothing
    // is written.
    let saved = match db.try_update_vm(name, |r| {
        if let Some(apply) = apply {
            apply(r, &policy)?;
        }
        r.take_credential_bindings(&next);
        if let Some(prepare) = prepare {
            prepare(r)?;
        }
        Ok(())
    }) {
        Ok(Some(saved)) => saved,
        failed => {
            let cause = match failed {
                Err(e) => e,
                _ => Error::vm_not_found(name),
            };
            // The record keeps the old bindings, so the running machine must too.
            if sent {
                if let Err(undo) = live.roll_back(name) {
                    mark_unsettled();
                    return Err(unsettled(name, &cause, &[undo.to_string()]));
                }
            }
            return Err(BindingsError::Failed(cause));
        }
    };
    if let Err(error) = then(&record, &saved, running) {
        // Undo the change, so the command that fails has changed nothing.
        // The guest keeps any CA it was handed (the CA never narrows), and
        // the record keeps saying which one that is.
        let mut undo = Vec::new();
        if let Err(restore) = db.update_vm(name, |r| {
            let trusted = r.credential_ca_trusted.clone();
            r.take_credential_bindings(&record);
            r.credential_ca_trusted = trusted;
        }) {
            undo.push(format!("the record: {restore}"));
        }
        if sent {
            if let Err(roll_back) = live.roll_back(name) {
                undo.push(format!("the running machine: {roll_back}"));
            }
        }
        if !undo.is_empty() {
            mark_unsettled();
            return Err(unsettled(name, &error, &undo));
        }
        return Err(BindingsError::Conflict(error));
    }
    retain_values(
        name,
        saved
            .credential_policy
            .as_ref()
            .unwrap_or(&CredentialPolicy::default()),
        &saved.credential_placeholders,
    );
    Ok(saved)
}

/// Suffix of a machine's bindings lock file, named by its data directory's
/// hash: `<vms>/<hash>.credentials.lock`.
const BINDINGS_LOCK_SUFFIX: &str = ".credentials.lock";

/// Lock file serializing machine `name`'s binding changes and starts. It sits
/// beside the machine's data directory, in the directory of all machines,
/// which belongs to this host's user (root under `serve`), never in the
/// machine's own directory, which belongs to the machine's user: a process
/// escaped from the machine can never swap it for a link, a FIFO or a device
/// that a root CLI or server then opens. And deleting the machine never
/// unlinks a lock someone holds.
pub(crate) fn bindings_lock_path(name: &str) -> PathBuf {
    crate::agent::vm_cache_root().join(format!(
        "{}{BINDINGS_LOCK_SUFFIX}",
        crate::agent::vm_dir_hash(name)
    ))
}

/// The data directory a [`bindings_lock_path`] file belongs to, or `None`
/// when `path` is not one.
pub(crate) fn bindings_lock_owner(path: &Path) -> Option<PathBuf> {
    let hash = path
        .file_name()?
        .to_str()?
        .strip_suffix(BINDINGS_LOCK_SUFFIX)?;
    let is_hash = hash.len() == 16
        && hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    is_hash.then(|| path.with_file_name(hash))
}

/// Serialize binding changes to one machine, and its starts, across
/// processes.
pub(crate) fn lock_bindings(name: &str) -> Result<std::fs::File> {
    lock_bindings_at(&bindings_lock_path(name))
}

fn lock_bindings_at(path: &Path) -> Result<std::fs::File> {
    let fail = |e: std::io::Error| Error::agent("credentials update lock", e.to_string());
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(fail)?;
    }
    loop {
        let file = open_lock_file(path).map_err(fail)?;
        crate::agent::fork::lock_file_exclusive(&file).map_err(fail)?;
        // The sweep of orphaned locks may have removed the file between the
        // open and the lock: hold the lock only on the file the path names.
        if still_named(&file, path) {
            return Ok(file);
        }
    }
}

/// Open (creating it) a lock file without following a link, without
/// blocking on a FIFO, and only if it is a regular file.
#[cfg(unix)]
fn open_lock_file(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    Ok(file)
}

#[cfg(not(unix))]
fn open_lock_file(path: &Path) -> std::io::Result<std::fs::File> {
    if std::fs::symlink_metadata(path).is_ok_and(|m| !m.file_type().is_file()) {
        return Err(std::io::Error::other(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
}

/// Whether `path` still names the open `file`: the same file on the same
/// device, not one made under its name after it was removed.
#[cfg(unix)]
pub(crate) fn still_named(file: &std::fs::File, path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    match (file.metadata(), std::fs::symlink_metadata(path)) {
        (Ok(open), Ok(named)) => open.dev() == named.dev() && open.ino() == named.ino(),
        _ => false,
    }
}

/// Whether `path` still names the open `file`, by volume and file index:
/// Rust opens files with `FILE_SHARE_DELETE`, so an open file can be removed
/// and another made under its name.
#[cfg(windows)]
pub(crate) fn still_named(file: &std::fs::File, path: &Path) -> bool {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };
    fn id(file: &std::fs::File) -> Option<(u32, u32, u32)> {
        // SAFETY: zeroed plain data the call fills in.
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        let handle = file.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;
        // SAFETY: a live handle and a valid out pointer.
        let ok = unsafe { GetFileInformationByHandle(handle, &mut info) };
        (ok != 0).then_some((
            info.dwVolumeSerialNumber,
            info.nFileIndexHigh,
            info.nFileIndexLow,
        ))
    }
    // A file pending deletion can no longer be opened by name.
    let Ok(named) = std::fs::File::open(path) else {
        return false;
    };
    matches!((id(file), id(&named)), (Some(open), Some(now)) if open == now)
}

/// Remove machine `name`'s bindings lock, once its record is gone. A lock
/// someone holds is left for the sweep of orphaned locks
/// ([`crate::agent::fork::prune_orphaned_fork_source_locks`]); the file is
/// unlinked only while held here, and only if the path still names it, so
/// a locker never ends up holding a file another holder does not see.
pub(crate) fn remove_bindings_lock(name: &str) {
    remove_bindings_lock_at(&bindings_lock_path(name));
}

fn remove_bindings_lock_at(path: &Path) {
    let Ok(file) = open_existing_lock_file(path) else {
        return;
    };
    if crate::agent::fork::try_lock_file_exclusive(&file).is_err() {
        return;
    }
    if still_named(&file, path) {
        let _ = std::fs::remove_file(path);
    }
}

#[cfg(unix)]
fn open_existing_lock_file(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other("not a regular file"));
    }
    Ok(file)
}

#[cfg(not(unix))]
fn open_existing_lock_file(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
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
) -> std::result::Result<LiveOutcome, BindingsError> {
    before
        .check_live_credentials(next, crate::agent::running_on_pod_network(name))
        .map_err(BindingsError::Conflict)?;
    // Removing every binding still reaches the boot process, as an empty set.
    // Nothing to nothing changes nothing, unless an undo failed earlier and
    // the boot process may hold bindings the record does not: then it is
    // sent the record's (none), if it serves its socket at all. One that
    // does not has no interceptor, so holds no bindings.
    let socket = crate::agent::vm_data_dir(name).join(CREDENTIALS_SOCKET);
    if !reaches_boot_process(before, next, || std::fs::symlink_metadata(&socket).is_ok()) {
        return Ok(LiveOutcome::default());
    }
    let policy = next.credential_policy.clone().unwrap_or_default();
    let capable =
        crate::agent::supports_live_credential_trust(name).map_err(BindingsError::Conflict)?;
    let message = BindingsMessage {
        policy,
        placeholders: next.credential_placeholders.clone(),
        supplied_only: next.credentials_supplied_by_api,
        // A supplied machine never reads this host, so it is sent nothing to.
        host_sources: if next.credentials_supplied_by_api {
            BTreeMap::new()
        } else {
            next.secret_refs.clone()
        },
    };
    // Undo what the boot process took, and say what failed: plainly when
    // the undo worked, as unsettled when it did not.
    let undo = |cause: Error, kind: fn(Error) -> BindingsError| match roll_back_live_bindings(name)
    {
        Ok(()) => kind(cause),
        Err(undo) => unsettled(name, &cause, &[undo.to_string()]),
    };
    let reply = match crate::agent::apply_live_credential_policy(name, &message) {
        Ok(reply) => reply,
        // Certainly not taken (no socket, a refusal, a boot process from
        // before binding changes): there is nothing to undo.
        Err(failure) if failure.changed_nothing => {
            return Err(BindingsError::Conflict(failure.error))
        }
        // The boot process may have applied it and only the answer was
        // lost (a timeout): put back what it had.
        Err(failure) => return Err(undo(failure.error, BindingsError::Conflict)),
    };
    let taken = |trusted: Option<String>| LiveOutcome {
        trusted,
        sent: true,
    };
    let pem = rustls_pemfile::certs(&mut reply.ca_pem.as_bytes())
        .next()
        .and_then(|der| der.ok())
        .map(|der| pem_certificate(&der));
    let Some(pem) = pem else {
        // A boot process that never had bindings and is given none has no
        // CA to answer with, and the guest needs none.
        if next.credential_policy.is_none() && reply.ca_pem.is_empty() {
            return Ok(taken(None));
        }
        return Err(undo(
            Error::config(
                "credentials",
                "the boot process answered without a CA certificate",
            ),
            BindingsError::Failed,
        ));
    };
    let fingerprint = CredentialLaunch::ca_fingerprint(&pem);
    if !guest_needs_ca(before, &pem) {
        return Ok(taken(Some(fingerprint)));
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
        Ok(()) => Ok(taken(Some(fingerprint))),
        Err(error) => Err(undo(error, BindingsError::Conflict)),
    }
}

/// What a running machine's boot process did with new bindings.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct LiveOutcome {
    /// Fingerprint of the CA its guest trusts now, when it was answered.
    pub trusted: Option<String>,
    /// The boot process took the bindings: undoing the change must reach
    /// it. False when nothing was sent (nothing to nothing).
    pub sent: bool,
}

/// Whether a change from `before` to `next` must be sent to the running
/// machine's boot process: any that has or had a binding, and one from none
/// to none only while the record is unsettled and the boot process serves
/// its socket (`serves_socket`); one that does not has no interceptor, so
/// holds no binding.
fn reaches_boot_process(
    before: &VmRecord,
    next: &VmRecord,
    serves_socket: impl FnOnce() -> bool,
) -> bool {
    before.credential_policy.is_some()
        || next.credential_policy.is_some()
        || (before.credential_bindings_unsettled && serves_socket())
}

/// Whether a running machine's guest must be handed CA certificate `pem`:
/// judged by the certificate its record says the guest was last given, never
/// by what is on disk, which a sibling branch may have widened or an earlier,
/// rolled-back attempt may have changed without the guest ever seeing it.
fn guest_needs_ca(before: &VmRecord, pem: &str) -> bool {
    before.credential_ca_trusted.as_deref() != Some(CredentialLaunch::ca_fingerprint(pem).as_str())
}

/// The start of what a boot process answers to a message it cannot read.
pub const UNREADABLE_REQUEST: &str = "unreadable request";

/// What a boot process answers to a rollback when the last bindings it was
/// sent were refused, or none were: it holds what it held, so there is
/// nothing to undo.
pub const NOTHING_TO_ROLL_BACK: &str = "there are no replaced bindings to restore";

/// Return running machine `name`'s boot process to the bindings, sources and
/// values it had before the last bindings it was sent. Called only after it
/// took them; one that answers there is nothing to undo is already there.
fn roll_back_live_bindings(name: &str) -> Result<()> {
    match crate::agent::roll_back_live_credential_policy(name) {
        Ok(()) => Ok(()),
        Err(failure) if failure.error.to_string().contains(NOTHING_TO_ROLL_BACK) => Ok(()),
        Err(failure) => {
            tracing::warn!(machine = name, error = %failure.error, "could not restore the previous credential bindings");
            Err(failure.error)
        }
    }
}

/// A value handed to this process for one binding, with the binding it was
/// handed for: its variable and placeholder. It serves only that binding; a
/// binding of the same name bound to another variable, or removed and added
/// again (a new placeholder), never receives it.
#[derive(Clone)]
struct HeldValue {
    value: zeroize::Zeroizing<String>,
    environment_variable: String,
    placeholder: String,
}

/// Values handed to this process for its machines' bindings, by machine name
/// then binding name. Held in memory only: never written to a record, a boot
/// config or a checkpoint, and gone when the process exits, so whoever supplied
/// them supplies them again before the next boot.
type SuppliedValues = BTreeMap<String, HeldValue>;

static SUPPLIED: std::sync::LazyLock<std::sync::Mutex<BTreeMap<String, SuppliedValues>>> =
    std::sync::LazyLock::new(Default::default);

/// Hold `values` (binding name → value) for `machine`'s next boots, replacing
/// any held before, each for the binding `policy` and `placeholders` (the
/// machine's record) say it has now. A name with no binding is ignored.
pub fn supply_values(
    machine: &str,
    values: BTreeMap<String, zeroize::Zeroizing<String>>,
    policy: &CredentialPolicy,
    placeholders: &BTreeMap<String, String>,
) {
    let entries: SuppliedValues = values
        .into_iter()
        .filter_map(|(name, value)| {
            let binding = policy.binding(&name)?;
            Some((
                name.clone(),
                HeldValue {
                    value,
                    environment_variable: binding.environment_variable.clone(),
                    placeholder: placeholders.get(&name).cloned().unwrap_or_default(),
                },
            ))
        })
        .collect();
    let mut held = SUPPLIED.lock().unwrap_or_else(|e| e.into_inner());
    if entries.is_empty() {
        held.remove(machine);
    } else {
        held.insert(machine.to_string(), entries);
    }
}

/// Drop whatever was supplied for `machine`.
pub fn forget_values(machine: &str) {
    SUPPLIED
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(machine);
}

/// Drop the values supplied for `machine` that no binding of `policy` (with
/// `placeholders`) still takes: removed, re-added, or bound to another
/// variable. New hosts or a header keep theirs.
pub fn retain_values(
    machine: &str,
    policy: &CredentialPolicy,
    placeholders: &BTreeMap<String, String>,
) {
    let mut held = SUPPLIED.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(values) = held.get_mut(machine) {
        values.retain(|name, held| held.serves(policy.binding(name), placeholders.get(name)));
        if values.is_empty() {
            held.remove(machine);
        }
    }
}

impl HeldValue {
    fn serves(&self, binding: Option<&CredentialBinding>, placeholder: Option<&String>) -> bool {
        binding.is_some_and(|b| b.environment_variable == self.environment_variable)
            && placeholder == Some(&self.placeholder)
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
        // and its own name is new to whoever supplied the golden's. Either way
        // a value serves only the binding it was supplied for.
        let own = held.get(&self.machine);
        let golden = (self.ca_owner != self.machine)
            .then(|| held.get(&self.ca_owner))
            .flatten();
        let mut env = Vec::new();
        for (index, binding) in self.policy.credentials.iter().enumerate() {
            let placeholder = self.placeholders.get(&binding.name);
            let take = |values: Option<&SuppliedValues>| {
                values
                    .and_then(|values| values.get(&binding.name))
                    .filter(|held| held.serves(Some(binding), placeholder))
                    .map(|held| held.value.clone())
            };
            let value = match own {
                Some(_) => take(own),
                None => take(golden),
            };
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
    /// Values come only from what is sent, never from this host. A change of
    /// it from the bindings in force drops every binding's secret.
    #[serde(default)]
    pub supplied_only: bool,
    /// The machine's secret references by variable, as its record holds them
    /// now (references only): where a binding that does not keep its secret
    /// resolves from on a machine whose values come from this host, so it
    /// reads the same place it would at boot (a file read per request, say),
    /// and never a reference the record has dropped since the boot. Ignored
    /// when `supplied_only`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub host_sources: BTreeMap<String, SecretRef>,
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
/// - `{"values":{"<binding>":"<value>",…},"expect":{"<binding>":{…},…}}`
///   replaces the values the machine resolves for the bindings named, from its
///   next request on. A name that is not a current binding, or whose binding
///   is not the one `expect` names for it (or that `expect` leaves out),
///   refuses the whole message.
/// - `{"bindings":{"policy":{…},"placeholders":{…},"supplied_only":bool,
///   "host_sources":{…}}}` replaces the bindings. The boot process creates or
///   widens the CA itself and answers `ok` plus `{"ca_pem":"…"}`. A binding
///   with the same name, placeholder and variable, whose values still come
///   from the same kind of place, keeps its source and value even if its
///   hosts, header, body flag or methods changed; any other binding starts
///   with none: on a machine whose values come from this host it resolves
///   from the reference `host_sources` holds for its variable, or else the
///   boot process's own variable of that name; on a supplied machine only
///   from a value sent for it. Policy, placeholders and resolver state change
///   in one step. On a machine that booted without bindings, the first ones
///   start the interceptor.
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
    /// Bindings were ever replaced in this process. Until then every value
    /// can only be meant for the bindings it booted with, so one sent
    /// without `expect` (by a host from before bindings could change) is
    /// taken; from then on, never.
    replaced: bool,
}

/// What a value was sent for: the variable and placeholder of its binding,
/// and whether values came from this host. The same rule decides whether a
/// binding keeps its secret across a change.
#[derive(Clone, PartialEq, Eq)]
struct SecretIdentity {
    environment_variable: String,
    placeholder: Option<String>,
    supplied_only: bool,
}

impl LiveState {
    /// The secret binding `name` holds now, if it is bound.
    fn identity_of(&self, name: &str) -> Option<SecretIdentity> {
        self.policy.binding(name).map(|b| SecretIdentity {
            environment_variable: b.environment_variable.clone(),
            placeholder: self.placeholders.get(name).cloned(),
            supplied_only: self.supplied_only,
        })
    }
}

struct Previous {
    policy: CredentialPolicy,
    placeholders: BTreeMap<String, String>,
    supplied_only: bool,
    /// The resolver's state, or `None` when no interceptor ran before.
    resolver: Option<ResolverState>,
    /// Bindings the replacement kept with their secret.
    kept: Vec<String>,
    /// Values sent after the replacement, with the binding each was sent for.
    values_since: BTreeMap<String, (Option<SecretIdentity>, zeroize::Zeroizing<String>)>,
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
    /// With `values`: the binding each value is meant for. A value whose
    /// binding is no longer exactly this one is refused, so a value read for
    /// one binding never reaches one that replaced it meanwhile.
    #[serde(default)]
    expect: Option<BTreeMap<String, CredentialBinding>>,
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
            move |request| {
                self.handle(request).map(|data| {
                    if data.is_empty() {
                        "ok\n".to_string()
                    } else {
                        format!("ok\n{data}\n")
                    }
                })
            },
        );
    }

    fn handle(&self, request: &str) -> std::result::Result<String, String> {
        // Not "malformed request", which is what a boot process from before
        // binding changes answers: a host retries values without `expect`
        // only for that one, and this process never takes them so.
        let request: LiveRequest =
            serde_json::from_str(request).map_err(|e| format!("{UNREADABLE_REQUEST}: {e}"))?;
        if request.expect.is_some() && request.values.is_none() {
            return Err("`expect` goes with `values`".to_string());
        }
        match (request.values, request.bindings, request.rollback) {
            (Some(values), None, None) => self
                .replace_values(values, request.expect.as_ref())
                .map(|()| String::new()),
            (None, Some(bindings), None) => self
                .replace_bindings(bindings)
                .and_then(|reply| serde_json::to_string(&reply).map_err(|e| e.to_string())),
            (None, None, Some(true)) => self.roll_back().map(|()| String::new()),
            _ => Err("send exactly one of `values`, `bindings` and `rollback`".to_string()),
        }
    }

    fn replace_values(
        &self,
        values: BTreeMap<String, String>,
        expect: Option<&BTreeMap<String, CredentialBinding>>,
    ) -> std::result::Result<(), String> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(unknown) = values.keys().find(|k| state.policy.binding(k).is_none()) {
            return Err(format!("no credential binding '{unknown}'"));
        }
        // Every value names the binding it was read for, and is refused if
        // that is no longer the binding of its name. One without it is taken
        // only while this process still enforces the bindings it booted
        // with (a host from before bindings could change sends none): then
        // no change can have come between reading it and sending it.
        let none = BTreeMap::new();
        let legacy = expect.is_none() && !state.replaced;
        let expect = expect.unwrap_or(&none);
        if let Some(name) = values
            .keys()
            .filter(|_| !legacy)
            .find(|name| state.policy.binding(name) != expect.get(*name))
        {
            return Err(if expect.contains_key(name) {
                format!("credential binding '{name}' changed since this value was read for it")
            } else {
                format!(
                    "the value for credential binding '{name}' was sent without the binding it \
                     was read for"
                )
            });
        }
        // A rollback of the bindings these values were sent for keeps them,
        // for the bindings it restores that take them.
        let bound: Vec<Option<SecretIdentity>> =
            values.keys().map(|name| state.identity_of(name)).collect();
        if let Some(previous) = state.previous.as_mut() {
            for ((name, value), binding) in values.iter().zip(bound) {
                previous.values_since.insert(
                    name.clone(),
                    (binding, zeroize::Zeroizing::new(value.clone())),
                );
            }
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
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        // Only a replacement that succeeds may be rolled back to what it
        // replaced; one refused for any reason leaves nothing to restore.
        state.previous = None;
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
        if state.running.is_none() && message.policy.credentials.is_empty() {
            // No bindings before and none now: no interceptor to start and
            // no CA to make. Accepted (a host settling a machine whose undo
            // failed sends exactly this), and undone like any other.
            state.previous = Some(Previous {
                policy: std::mem::take(&mut state.policy),
                placeholders: std::mem::take(&mut state.placeholders),
                supplied_only: state.supplied_only,
                resolver: None,
                kept: Vec::new(),
                values_since: BTreeMap::new(),
            });
            state.supplied_only = message.supplied_only;
            state.replaced = true;
            return Ok(BindingsReply {
                ca_pem: String::new(),
            });
        }
        let (ca, _) =
            ensure_lineage_ca(&self.identity, &message.policy).map_err(|e| e.to_string())?;
        let reply = BindingsReply {
            ca_pem: ca.certificate_pem().to_string(),
        };
        // The record decides where values come from (it stays supplied while a
        // supplied binding remains); a change of it, either way, is a change
        // of every binding's secret.
        let supplied_only = message.supplied_only;
        // A binding keeps its secret (source and value) when it is the same
        // binding by name and placeholder, its variable is the same, and its
        // value still comes from the same kind of place. New hosts or a new
        // header keep it: the caller re-scoped the same secret. A new
        // variable, or values that stop coming from this host, drop it, so
        // the old secret is never sent anywhere under the new definition.
        let unchanged = |binding: &CredentialBinding| {
            state
                .policy
                .binding(&binding.name)
                .is_some_and(|current| current.environment_variable == binding.environment_variable)
                && state.placeholders.get(&binding.name) == message.placeholders.get(&binding.name)
                && state.supplied_only == supplied_only
        };
        let kept: Vec<String> = message
            .policy
            .credentials
            .iter()
            .filter(|b| unchanged(b))
            .map(|b| b.name.clone())
            .collect();
        // Where a binding without a kept secret resolves from: nowhere on a
        // supplied machine, whatever the message names; otherwise as at
        // boot, from the machine's own reference for its variable as the
        // record holds it now, or the boot process's variable of it.
        let fresh_source = |binding: &CredentialBinding| {
            (!supplied_only && !binding.environment_variable.is_empty()).then(|| {
                message
                    .host_sources
                    .get(&binding.environment_variable)
                    .cloned()
                    .unwrap_or_else(|| {
                        crate::secrets::env_ref(binding.environment_variable.clone())
                    })
            })
        };
        match &state.running {
            Some(running) => {
                // Connections spliced to hosts these bindings intercept end
                // first, without the resolver's lock held while they do; a
                // connection that will not end refuses the change whole.
                let prepared = running.control.prepare_bindings(&message.policy)?;
                let mut resolver = running.resolver.lock();
                let previous_resolver = resolver.clone();
                let mut next = ResolverState::default();
                for binding in &message.policy.credentials {
                    let name = &binding.name;
                    if kept.contains(name) {
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
                running.control.commit_bindings(
                    prepared,
                    message.policy.clone(),
                    &message.placeholders,
                    &kept,
                );
                *resolver = next;
                drop(resolver);
                state.previous = Some(Previous {
                    policy: state.policy.clone(),
                    placeholders: state.placeholders.clone(),
                    supplied_only: state.supplied_only,
                    resolver: Some(previous_resolver),
                    kept: kept.clone(),
                    values_since: BTreeMap::new(),
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
                    kept: Vec::new(),
                    values_since: BTreeMap::new(),
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
        state.replaced = true;
        Ok(reply)
    }

    fn roll_back(&self) -> std::result::Result<(), String> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let Some(previous) = state.previous.take() else {
            return Err(NOTHING_TO_ROLL_BACK.to_string());
        };
        // Connections spliced to hosts the restored bindings intercept end
        // first; if one will not, nothing is restored, and the rollback can
        // be asked for again. An interceptor started since is kept, with no
        // binding (see below).
        let target = match &previous.resolver {
            Some(_) => previous.policy.clone(),
            None => CredentialPolicy::default(),
        };
        let prepared = match &state.running {
            Some(running) => match running.control.prepare_bindings(&target) {
                Ok(prepared) => Some(prepared),
                Err(reason) => {
                    state.previous = Some(previous);
                    return Err(reason);
                }
            },
            None => None,
        };
        match previous.resolver {
            Some(mut resolver_state) => {
                // A value sent since serves a restored binding that has the
                // same secret it was sent for (variable, placeholder, where
                // values come from), as a change keeps a secret by: a value
                // rotated after a hosts-only change replaces the older one.
                for (name, (identity, value)) in previous.values_since {
                    let restored = previous.policy.binding(&name).map(|b| SecretIdentity {
                        environment_variable: b.environment_variable.clone(),
                        placeholder: previous.placeholders.get(&name).cloned(),
                        supplied_only: previous.supplied_only,
                    });
                    if identity.is_some() && restored == identity {
                        resolver_state.live.insert(name, value);
                    }
                }
                if let (Some(running), Some(prepared)) = (&state.running, prepared) {
                    let mut resolver = running.resolver.lock();
                    running.control.commit_bindings(
                        prepared,
                        previous.policy.clone(),
                        &previous.placeholders,
                        &previous.kept,
                    );
                    *resolver = resolver_state;
                }
            }
            None => {
                // No interceptor ran before the one started since (none was
                // started if the bindings sent were none). It keeps running
                // with no binding, still published, for as long as the
                // machine runs, whether or not it resolved a value yet: a
                // request may be resolving one as this runs, and only a
                // running interceptor keeps it from being sent. Under the
                // empty bindings that request injects nothing (its binding
                // is no longer the one it was checked against), and a host a
                // value was resolved for before they took effect stays
                // intercepted and scrubbed of it, never relayed directly
                // again.
                if let (Some(running), Some(prepared)) = (&state.running, prepared) {
                    let mut resolver = running.resolver.lock();
                    running.control.commit_bindings(
                        prepared,
                        CredentialPolicy::default(),
                        &BTreeMap::new(),
                        &[],
                    );
                    *resolver = ResolverState::default();
                    tracing::info!(
                        "credential bindings removed; their interceptor keeps running with none"
                    );
                }
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
        // The lock covers only the lookup, never reading the source (which may
        // run a helper or wait on a file): a swap made under it is seen whole,
        // and the interceptor checks after resolving that the binding it
        // resolved for is still the same one, so a value read from a source
        // the swap replaced is never sent.
        let source = {
            let state = self.lock();
            if let Some(value) = state.live.get(&request.binding) {
                return Ok(value.clone());
            }
            state
                .sources
                .get(&request.binding)
                .cloned()
                .ok_or(ResolveError::Unknown)?
        };
        let value = crate::secrets::resolve_secret_ref_classified(
            &request.binding,
            &source,
            crate::secrets::ResolutionScope::RecordReplay,
        )
        .map_err(|failure| ResolveError::Unavailable(failure.as_str().to_string()))?;
        Ok(value)
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

    /// A values message naming, for each value whose binding `policy` has,
    /// that binding (`expect`), as a host sends it.
    fn values_for(policy: &CredentialPolicy, values: &str) -> String {
        let values: BTreeMap<String, String> = serde_json::from_str(values).unwrap();
        let expect: BTreeMap<&String, &CredentialBinding> = values
            .keys()
            .filter_map(|name| policy.binding(name).map(|b| (name, b)))
            .collect();
        serde_json::json!({ "values": values, "expect": expect }).to_string()
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
        bindings_message_with(launch, BTreeMap::new())
    }

    fn bindings_message_with(
        launch: &CredentialLaunch,
        host_sources: BTreeMap<String, SecretRef>,
    ) -> String {
        serde_json::json!({
            "bindings": BindingsMessage {
                policy: launch.policy.clone(),
                placeholders: launch.placeholders.clone(),
                supplied_only: launch.supplied_only,
                host_sources,
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

        assert_eq!(
            send(
                dir.path(),
                &values_for(&launch.policy, r#"{"github":"rotated"}"#)
            ),
            "ok"
        );
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

    /// A value sent without the binding it was read for (by a host from
    /// before bindings could change) is taken only while the boot process
    /// still enforces the bindings it booted with; once they were replaced,
    /// never. A message this process cannot read is answered as unreadable,
    /// never as the old process's "malformed request" a host falls back on.
    #[test]
    fn values_without_their_binding_are_taken_only_before_any_change() {
        let dir = tempfile::tempdir().unwrap();
        let launch = launch_in(dir.path(), &["gh=GH_TOKEN@github.com"], false);
        launch.ensure_ca().unwrap();
        let (_interceptor, live) = launch.spawn_interceptor(BTreeMap::new()).unwrap();
        live.clone().serve(dir.path());
        assert_eq!(
            send(dir.path(), r#"{"values":{"gh":"from-an-older-host"}}"#),
            "ok"
        );
        assert_eq!(
            resolver_of(&live).lock().live["gh"].as_str(),
            "from-an-older-host"
        );

        // Replaced (even with the same bindings): `expect` is required now.
        assert!(send(dir.path(), &bindings_message(&launch)).starts_with("ok"));
        let refused = send(dir.path(), r#"{"values":{"gh":"v"}}"#);
        assert!(
            refused.contains("without the binding it was read for"),
            "{refused}"
        );
        assert_eq!(
            resolver_of(&live).lock().live["gh"].as_str(),
            "from-an-older-host"
        );
        let unreadable = send(dir.path(), r#"{"values":{},"expect":{},"future":1}"#);
        assert!(
            unreadable.starts_with(&format!("error: {UNREADABLE_REQUEST}")),
            "{unreadable}"
        );
        assert!(!unreadable.contains("malformed request"));
        assert_eq!(
            send(dir.path(), &values_for(&launch.policy, r#"{"gh":"v"}"#)),
            "ok"
        );
    }

    /// A value rotated after a hosts-only change has the secret of the
    /// binding a rollback restores (same variable and placeholder), so the
    /// rollback keeps it instead of bringing back the older one.
    #[test]
    fn a_rollback_keeps_a_value_rotated_after_a_hosts_only_change() {
        let dir = tempfile::tempdir().unwrap();
        let launch = launch_in(dir.path(), &["gh=GH_TOKEN@github.com"], false);
        launch.ensure_ca().unwrap();
        let (_interceptor, live) = launch.spawn_interceptor(BTreeMap::new()).unwrap();
        live.clone().serve(dir.path());
        assert_eq!(
            send(
                dir.path(),
                &values_for(&launch.policy, r#"{"gh":"old-revoked"}"#)
            ),
            "ok"
        );
        let mut rescoped = launch_in(
            dir.path(),
            &["gh=GH_TOKEN@github.com,api.github.com"],
            false,
        );
        rescoped.placeholders = launch.placeholders.clone();
        assert!(send(dir.path(), &bindings_message(&rescoped)).starts_with("ok"));
        assert_eq!(
            send(
                dir.path(),
                &values_for(&rescoped.policy, r#"{"gh":"rotated"}"#)
            ),
            "ok"
        );
        assert_eq!(send(dir.path(), r#"{"rollback":true}"#), "ok");
        assert_eq!(resolver_of(&live).lock().live["gh"].as_str(), "rotated");

        // A value sent for another variable does not serve the restored one.
        assert!(send(dir.path(), &bindings_message(&rescoped)).starts_with("ok"));
        let mut renamed = launch_in(dir.path(), &["gh=OTHER_TOKEN@github.com"], false);
        renamed.placeholders = launch.placeholders.clone();
        assert!(send(dir.path(), &bindings_message(&renamed)).starts_with("ok"));
        assert_eq!(
            send(
                dir.path(),
                &values_for(&renamed.policy, r#"{"gh":"for-other"}"#)
            ),
            "ok"
        );
        assert_eq!(send(dir.path(), r#"{"rollback":true}"#), "ok");
        assert_eq!(resolver_of(&live).lock().live["gh"].as_str(), "rotated");
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
            assert_eq!(
                send(
                    dir.path(),
                    &values_for(&launch.policy, r#"{"a":"va","b":"vb"}"#)
                ),
                "ok"
            );

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
            assert_eq!(
                send(dir.path(), &values_for(&next.policy, r#"{"c":"vc"}"#)),
                "ok"
            );
            assert_eq!(
                resolver
                    .resolve(&request("c", "api.c.com"))
                    .unwrap()
                    .as_str(),
                "vc"
            );
        }
    }

    /// Re-scoping a binding to other hosts or a header keeps its secret: the
    /// caller moved the same secret on purpose. Giving it another variable
    /// drops the secret it had (source and value), so the old one is never
    /// sent under the new definition; it resolves to nothing until a value
    /// is supplied. The placeholder stays either way.
    #[test]
    fn a_new_variable_drops_the_secret_and_new_hosts_keep_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("openai");
        std::fs::write(&path, "sk-openai").unwrap();
        let launch = launch_in(dir.path(), &["key=OPENAI_KEY@api.openai.com"], false);
        launch.ensure_ca().unwrap();
        let file = crate::secrets::file_ref(path);
        let (_interceptor, live) = launch
            .spawn_interceptor([("key".into(), file.clone())].into())
            .unwrap();
        live.clone().serve(dir.path());
        assert_eq!(
            send(
                dir.path(),
                &values_for(&launch.policy, r#"{"key":"sk-live"}"#)
            ),
            "ok"
        );

        let mut rescoped = launch_in(
            dir.path(),
            &["key=OPENAI_KEY@api.openai.com,eu.openai.com:set-header=authorization"],
            false,
        );
        rescoped.placeholders = launch.placeholders.clone();
        assert!(send(dir.path(), &bindings_message(&rescoped)).starts_with("ok"));
        let state = resolver_of(&live).lock().clone();
        assert_eq!(state.live.get("key").map(|v| v.as_str()), Some("sk-live"));
        assert_eq!(state.sources["key"], file, "the same secret, re-scoped");

        let mut renamed = launch_in(dir.path(), &["key=ANTHROPIC_KEY@api.anthropic.com"], false);
        renamed.placeholders = launch.placeholders.clone();
        assert!(send(dir.path(), &bindings_message(&renamed)).starts_with("ok"));
        let state = resolver_of(&live).lock().clone();
        assert!(
            state.live.is_empty(),
            "the value sent for the old variable is gone"
        );
        assert_eq!(
            state.sources["key"].from_env.as_deref(),
            Some("ANTHROPIC_KEY"),
            "the old file source is gone too"
        );
        assert_eq!(live.state.lock().unwrap().placeholders, launch.placeholders);
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
        assert_eq!(
            send(
                dir.path(),
                &values_for(&launch.policy, r#"{"gh":"ghp_cli"}"#)
            ),
            "ok"
        );

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
        assert_eq!(
            send(
                dir.path(),
                &values_for(&same.policy, r#"{"gh":"api-value"}"#)
            ),
            "ok"
        );
        // Back to the operator (the record cleared its supplied bindings and
        // the CLI added this one): the API caller's value is dropped too, and
        // the binding reads its own source again.
        let mut back = launch_in(dir.path(), &["gh=GH_TOKEN@github.com"], false);
        back.placeholders = launch.placeholders.clone();
        assert!(send(dir.path(), &bindings_message(&back)).starts_with("ok"));
        let state = resolver.lock().clone();
        assert!(
            state.live.is_empty(),
            "a value supplied by the API caller never serves the operator"
        );
        assert_eq!(state.sources["gh"].from_env.as_deref(), Some("GH_TOKEN"));
        // And a later API takeover of the operator's binding drops that again.
        assert_eq!(
            send(
                dir.path(),
                &values_for(&back.policy, r#"{"gh":"operator-pushed"}"#)
            ),
            "ok"
        );
        assert!(send(dir.path(), &bindings_message(&hijack)).starts_with("ok"));
        let state = resolver.lock().clone();
        assert!(state.live.is_empty() && state.sources.is_empty());
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
        assert_eq!(
            send(
                dir.path(),
                &values_for(&launch.policy, r#"{"a":"va","b":"vb"}"#)
            ),
            "ok"
        );
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
    /// rollback leaves it running with no binding, never stopped while the
    /// machine runs.
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
        assert_eq!(
            send(dir.path(), &values_for(&launch.policy, r#"{"a":"x"}"#)),
            "ok"
        );

        let published = slot.get().unwrap().addr;
        assert_eq!(send(dir.path(), r#"{"rollback":true}"#), "ok");
        assert_eq!(
            slot.get().map(|endpoint| endpoint.addr),
            Some(published),
            "the same interceptor stays published"
        );
        assert!(send(dir.path(), r#"{"values":{"a":"x"}}"#).contains("no credential binding 'a'"));
    }

    /// A machine with no bindings, sent none (a host settling it after a
    /// failed undo), takes them without starting an interceptor or making a
    /// CA, answers with no certificate, and can be rolled back.
    #[test]
    fn no_bindings_sent_to_a_machine_without_any_change_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let live = serve_unbound(dir.path());
        let none = launch_in(dir.path(), &[], false);
        let reply = send(dir.path(), &bindings_message(&none));
        let (ok, data) = reply.split_once('\n').expect("ok and the reply");
        assert_eq!(ok, "ok");
        let reply: BindingsReply = serde_json::from_str(data).unwrap();
        assert!(reply.ca_pem.is_empty());
        assert!(!dir.path().join("ca").exists(), "no CA made");
        assert!(live.state.lock().unwrap().running.is_none());
        assert_eq!(send(dir.path(), r#"{"rollback":true}"#), "ok");
        assert!(send(dir.path(), r#"{"rollback":true}"#).contains(NOTHING_TO_ROLL_BACK));
    }

    /// The first bindings of a machine that booted without any start an
    /// interceptor; if the change then fails (the guest cannot install the
    /// CA, say) after that interceptor already resolved a value, the
    /// rollback keeps it running with no binding, still published, instead of
    /// stopping it: a host the value went to stays intercepted and scrubbed,
    /// never relayed directly again.
    #[test]
    fn a_rollback_keeps_a_late_interceptor_that_already_resolved_a_value() {
        let dir = tempfile::tempdir().unwrap();
        let token = dir.path().join("token");
        std::fs::write(&token, "ghp_resolved").unwrap();
        let live = serve_unbound(dir.path());
        let slot = live.late.unwrap();
        let launch = launch_in(dir.path(), &["gh=GH_TOKEN@github.com"], false);
        let refs: BTreeMap<String, SecretRef> =
            [("GH_TOKEN".to_string(), crate::secrets::file_ref(token))].into();
        assert!(send(dir.path(), &bindings_message_with(&launch, refs)).starts_with("ok"));
        assert!(slot.get().is_some());
        // The interceptor resolves the value for a request to its host...
        let resolver = resolver_of(&live);
        assert_eq!(
            resolver
                .resolve(&request("gh", "github.com"))
                .unwrap()
                .as_str(),
            "ghp_resolved"
        );
        // ...and then the guest refuses the CA: the host rolls back.
        assert_eq!(send(dir.path(), r#"{"rollback":true}"#), "ok");
        assert!(slot.get().is_some(), "still published");
        let state = live.state.lock().unwrap();
        assert!(state.running.is_some(), "still running");
        assert!(state.policy.is_empty());
        drop(state);
        let after = resolver_of(&live).lock().clone();
        assert!(after.sources.is_empty() && after.live.is_empty());
        assert!(matches!(
            resolver.resolve(&request("gh", "github.com")),
            Err(ResolveError::Unknown)
        ));
        assert!(send(dir.path(), r#"{"values":{"gh":"x"}}"#).contains("no credential binding 'gh'"));
    }

    /// Wait until a resolution opens FIFO `fifo` to read it, then return the
    /// writing end, which holds that resolution mid-read until it is written
    /// and dropped.
    #[cfg(unix)]
    fn writer_once_read(fifo: &Path) -> std::fs::File {
        use std::os::unix::fs::OpenOptionsExt;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            // Refused (ENXIO) until a reader has the FIFO open.
            match std::fs::OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(fifo)
            {
                Ok(writer) => return writer,
                Err(e) if e.raw_os_error() == Some(libc::ENXIO) => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "nothing resolved the binding"
                    );
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(e) => panic!("open {}: {e}", fifo.display()),
            }
        }
    }

    /// Speak TLS through interceptor `endpoint` to `host` at `destination`,
    /// as the guest, trusting `ca_pem`, and return the raw response.
    #[cfg(unix)]
    fn guest_request(
        endpoint: smolvm_protocol::intercept::InterceptEndpoint,
        destination: std::net::SocketAddr,
        ca_pem: &str,
        host: &str,
        request: &str,
    ) -> std::io::Result<String> {
        use std::io::{Read, Write};
        let mut tcp = std::net::TcpStream::connect(endpoint.addr)?;
        tcp.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
        tcp.set_write_timeout(Some(std::time::Duration::from_secs(30)))?;
        tcp.write_all(&endpoint.preamble(destination))?;
        let mut verdict = [0xffu8; 1];
        tcp.read_exact(&mut verdict)?;
        assert_eq!(
            verdict[0], 0,
            "the interceptor could not reach the upstream"
        );
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut ca_pem.as_bytes()) {
            roots.add(cert?).map_err(std::io::Error::other)?;
        }
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(std::io::Error::other)?
        .with_root_certificates(roots)
        .with_no_client_auth();
        let name = rustls::pki_types::ServerName::try_from(host.to_string())
            .map_err(std::io::Error::other)?;
        let connection =
            rustls::ClientConnection::new(Arc::new(config), name).map_err(std::io::Error::other)?;
        let mut tls = rustls::StreamOwned::new(connection, tcp);
        tls.write_all(request.as_bytes())?;
        let mut out = Vec::new();
        // The interceptor may close without a TLS close_notify.
        let _ = tls.read_to_end(&mut out);
        Ok(String::from_utf8_lossy(&out).into_owned())
    }

    /// A rollback of a machine's first bindings never stops their
    /// interceptor, even one that has not resolved a value yet: a request may
    /// be resolving one at that moment. Here one is held mid-read of its
    /// source while the rollback runs. Released after it, the request injects
    /// nothing (its binding is gone), and the interceptor is still the one
    /// published, running with no binding. A host a value was resolved for
    /// before the rollback stays intercepted; one only the held request
    /// resolved for, after it, is relayed directly again, the value never
    /// having left this process.
    #[cfg(unix)]
    #[test]
    fn a_rollback_never_stops_a_late_interceptor_a_request_is_resolving_for() {
        use std::io::Write;
        // An upstream the interceptor reaches but cannot complete TLS with.
        let upstream = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let destination = upstream.local_addr().unwrap();
        std::thread::spawn(move || {
            for connection in upstream.incoming() {
                drop(connection);
            }
        });
        for resolved_before in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let fifo = dir.path().join("token");
            let path = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
            // SAFETY: a NUL-terminated path.
            assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
            let live = serve_unbound(dir.path());
            let slot = live.late.unwrap();
            let launch = launch_in(dir.path(), &["gh=GH_TOKEN@github.com"], false);
            let refs: BTreeMap<String, SecretRef> = [(
                "GH_TOKEN".to_string(),
                crate::secrets::file_ref(fifo.clone()),
            )]
            .into();
            let reply = send(dir.path(), &bindings_message_with(&launch, refs));
            let (ok, data) = reply.split_once('\n').expect("ok and the reply");
            assert_eq!(ok, "ok");
            let ca_pem = serde_json::from_str::<BindingsReply>(data).unwrap().ca_pem;
            let endpoint = slot.get().expect("published");
            let with_placeholder = format!(
                "GET / HTTP/1.1\r\nHost: github.com\r\nAuthorization: Bearer {}\r\n\
                 Connection: close\r\n\r\n",
                launch.placeholders["gh"]
            );
            let plain = "GET / HTTP/1.1\r\nHost: github.com\r\nConnection: close\r\n\r\n";

            if resolved_before {
                // A request resolves the value and sends it on (the upstream
                // then fails it) before the bindings change.
                let feeder = {
                    let fifo = fifo.clone();
                    std::thread::spawn(move || {
                        writer_once_read(&fifo)
                            .write_all(b"ghp_sentbefore")
                            .unwrap()
                    })
                };
                let sent = guest_request(
                    endpoint,
                    destination,
                    &ca_pem,
                    "github.com",
                    &with_placeholder,
                )
                .unwrap();
                feeder.join().unwrap();
                assert!(sent.starts_with("HTTP/1.1 502"), "{sent}");
            }

            // A request is held reading its value...
            let held = {
                let ca_pem = ca_pem.clone();
                let request = with_placeholder.clone();
                std::thread::spawn(move || {
                    guest_request(endpoint, destination, &ca_pem, "github.com", &request)
                })
            };
            let mut writer = writer_once_read(&fifo);
            // ...while the guest refuses the CA and the host rolls back.
            assert_eq!(send(dir.path(), r#"{"rollback":true}"#), "ok");
            assert_eq!(
                slot.get().map(|e| e.addr),
                Some(endpoint.addr),
                "the same interceptor stays published"
            );
            let state = live.state.lock().unwrap();
            assert!(state.running.is_some(), "still running");
            assert!(state.policy.is_empty());
            drop(state);
            let after = resolver_of(&live).lock().clone();
            assert!(after.sources.is_empty() && after.live.is_empty());

            // Released, the held request has its value and sends nothing.
            writer.write_all(b"ghp_resolvedlate").unwrap();
            drop(writer);
            let response = held.join().unwrap().unwrap();
            assert!(response.starts_with("HTTP/1.1 503"), "{response}");
            assert!(
                response.contains("changed during the request"),
                "{response}"
            );
            assert!(slot.get().is_some_and(|e| e.addr == endpoint.addr));

            let next = guest_request(endpoint, destination, &ca_pem, "github.com", plain);
            if resolved_before {
                // Terminated by the interceptor (its response would be
                // scrubbed of the value), which then fails to reach upstream.
                let next = next.unwrap();
                assert!(next.starts_with("HTTP/1.1 502"), "intercepted: {next}");
            } else {
                // Spliced to the upstream, which is not the machine CA.
                assert!(next.is_err(), "relayed directly: {next:?}");
            }
        }
    }

    /// A value is sent tagged with the binding it was read for, and refused
    /// when the boot process has another binding of that name by then.
    #[test]
    fn a_value_for_a_binding_replaced_meanwhile_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let launch = launch_in(dir.path(), &["gh=GH_TOKEN@github.com"], false);
        launch.ensure_ca().unwrap();
        let (_interceptor, live) = launch.spawn_interceptor(BTreeMap::new()).unwrap();
        live.clone().serve(dir.path());
        let expect_for = |spec: &str| {
            serde_json::json!({
                "values": {"gh": "operator-value"},
                "expect": {"gh": parse_credential_flag(spec).unwrap()},
            })
            .to_string()
        };
        assert_eq!(
            send(dir.path(), &expect_for("gh=GH_TOKEN@github.com")),
            "ok"
        );
        // An API caller rebinds gh before the operator's value arrives.
        let mut rebound = launch_in(dir.path(), &["gh=GH_TOKEN@attacker.example"], true);
        rebound.placeholders = launch.placeholders.clone();
        assert!(send(dir.path(), &bindings_message(&rebound)).starts_with("ok"));
        let refused = send(dir.path(), &expect_for("gh=GH_TOKEN@github.com"));
        assert!(
            refused.contains("changed since this value was read"),
            "{refused}"
        );
        assert!(resolver_of(&live).lock().live.is_empty());
    }

    /// The resolver never holds its lock while reading a source: a slow
    /// source (a FIFO here, a keychain helper in life) does not stall a
    /// binding change or any other request.
    #[cfg(unix)]
    #[test]
    fn a_slow_source_does_not_hold_the_resolver() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("slow");
        let path = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        // SAFETY: a NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        let resolver = Arc::new(SecretRefResolver::new(
            [("slow".to_string(), crate::secrets::file_ref(fifo.clone()))].into(),
        ));
        let reading = {
            let resolver = resolver.clone();
            std::thread::spawn(move || resolver.resolve(&request("slow", "api.slow.com")))
        };
        std::thread::sleep(std::time::Duration::from_millis(200));
        let free = resolver.state.try_lock().is_ok();
        // Unblock the reader whatever happened.
        std::fs::write(&fifo, "late-value").unwrap();
        let _ = reading.join();
        assert!(free, "the lock was free while the source was being read");
    }

    /// A replacement that fails leaves nothing to roll back to, so a host
    /// that rolls back after an error never restores an older state; and a
    /// rollback keeps values sent after the replacement for the bindings it
    /// restores that they were sent for.
    #[test]
    fn rollback_after_a_failed_replacement_restores_nothing_and_keeps_new_values() {
        let dir = tempfile::tempdir().unwrap();
        let launch = launch_in(dir.path(), &["a=A_KEY@api.a.com"], true);
        launch.ensure_ca().unwrap();
        let (_interceptor, live) = launch.spawn_interceptor(BTreeMap::new()).unwrap();
        live.clone().serve(dir.path());

        let mut more = launch_in(
            dir.path(),
            &["a=A_KEY@api.a.com", "b=B_KEY@api.b.com"],
            true,
        );
        more.placeholders
            .insert("a".into(), launch.placeholders["a"].clone());
        assert!(send(dir.path(), &bindings_message(&more)).starts_with("ok"));
        assert_eq!(
            send(
                dir.path(),
                &values_for(&more.policy, r#"{"a":"sent-after","b":"vb"}"#)
            ),
            "ok"
        );
        assert_eq!(send(dir.path(), r#"{"rollback":true}"#), "ok");
        let state = resolver_of(&live).lock().clone();
        assert_eq!(
            state.live.get("a").map(|v| v.as_str()),
            Some("sent-after"),
            "a value sent for a binding the rollback restores is kept"
        );
        assert!(!state.live.contains_key("b"));

        // A refused replacement (no placeholder) clears what an earlier one
        // could be rolled back to.
        assert!(send(dir.path(), &bindings_message(&more)).starts_with("ok"));
        let mut broken = more.clone();
        broken.placeholders.remove("b");
        assert!(send(dir.path(), &bindings_message(&broken)).starts_with("error:"));
        assert!(send(dir.path(), r#"{"rollback":true}"#).contains("no replaced bindings"));
        assert_eq!(live.state.lock().unwrap().policy, more.policy);
    }

    /// A machine serving its socket from boot without bindings.
    fn serve_unbound(dir: &Path) -> Arc<LiveCredentials> {
        let live = Arc::new(LiveCredentials {
            identity: CredentialIdentity {
                machine: "live-test".into(),
                ca_owner: "live-test".into(),
                ca_dir: dir.join("ca"),
            },
            late: Some(smolvm_network::LateHttpsIntercept::new()),
            state: Mutex::new(LiveState {
                policy: CredentialPolicy::default(),
                placeholders: BTreeMap::new(),
                supplied_only: false,
                running: None,
                previous: None,
                replaced: false,
            }),
        });
        live.clone().serve(dir);
        live
    }

    /// A binding the host operator adds while the machine runs resolves from
    /// the machine's own reference for its variable, as the record holds it
    /// when the binding is sent, so rotating that file keeps working; it
    /// never does on a supplied machine, whatever reference the message names.
    #[test]
    fn an_operator_binding_added_live_resolves_from_its_reference() {
        for supplied_only in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let token = dir.path().join("token");
            std::fs::write(&token, "first").unwrap();
            let live = serve_unbound(dir.path());
            let launch = launch_in(dir.path(), &["gh=GH_TOKEN@github.com"], supplied_only);
            let refs: BTreeMap<String, SecretRef> = [(
                "GH_TOKEN".to_string(),
                crate::secrets::file_ref(token.clone()),
            )]
            .into();
            assert!(send(dir.path(), &bindings_message_with(&launch, refs)).starts_with("ok"));
            let resolver = resolver_of(&live);
            let gh = request("gh", "github.com");
            if supplied_only {
                assert!(matches!(resolver.resolve(&gh), Err(ResolveError::Unknown)));
                continue;
            }
            assert_eq!(resolver.resolve(&gh).unwrap().as_str(), "first");
            std::fs::write(&token, "rotated").unwrap();
            assert_eq!(resolver.resolve(&gh).unwrap().as_str(), "rotated");
        }
    }

    /// A reference the record dropped since the machine booted (its binding
    /// was removed, taking it along) never feeds a binding added later in the
    /// same boot: the boot process reads only the references each change
    /// sends, never ones it was booted with.
    #[test]
    fn a_reference_the_record_dropped_never_feeds_a_later_binding() {
        let dir = tempfile::tempdir().unwrap();
        let token = dir.path().join("token");
        std::fs::write(&token, "operator-file").unwrap();
        let live = serve_unbound(dir.path());
        let launch = launch_in(dir.path(), &["gh=GH_TOKEN@github.com"], false);
        let refs: BTreeMap<String, SecretRef> =
            [("GH_TOKEN".to_string(), crate::secrets::file_ref(token))].into();
        assert!(send(dir.path(), &bindings_message_with(&launch, refs)).starts_with("ok"));
        let resolver = resolver_of(&live);
        let gh = request("gh", "github.com");
        assert_eq!(resolver.resolve(&gh).unwrap().as_str(), "operator-file");

        // Removed, and the record drops the file reference with it.
        let empty = launch_in(dir.path(), &[], false);
        assert!(send(dir.path(), &bindings_message(&empty)).starts_with("ok"));
        // Added again: the record has no reference, so neither does the
        // binding; it reads the boot process's variable of its name.
        assert!(send(dir.path(), &bindings_message(&launch)).starts_with("ok"));
        let state = resolver.lock().clone();
        assert_eq!(
            state.sources["gh"].from_env.as_deref(),
            Some("GH_TOKEN"),
            "the dropped file is not read: {:?}",
            state.sources["gh"]
        );
    }

    /// The bindings lock lives beside the machine's data directory, in the
    /// directory of all machines, never inside the directory the machine's
    /// user owns; and it is opened only as a regular file, never through a
    /// link or as a FIFO a start would hang on.
    #[test]
    fn the_bindings_lock_is_kept_out_of_the_machines_directory() {
        let path = bindings_lock_path("lock-placement");
        let data = crate::agent::vm_data_dir("lock-placement");
        assert_eq!(path.parent(), data.parent());
        assert!(!path.starts_with(&data));
        assert_eq!(bindings_lock_owner(&path), Some(data));
        assert_eq!(
            bindings_lock_owner(Path::new("/v/name.credentials.lock")),
            None
        );
        assert_eq!(
            bindings_lock_owner(Path::new("/v/0123456789abcdef.lock")),
            None
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_bindings_lock_refuses_links_and_fifos() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join("0123456789abcdef.credentials.lock");
        let held = lock_bindings_at(&lock).unwrap();
        let meta = std::fs::symlink_metadata(&lock).unwrap();
        assert!(meta.is_file());
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        drop(held);

        // A link to somewhere root could be made to create a file.
        std::fs::remove_file(&lock).unwrap();
        let target = dir.path().join("created-through-link");
        std::os::unix::fs::symlink(&target, &lock).unwrap();
        assert!(lock_bindings_at(&lock).is_err());
        assert!(!target.exists(), "nothing created through the link");

        // A FIFO: refused at once instead of blocking the open.
        std::fs::remove_file(&lock).unwrap();
        let c = std::ffi::CString::new(lock.to_str().unwrap()).unwrap();
        // SAFETY: a NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let refused = lock_bindings_at(&lock).unwrap_err();
        assert!(
            refused.to_string().contains("not a regular file"),
            "{refused}"
        );
    }

    /// A lock file swept away (its machine gone) between the open and the
    /// lock is not the lock: the locker takes the one the path names.
    #[cfg(unix)]
    #[test]
    fn a_swept_lock_file_is_never_held() {
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join("0123456789abcdef.credentials.lock");
        let first = open_lock_file(&lock).unwrap();
        std::fs::remove_file(&lock).unwrap();
        assert!(!still_named(&first, &lock));
        let held = lock_bindings_at(&lock).unwrap();
        assert!(still_named(&held, &lock));
    }

    /// A stand-in for a running machine's boot process, whose undo can be
    /// made to fail.
    #[derive(Default)]
    struct FakeBootProcess {
        calls: Mutex<Vec<&'static str>>,
        undo_fails: bool,
        /// Behaves like a change from no bindings to none: nothing is sent.
        sends_nothing: bool,
    }

    impl LiveBindings for FakeBootProcess {
        fn apply(
            &self,
            _name: &str,
            _before: &VmRecord,
            _next: &VmRecord,
        ) -> std::result::Result<LiveOutcome, BindingsError> {
            self.calls.lock().unwrap().push("apply");
            Ok(LiveOutcome {
                trusted: Some("new-ca-fingerprint".into()),
                sent: !self.sends_nothing,
            })
        }

        fn roll_back(&self, _name: &str) -> Result<()> {
            self.calls.lock().unwrap().push("roll_back");
            if self.undo_fails {
                return Err(Error::config("credentials", "the socket is gone"));
            }
            Ok(())
        }
    }

    fn test_db() -> (tempfile::TempDir, crate::db::SmolvmDb) {
        let dir = tempfile::tempdir().unwrap();
        let db = crate::db::SmolvmDb::open_at(&dir.path().join("state.db")).unwrap();
        (dir, db)
    }

    fn unique_machine(tag: &str) -> String {
        format!(
            "cred-{tag}-{}",
            crate::db::SmolvmDb::create_reservation_token()
        )
    }

    /// Replace `name`'s bindings with exactly `policy`, as `caller`.
    fn put(
        db: &crate::db::SmolvmDb,
        name: &str,
        policy: CredentialPolicy,
        caller: crate::machine_spec::Caller,
        live: &FakeBootProcess,
    ) -> std::result::Result<VmRecord, BindingsError> {
        set_bindings_with(
            db,
            name,
            caller,
            None,
            |_| Ok(policy),
            None,
            live,
            |_, _, _| Ok(()),
        )
    }

    /// A machine record in `db`: running (this process) or stopped.
    fn machine_in(db: &crate::db::SmolvmDb, tag: &str, running: bool) -> (String, VmRecord) {
        let name = unique_machine(tag);
        let mut record = VmRecord::new(name.clone(), 1, 512, vec![], vec![], true);
        if running {
            record.state = crate::config::RecordState::Running;
            record.pid = Some(std::process::id() as i32);
            record.pid_start_time = None;
        }
        db.insert_vm(&name, &record).unwrap();
        (name, record)
    }

    /// When what runs after the change fails (the CLI handing a running
    /// machine its values), the change is undone: the record and the boot
    /// process are back to the bindings they had, so the failed command has
    /// changed nothing. Supplied values are kept for the bindings restored.
    #[test]
    fn a_failure_after_the_change_undoes_it() {
        use crate::machine_spec::Caller;
        let (_dir, db) = test_db();
        for running in [true, false] {
            let (name, mut record) = machine_in(
                &db,
                if running {
                    "then-running"
                } else {
                    "then-stopped"
                },
                running,
            );
            record.secret_refs.insert(
                "GH_TOKEN".into(),
                crate::secrets::file_ref("/operator/gh-token"),
            );
            db.insert_vm(&name, &record).unwrap();
            let first = bindings_of(&["gh=GH_TOKEN@github.com"]);
            let fake = FakeBootProcess::default();
            let bound = put(&db, &name, first.clone(), Caller::Cli, &fake).unwrap();
            assert_eq!(bound.credential_policy.as_ref(), Some(&first));
            supply_values(
                &name,
                [("gh".to_string(), zeroize::Zeroizing::new("v".to_string()))].into(),
                &first,
                &bound.credential_placeholders,
            );

            let fake = FakeBootProcess::default();
            let failed = set_bindings_with(
                &db,
                &name,
                Caller::Cli,
                Some(&Default::default()),
                |_| Ok(CredentialPolicy::default()),
                None,
                &fake,
                |_, saved, _| {
                    assert!(saved.credential_policy.is_none(), "runs after the change");
                    Err(Error::config("credentials", "could not hand over values"))
                },
            );
            assert!(matches!(failed, Err(BindingsError::Conflict(_))));
            let after = db.get_vm(&name).unwrap().unwrap();
            assert_eq!(after.credential_policy.as_ref(), Some(&first));
            assert_eq!(after.credential_placeholders, bound.credential_placeholders);
            assert!(!after.credential_bindings_unsettled);
            assert!(
                after.secret_refs.contains_key("GH_TOKEN"),
                "the reference the removal would have dropped is back"
            );
            assert_eq!(
                *fake.calls.lock().unwrap(),
                if running {
                    vec!["apply", "roll_back"]
                } else {
                    vec![]
                }
            );
            assert!(
                SUPPLIED
                    .lock()
                    .unwrap()
                    .get(&name)
                    .is_some_and(|v| v.contains_key("gh")),
                "a value for a binding that stays is kept"
            );
            forget_values(&name);
            db.remove_vm(&name).unwrap();
        }
    }

    /// An undo that fails is reported as such, not as a plain conflict: the
    /// error says the machine may be inconsistent and how to recover, the
    /// record says so too, and the next change, even one that leaves the
    /// record as it is, reaches the machine and settles it.
    #[test]
    fn a_failed_undo_is_reported_and_the_next_change_settles_it() {
        use crate::machine_spec::Caller;
        let (_dir, db) = test_db();
        let (name, _) = machine_in(&db, "unsettled", true);
        let broken = FakeBootProcess {
            undo_fails: true,
            ..Default::default()
        };
        let failed = set_bindings_with(
            &db,
            &name,
            Caller::Cli,
            Some(&["gh".to_string()].into()),
            |_| Ok(bindings_of(&["gh=GH_TOKEN@github.com"])),
            None,
            &broken,
            |_, _, _| Err(Error::config("credentials", "could not hand over values")),
        );
        let Err(BindingsError::Unsettled(error)) = failed else {
            panic!("expected an unsettled error, got {failed:?}");
        };
        let message = error.to_string();
        assert!(message.contains("could not hand over values"), "{message}");
        assert!(message.contains("the socket is gone"), "{message}");
        assert!(
            message.contains("may now hold different bindings"),
            "{message}"
        );
        assert!(message.contains("--credential"), "{message}");
        let record = db.get_vm(&name).unwrap().unwrap();
        assert!(record.credential_bindings_unsettled);
        assert_eq!(record.credential_policy, None, "the record was restored");

        // Setting what the record already holds (nothing) still reaches the
        // machine, and settles it.
        let live = FakeBootProcess::default();
        let settled = put(&db, &name, CredentialPolicy::default(), Caller::Api, &live).unwrap();
        assert_eq!(*live.calls.lock().unwrap(), vec!["apply"]);
        assert!(!settled.credential_bindings_unsettled);
        assert!(
            !db.get_vm(&name)
                .unwrap()
                .unwrap()
                .credential_bindings_unsettled
        );
        db.remove_vm(&name).unwrap();
    }

    /// Nothing to nothing reaches the boot process only while the record is
    /// unsettled and the boot process serves its socket.
    #[test]
    fn an_unsettled_machine_is_sent_even_an_unchanged_set() {
        let mut before = VmRecord::new("settle".into(), 1, 512, vec![], vec![], true);
        let none = before.clone();
        assert!(!reaches_boot_process(&before, &none, || true));
        before.credential_bindings_unsettled = true;
        assert!(reaches_boot_process(&before, &none, || true));
        assert!(!reaches_boot_process(&before, &none, || false));
        let mut bound = none.clone();
        bound.credential_policy = Some(bindings_of(&["a=A@api.a.com"]));
        assert!(reaches_boot_process(&none, &bound, || false));
        assert!(reaches_boot_process(&bound, &none, || false));
    }

    /// The CLI builds its change from the record under the change's lock:
    /// a binding someone revoked while the command was starting stays
    /// revoked, and one an API caller set stays theirs.
    #[test]
    fn the_cli_edits_the_record_as_the_lock_finds_it() {
        use crate::machine_spec::Caller;
        let (_dir, db) = test_db();
        let (name, _) = machine_in(&db, "cli-edit", false);
        let live = FakeBootProcess::default();
        put(
            &db,
            &name,
            bindings_of(&["a=A_KEY@api.a.com", "b=B_KEY@api.b.com"]),
            Caller::Cli,
            &live,
        )
        .unwrap();
        // The CLI read the record here, then someone revoked `b`.
        let stale = db.get_vm(&name).unwrap().unwrap();
        put(
            &db,
            &name,
            bindings_of(&["a=A_KEY@api.a.com"]),
            Caller::Cli,
            &live,
        )
        .unwrap();
        let edited = set_bindings_with(
            &db,
            &name,
            Caller::Cli,
            Some(&["c".to_string()].into()),
            |locked| {
                assert_ne!(locked.credential_policy, stale.credential_policy);
                let mut policy = locked.credential_policy.clone().unwrap_or_default();
                policy
                    .credentials
                    .push(parse_credential_flag("c=C_KEY@api.c.com").unwrap());
                Ok(policy)
            },
            None,
            &live,
            |_, _, _| Ok(()),
        )
        .unwrap();
        let names: Vec<&str> = edited
            .credential_policy
            .iter()
            .flat_map(|p| p.credentials.iter().map(|b| b.name.as_str()))
            .collect();
        assert_eq!(names, ["a", "c"], "the revoked binding does not come back");
        db.remove_vm(&name).unwrap();
    }

    /// The race the lock closes, replayed with the CLI's stale view: an API
    /// caller sets `evil` to read `AWS_SECRET_ACCESS_KEY` for its own host,
    /// then clears every binding, which makes the machine's values come from
    /// this host again. A CLI command that names only `gh` but carries
    /// `evil` from an earlier read is refused, and nothing changes: no
    /// binding the operator did not name ever reads this host's values.
    #[test]
    fn a_binding_the_operator_did_not_name_never_reads_this_host() {
        use crate::machine_spec::Caller;
        let (_dir, db) = test_db();
        let (name, _) = machine_in(&db, "unnamed", false);
        let live = FakeBootProcess::default();
        let evil = "evil=AWS_SECRET_ACCESS_KEY@attacker.example";
        put(&db, &name, bindings_of(&[evil]), Caller::Api, &live).unwrap();
        let stale = db.get_vm(&name).unwrap().unwrap();
        assert!(stale.credentials_supplied_by_api);
        put(&db, &name, CredentialPolicy::default(), Caller::Api, &live).unwrap();
        assert!(
            !db.get_vm(&name)
                .unwrap()
                .unwrap()
                .credentials_supplied_by_api
        );

        let refused = set_bindings_with(
            &db,
            &name,
            Caller::Cli,
            Some(&["gh".to_string()].into()),
            |_| Ok(bindings_of(&[evil, "gh=GH_TOKEN@github.com"])),
            None,
            &live,
            |_, _, _| panic!("nothing runs after a refused change"),
        );
        let Err(BindingsError::Conflict(error)) = refused else {
            panic!("expected a conflict, got {refused:?}");
        };
        assert!(error.to_string().contains("'evil'"), "{error}");
        assert_eq!(db.get_vm(&name).unwrap().unwrap().credential_policy, None);

        // Named, it is the operator's own binding.
        let named = set_bindings_with(
            &db,
            &name,
            Caller::Cli,
            Some(&["evil".to_string(), "gh".to_string()].into()),
            |_| Ok(bindings_of(&[evil, "gh=GH_TOKEN@github.com"])),
            None,
            &live,
            |_, _, _| Ok(()),
        )
        .unwrap();
        assert!(!named.credentials_supplied_by_api);
        // A host-sourced binding left as it was needs no naming again.
        set_bindings_with(
            &db,
            &name,
            Caller::Cli,
            Some(&Default::default()),
            |locked| Ok(locked.credential_policy.clone().unwrap_or_default()),
            None,
            &live,
            |_, _, _| Ok(()),
        )
        .unwrap();
        db.remove_vm(&name).unwrap();
    }

    /// A change from no bindings to none sends nothing to the boot process,
    /// so a failure after it undoes nothing there and is a plain conflict,
    /// never reported as unsettled.
    #[test]
    fn nothing_sent_means_nothing_to_undo() {
        use crate::machine_spec::Caller;
        let (_dir, db) = test_db();
        let (name, _) = machine_in(&db, "nothing-sent", true);
        let live = FakeBootProcess {
            undo_fails: true,
            sends_nothing: true,
            ..Default::default()
        };
        let failed = set_bindings_with(
            &db,
            &name,
            Caller::Cli,
            Some(&Default::default()),
            |_| Ok(CredentialPolicy::default()),
            None,
            &live,
            |_, _, _| Err(Error::config("credentials", "then failed")),
        );
        assert!(
            matches!(failed, Err(BindingsError::Conflict(_))),
            "{failed:?}"
        );
        assert_eq!(*live.calls.lock().unwrap(), vec!["apply"], "no undo sent");
        assert!(
            !db.get_vm(&name)
                .unwrap()
                .unwrap()
                .credential_bindings_unsettled
        );
        db.remove_vm(&name).unwrap();
    }

    /// A binding the CLI names on a machine whose values are supplied would
    /// never get one: refused, saying where values come from; removing
    /// bindings there still works.
    #[test]
    fn the_cli_cannot_add_a_binding_no_value_would_reach() {
        use crate::machine_spec::Caller;
        let (_dir, db) = test_db();
        let (name, _) = machine_in(&db, "supplied", false);
        let live = FakeBootProcess::default();
        put(
            &db,
            &name,
            bindings_of(&["a=A_KEY@api.a.com", "b=B_KEY@api.b.com"]),
            Caller::Api,
            &live,
        )
        .unwrap();
        let refused = set_bindings_with(
            &db,
            &name,
            Caller::Cli,
            Some(&["gh".to_string()].into()),
            |locked| {
                let mut policy = locked.credential_policy.clone().unwrap_or_default();
                policy
                    .credentials
                    .push(parse_credential_flag("gh=GH_TOKEN@github.com").unwrap());
                Ok(policy)
            },
            None,
            &live,
            |_, _, _| Ok(()),
        );
        let Err(BindingsError::Conflict(error)) = refused else {
            panic!("expected a conflict, got {refused:?}");
        };
        assert!(error.to_string().contains("credential-values"), "{error}");
        assert!(error.to_string().contains("'gh'"), "{error}");
        let removed = set_bindings_with(
            &db,
            &name,
            Caller::Cli,
            Some(&Default::default()),
            |_| Ok(bindings_of(&["a=A_KEY@api.a.com"])),
            None,
            &live,
            |_, _, _| Ok(()),
        )
        .unwrap();
        assert!(removed.credentials_supplied_by_api);
        db.remove_vm(&name).unwrap();
    }

    /// Other settings changed beside the bindings land in the same write,
    /// the bindings checked against them; work before the write that fails
    /// (growing a disk) leaves the record exactly as it was.
    #[test]
    fn other_settings_and_bindings_land_together_or_not_at_all() {
        use crate::machine_spec::Caller;
        let (_dir, db) = test_db();
        let (name, mut record) = machine_in(&db, "together", false);
        record.network = false;
        db.insert_vm(&name, &record).unwrap();
        let live = FakeBootProcess::default();
        let turn_on = |r: &mut VmRecord, _: &CredentialPolicy| -> Result<()> {
            r.network = true;
            r.cpus = 3;
            Ok(())
        };
        let failed = set_bindings_with(
            &db,
            &name,
            Caller::Cli,
            Some(&["gh".to_string()].into()),
            |_| Ok(bindings_of(&["gh=GH_TOKEN@github.com"])),
            Some(OtherSettings {
                apply: &turn_on,
                prepare: Box::new(|_| Err(Error::config("resize", "disk is busy"))),
            }),
            &live,
            |_, _, _| Ok(()),
        );
        assert!(
            matches!(failed, Err(BindingsError::Failed(_))),
            "{failed:?}"
        );
        let unchanged = db.get_vm(&name).unwrap().unwrap();
        assert!(unchanged.credential_policy.is_none() && !unchanged.network);
        assert_eq!(unchanged.cpus, record.cpus);

        let saved = set_bindings_with(
            &db,
            &name,
            Caller::Cli,
            Some(&["gh".to_string()].into()),
            |_| Ok(bindings_of(&["gh=GH_TOKEN@github.com"])),
            Some(OtherSettings {
                apply: &turn_on,
                prepare: Box::new(|next| {
                    assert!(next.network, "checked against the settings");
                    Ok(())
                }),
            }),
            &live,
            |_, _, _| Ok(()),
        )
        .unwrap();
        assert!(saved.network && saved.cpus == 3 && saved.credential_policy.is_some());
        db.remove_vm(&name).unwrap();
    }

    /// A setting that applied to the record as the lock found it but no
    /// longer applies to the record the write finds refuses the write: the
    /// bindings are not written without it, and the error is reported.
    #[test]
    fn a_setting_refused_in_the_write_writes_nothing() {
        use crate::machine_spec::Caller;
        let (_dir, db) = test_db();
        let (name, record) = machine_in(&db, "write-refused", false);
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let apply = |r: &mut VmRecord, _: &CredentialPolicy| -> Result<()> {
            if calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) > 0 {
                return Err(Error::config("update", "the allow list changed meanwhile"));
            }
            r.cpus = 3;
            Ok(())
        };
        let live = FakeBootProcess::default();
        let refused = set_bindings_with(
            &db,
            &name,
            Caller::Cli,
            Some(&["gh".to_string()].into()),
            |_| Ok(bindings_of(&["gh=GH_TOKEN@github.com"])),
            Some(OtherSettings {
                apply: &apply,
                prepare: Box::new(|_| panic!("disks never grow for a refused write")),
            }),
            &live,
            |_, _, _| panic!("nothing runs after a refused write"),
        );
        let Err(BindingsError::Failed(error)) = refused else {
            panic!("expected the write to fail, got {refused:?}");
        };
        assert!(error.to_string().contains("changed meanwhile"), "{error}");
        let after = db.get_vm(&name).unwrap().unwrap();
        assert!(after.credential_policy.is_none());
        assert_eq!(after.cpus, record.cpus);
        db.remove_vm(&name).unwrap();
    }

    /// Bindings of a machine that does not exist are refused before anything
    /// is created for it: no data directory, no lock.
    #[test]
    fn bindings_for_an_unknown_machine_create_nothing() {
        use crate::machine_spec::Caller;
        let (_dir, db) = test_db();
        let name = unique_machine("unknown");
        let fake = FakeBootProcess::default();
        let refused = put(
            &db,
            &name,
            bindings_of(&["gh=GH_TOKEN@github.com"]),
            Caller::Api,
            &fake,
        );
        assert!(matches!(refused, Err(BindingsError::Failed(_))));
        assert!(!crate::agent::vm_data_dir(&name).exists());
        assert!(!bindings_lock_path(&name).exists());
    }

    /// Deleting a machine's record removes its bindings lock, unless someone
    /// holds it (then the sweep of orphaned locks takes it later).
    #[test]
    fn deleting_a_machine_removes_its_bindings_lock() {
        let (_dir, db) = test_db();
        let (name, _) = machine_in(&db, "delete-lock", false);
        drop(lock_bindings(&name).unwrap());
        assert!(bindings_lock_path(&name).exists());
        db.remove_vm(&name).unwrap();
        assert!(!bindings_lock_path(&name).exists());

        let (name, _) = machine_in(&db, "delete-held", false);
        let held = lock_bindings(&name).unwrap();
        // Another process's view: flock conflicts across descriptions.
        remove_bindings_lock(&name);
        assert!(bindings_lock_path(&name).exists(), "a held lock stays");
        drop(held);
        db.remove_vm(&name).unwrap();
        assert!(!bindings_lock_path(&name).exists());
    }

    fn bindings_of(specs: &[&str]) -> CredentialPolicy {
        CredentialPolicy {
            credentials: specs
                .iter()
                .map(|spec| parse_credential_flag(spec).unwrap())
                .collect(),
        }
    }

    /// The host loads a CA without following links: a key, name or
    /// certificate the directory's owner linked elsewhere is refused.
    #[cfg(unix)]
    #[test]
    fn the_host_loads_the_ca_without_following_links() {
        let dir = tempfile::tempdir().unwrap();
        let ca_dir = dir.path().join("credentials");
        let ca = MachineCa::generate("m", &["api.a.com".to_string()]).unwrap();
        ca.save(&ca_dir).unwrap();
        assert_eq!(
            load_ca(&ca_dir, "m").unwrap().certificate_pem(),
            ca.certificate_pem()
        );
        let elsewhere = tempfile::tempdir().unwrap();
        let foreign = MachineCa::generate("host", &["h.com".to_string()]).unwrap();
        foreign.save(elsewhere.path()).unwrap();
        for file in ["ca.key", "ca.name", "ca.pem"] {
            let fresh = dir.path().join(format!("fresh-{file}"));
            ca.save(&fresh).unwrap();
            std::fs::remove_file(fresh.join(file)).unwrap();
            std::os::unix::fs::symlink(elsewhere.path().join(file), fresh.join(file)).unwrap();
            assert!(load_ca(&fresh, "m").is_err(), "{file} linked elsewhere");
        }
        // The directory itself linked elsewhere is refused too.
        let linked = dir.path().join("linked");
        std::os::unix::fs::symlink(elsewhere.path(), &linked).unwrap();
        assert!(load_ca(&linked, "m").is_err());
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

    /// Fixed placeholders, so values held for a binding can be told apart.
    fn fixed_placeholders(names: &[&str]) -> BTreeMap<String, String> {
        names
            .iter()
            .map(|n| {
                (
                    n.to_string(),
                    format!("SMOL_PLACEHOLDER_{}_1", n.to_uppercase()),
                )
            })
            .collect()
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
            &fixed_placeholders(&["a", "b"]),
            &BTreeMap::new(),
            None,
        )
        .unwrap();
        launch.supplied_only = supplied_only;
        launch
    }

    fn supply(machine: &str, launch: &CredentialLaunch, values: &[(&str, &str)]) {
        supply_values(
            machine,
            values
                .iter()
                .map(|(k, v)| (k.to_string(), zeroize::Zeroizing::new(v.to_string())))
                .collect(),
            &launch.policy,
            &launch.placeholders,
        );
    }

    #[test]
    fn supplied_values_reach_only_the_boot_process() {
        let machine = "cred-test-supplied";
        let template = launch(machine, false);
        supply(machine, &template, &[("a", "value-a")]);
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
        let template = launch(machine, true);
        supply(machine, &template, &[("a", "va"), ("b", "vb")]);
        retain_values(
            machine,
            &CredentialPolicy {
                credentials: vec![parse_credential_flag("b=B_KEY@api.b.com").unwrap()],
            },
            &fixed_placeholders(&["b"]),
        );
        let mut l = launch(machine, true);
        let env = l.child_env();
        assert_eq!(env[0].1, None, "a's value is gone");
        assert_eq!(env[1].1.as_deref().map(String::as_str), Some("vb"));
        retain_values(machine, &CredentialPolicy::default(), &BTreeMap::new());
        assert!(launch(machine, true)
            .child_env()
            .iter()
            .all(|(_, v)| v.is_none()));
    }

    /// A held value serves only the binding it was supplied for: after a
    /// stop and start, a name bound to another variable, or removed and
    /// added again (a new placeholder), gets nothing; new hosts keep it.
    #[test]
    fn a_held_value_serves_only_the_binding_it_was_supplied_for() {
        let machine = "cred-test-held";
        let template = launch(machine, true);
        supply(machine, &template, &[("a", "va")]);
        let boot = |spec: &str, placeholder: &str| {
            let policy = CredentialPolicy {
                credentials: vec![parse_credential_flag(spec).unwrap()],
            };
            let placeholders: BTreeMap<String, String> =
                [("a".to_string(), placeholder.to_string())].into();
            let mut l = CredentialLaunch::from_parts(
                machine,
                &policy,
                &placeholders,
                &BTreeMap::new(),
                None,
            )
            .unwrap();
            l.supplied_only = true;
            l.child_env().remove(0).1.map(|v| v.to_string())
        };
        assert_eq!(
            boot("a=A_KEY@api.a.com", "SMOL_PLACEHOLDER_A_1").as_deref(),
            Some("va")
        );
        assert_eq!(
            boot("a=A_KEY@other.a.com", "SMOL_PLACEHOLDER_A_1").as_deref(),
            Some("va"),
            "re-scoped to other hosts: the same secret"
        );
        assert_eq!(
            boot("a=OTHER_KEY@api.a.com", "SMOL_PLACEHOLDER_A_1"),
            None,
            "another variable"
        );
        assert_eq!(
            boot("a=A_KEY@api.a.com", "SMOL_PLACEHOLDER_A_2"),
            None,
            "removed and re-added"
        );
        // Pruned once the record says so.
        retain_values(
            machine,
            &CredentialPolicy {
                credentials: vec![parse_credential_flag("a=OTHER_KEY@api.a.com").unwrap()],
            },
            &fixed_placeholders(&["a"]),
        );
        assert!(SUPPLIED.lock().unwrap().get(machine).is_none());
        forget_values(machine);
    }

    #[test]
    fn a_branch_uses_its_goldens_values_until_given_its_own() {
        let golden = "cred-test-golden";
        let clone = "cred-test-golden-branch";
        let policy = CredentialPolicy {
            credentials: vec![parse_credential_flag("a=A_KEY@api.a.com").unwrap()],
        };
        let placeholders = fixed_placeholders(&["a"]);
        let held = |value: &str| -> BTreeMap<String, zeroize::Zeroizing<String>> {
            [("a".to_string(), zeroize::Zeroizing::new(value.to_string()))].into()
        };
        supply_values(golden, held("golden-a"), &policy, &placeholders);
        let mut l = CredentialLaunch::from_parts(
            clone,
            &policy,
            &placeholders,
            &BTreeMap::new(),
            Some(golden),
        )
        .unwrap();
        l.supplied_only = true;
        let env = l.child_env();
        assert_eq!(env[0].1.as_deref().map(String::as_str), Some("golden-a"));
        // A branch whose binding was re-added (a new placeholder) or bound to
        // another variable never falls back to the golden's value.
        let mut readded = CredentialLaunch::from_parts(
            clone,
            &policy,
            &[("a".to_string(), "SMOL_PLACEHOLDER_A_9".to_string())].into(),
            &BTreeMap::new(),
            Some(golden),
        )
        .unwrap();
        readded.supplied_only = true;
        assert_eq!(readded.child_env()[0].1, None);
        let rebound = CredentialPolicy {
            credentials: vec![parse_credential_flag("a=OTHER@api.a.com").unwrap()],
        };
        let mut rebound = CredentialLaunch::from_parts(
            clone,
            &rebound,
            &placeholders,
            &BTreeMap::new(),
            Some(golden),
        )
        .unwrap();
        rebound.supplied_only = true;
        assert_eq!(rebound.child_env()[0].1, None);

        supply_values(clone, held("branch-a"), &policy, &placeholders);
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
