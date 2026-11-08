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

/// Values handed to a running boot process through [`CREDENTIALS_SOCKET`], by
/// binding name. A binding with one resolves to it instead of its reference.
type LiveValues = Arc<Mutex<BTreeMap<String, zeroize::Zeroizing<String>>>>;

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

    /// The DNS subtrees the policy's hosts live in: a wildcard's parent is
    /// the subtree the CA may sign in, and the name constraint on it already
    /// covers every subdomain.
    fn host_subtrees(&self) -> Vec<String> {
        self.policy
            .credentials
            .iter()
            .flat_map(|binding| binding.allowed_hosts.iter())
            .map(|host| smolvm_protocol::credentials::host_subtree(host).to_string())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    /// Create the lineage's CA on first use, or widen it to every host the
    /// policy names. Returns whether the certificate changed, in which case a
    /// running guest must be handed the new one. Called by the launcher before
    /// the guest CA directory is mounted, and before bindings are replaced on
    /// a running machine.
    ///
    /// Widening keeps the key, so leaves stay valid for processes that loaded
    /// the earlier certificate, and never narrows: branches share the CA, and
    /// a host a sibling still uses must stay permitted.
    pub fn ensure_ca(&self) -> Result<bool> {
        fn fail(e: impl std::fmt::Display) -> Error {
            Error::config("credentials", format!("machine CA: {e:#}"))
        }
        // The common case reads only: a boot whose CA already covers its
        // hosts writes nothing (a confined boot process may only read it).
        if self.ca_covers_policy()? {
            return Ok(false);
        }
        std::fs::create_dir_all(&self.ca_dir)
            .map_err(|e| Error::config("credentials", format!("machine CA: {e}")))?;
        // Branches of one lineage may widen the shared CA at once.
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(self.ca_dir.join("ca.lock"))
            .map_err(|e| Error::config("credentials", format!("machine CA lock: {e}")))?;
        crate::agent::fork::lock_file_exclusive(&lock)
            .map_err(|e| Error::config("credentials", format!("machine CA lock: {e}")))?;
        let hosts = self.host_subtrees();
        if !MachineCa::exists(&self.ca_dir) {
            let hosts = if hosts.is_empty() {
                vec![NO_CREDENTIAL_HOST.to_string()]
            } else {
                hosts
            };
            MachineCa::generate(&self.ca_owner, &hosts)
                .and_then(|ca| ca.save(&self.ca_dir))
                .map_err(fail)?;
            return Ok(true);
        }
        let ca = MachineCa::load(&self.ca_dir, &self.ca_owner).map_err(fail)?;
        match ca.widened(&hosts).map_err(fail)? {
            Some(wider) => {
                wider.save(&self.ca_dir).map_err(fail)?;
                tracing::info!(machine = %self.machine, ca_owner = %self.ca_owner, "credential CA widened to new hosts");
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Whether the lineage's CA exists and already permits every host the
    /// policy names, so the guest's trust needs no change.
    pub fn ca_covers_policy(&self) -> Result<bool> {
        if !MachineCa::exists(&self.ca_dir) {
            return Ok(false);
        }
        MachineCa::load(&self.ca_dir, &self.ca_owner)
            .and_then(|ca| ca.widened(&self.host_subtrees()))
            .map(|wider| wider.is_none())
            .map_err(|e| Error::config("credentials", format!("machine CA: {e:#}")))
    }

    /// SHA-256 (hex) of a CA certificate PEM, as
    /// [`VmRecord::credential_ca_trusted`] keeps it.
    pub fn ca_fingerprint(pem: &str) -> String {
        use sha2::Digest;
        hex::encode(sha2::Sha256::digest(pem.as_bytes()))
    }

    /// The CA certificate the guest trusts, PEM.
    pub fn ca_certificate_pem(&self) -> Result<String> {
        MachineCa::load(&self.ca_dir, &self.ca_owner)
            .map(|ca| ca.certificate_pem().to_string())
            .map_err(|e| Error::config("credentials", format!("load machine CA: {e:#}")))
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
        let resolver = Arc::new(SecretRefResolver {
            sources: Arc::new(Mutex::new(sources)),
            live: LiveValues::default(),
        });
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
            state: Mutex::new(LiveState {
                running: Some(Running {
                    control: interceptor.control(),
                    resolver,
                    ca_dir: self.ca_dir.clone(),
                    supplied_only: self.supplied_only,
                    _owned: None,
                }),
                policy: self.policy.clone(),
            }),
            late: None,
        });
        Ok((interceptor, live))
    }
}

/// Serve [`CREDENTIALS_SOCKET`] in `vm_dir` for a machine that booted without
/// bindings on a network whose HTTPS flows can be redirected after boot: the
/// first bindings sent start the interceptor and publish it in `slot`.
pub fn serve_without_bindings(vm_dir: &Path, slot: smolvm_network::LateHttpsIntercept) {
    Arc::new(LiveCredentials {
        state: Mutex::new(LiveState {
            running: None,
            policy: CredentialPolicy::default(),
        }),
        late: Some(slot),
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
    let saved = db.update_vm(name, |r| {
        r.take_credential_bindings(&next);
        r.network = next.network;
    });
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
                revert_live_bindings(name, &record, &next);
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
/// `before`.
///
/// The CA is created or widened first, so it covers every new host. The
/// boot process then swaps policy and placeholders in its interceptor in one
/// step (starting the interceptor when the machine booted without bindings),
/// and, when the CA is new to the guest or now covers more, the guest agent
/// installs it in the machine root and every workload container. A guest
/// that cannot take the CA is refused before anything changes.
///
/// Returns the fingerprint of the CA the guest was handed, when it was.
pub fn apply_live_bindings(
    name: &str,
    before: &VmRecord,
    next: &VmRecord,
) -> std::result::Result<Option<String>, BindingsError> {
    before
        .check_live_credentials(next)
        .map_err(BindingsError::Conflict)?;
    let Some(launch) = CredentialLaunch::for_record(name, next) else {
        return Ok(None);
    };
    let trust_needed = before.credential_policy.is_none()
        || !launch.ca_covers_policy().map_err(BindingsError::Failed)?;
    if trust_needed
        && !crate::agent::supports_live_credential_trust(name).map_err(BindingsError::Conflict)?
    {
        return Err(BindingsError::Conflict(Error::config(
            "credentials",
            format!(
                "machine '{name}' runs a guest agent that cannot take a credential CA while it \
                 runs, which bindings for new hosts need; restart it to apply them"
            ),
        )));
    }
    launch.ensure_ca().map_err(BindingsError::Failed)?;
    crate::agent::apply_live_credential_policy(name, &launch).map_err(BindingsError::Conflict)?;
    if !trust_needed {
        return Ok(None);
    }
    let installed = launch.ca_certificate_pem().and_then(|pem| {
        crate::agent::install_live_credential_trust(name, &pem)
            .map(|()| CredentialLaunch::ca_fingerprint(&pem))
    });
    match installed {
        Ok(fingerprint) => Ok(Some(fingerprint)),
        Err(error) => {
            revert_live_bindings(name, before, next);
            Err(BindingsError::Conflict(error))
        }
    }
}

/// Put `before`'s bindings back on running machine `name` after applying
/// `next`'s failed further on. Best effort: the error that caused it is what
/// the caller reports.
fn revert_live_bindings(name: &str, before: &VmRecord, next: &VmRecord) {
    let previous = CredentialLaunch::for_record(name, before).or_else(|| {
        // It booted without bindings: an interceptor with none splices
        // everything through.
        let mut empty = CredentialLaunch::for_record(name, next)?;
        empty.policy = CredentialPolicy::default();
        empty.placeholders.clear();
        Some(empty)
    });
    if let Some(previous) = previous {
        if let Err(error) = crate::agent::apply_live_credential_policy(name, &previous) {
            tracing::warn!(machine = name, %error, "could not restore the previous credential bindings");
        }
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

/// The credentials a running boot process enforces, as its
/// [`CREDENTIALS_SOCKET`] changes them.
///
/// Each connection to the socket sends one JSON object and reads back `ok` or
/// `error: <reason>`:
///
/// - `{"values":{"<binding>":"<value>",…}}` replaces the values the machine
///   resolves for the bindings named, from its next request on. A name that is
///   not a current binding refuses the whole message.
/// - `{"launch":<CredentialLaunch>}` replaces the bindings: the policy and
///   placeholders are swapped in the interceptor as one value, a binding no
///   longer present stops being substituted and loses any value sent for it,
///   and the CA is reloaded from disk (the host widens it before sending). A
///   binding kept by name keeps resolving where it did; a new one resolves
///   from the launch's source, or, for a machine whose values are supplied
///   (`supplied_only`), only from values sent afterwards. On a machine that
///   booted without bindings, the first launch starts the interceptor.
pub struct LiveCredentials {
    state: Mutex<LiveState>,
    /// Where an interceptor started after boot is published.
    late: Option<smolvm_network::LateHttpsIntercept>,
}

struct LiveState {
    /// The bindings in force.
    policy: CredentialPolicy,
    /// The interceptor, once there is one.
    running: Option<Running>,
}

struct Running {
    control: InterceptorControl,
    resolver: Arc<SecretRefResolver>,
    ca_dir: PathBuf,
    supplied_only: bool,
    /// An interceptor started after boot, kept alive here.
    _owned: Option<Interceptor>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LiveRequest {
    #[serde(default)]
    values: Option<BTreeMap<String, String>>,
    #[serde(default)]
    launch: Option<CredentialLaunch>,
}

impl LiveCredentials {
    fn serve(self: Arc<Self>, vm_dir: &Path) {
        let path = vm_dir.join(CREDENTIALS_SOCKET);
        let _ = std::fs::remove_file(&path);
        crate::network::launch::serve_control_socket(
            path,
            "credentials-control",
            MAX_CREDENTIALS_REQUEST_BYTES,
            move |request| self.handle(request),
        );
    }

    fn handle(&self, request: &str) -> std::result::Result<(), String> {
        let request: LiveRequest =
            serde_json::from_str(request).map_err(|_| "malformed request".to_string())?;
        match (request.values, request.launch) {
            (Some(values), None) => self.replace_values(values),
            (None, Some(launch)) => self.replace_bindings(launch),
            _ => Err("send exactly one of `values` and `launch`".to_string()),
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
        running
            .resolver
            .live
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .extend(
                values
                    .into_iter()
                    .map(|(name, value)| (name, zeroize::Zeroizing::new(value))),
            );
        tracing::info!(bindings = ?names, "credential values replaced");
        Ok(())
    }

    fn replace_bindings(&self, launch: CredentialLaunch) -> std::result::Result<(), String> {
        launch.policy.validate(None).map_err(|e| e.to_string())?;
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let ca = MachineCa::load(&launch.ca_dir, &launch.ca_owner)
            .map_err(|e| format!("load machine CA: {e:#}"))?;
        match &mut state.running {
            Some(running) => {
                if running.ca_dir != launch.ca_dir {
                    return Err(format!(
                        "the machine's credential CA lives in {}, not {}",
                        running.ca_dir.display(),
                        launch.ca_dir.display()
                    ));
                }
                let mut sources = running
                    .resolver
                    .sources
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                let next = next_sources(
                    &launch,
                    &sources,
                    running.supplied_only || launch.supplied_only,
                );
                *sources = next;
                drop(sources);
                running
                    .resolver
                    .live
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .retain(|name, _| launch.policy.binding(name).is_some());
                running.supplied_only |= launch.supplied_only;
                // The CA first: a new binding's host may need the wider one.
                running.control.replace_ca(ca);
                running
                    .control
                    .replace_bindings(launch.policy.clone(), &launch.placeholders);
            }
            None => {
                let Some(slot) = self.late else {
                    return Err("this machine's network cannot route HTTPS through an \
                                interceptor started after boot; restart it"
                        .to_string());
                };
                let sources = next_sources(&launch, &BTreeMap::new(), launch.supplied_only);
                let resolver = Arc::new(SecretRefResolver {
                    sources: Arc::new(Mutex::new(sources)),
                    live: LiveValues::default(),
                });
                let interceptor = Interceptor::spawn(
                    InterceptorConfig {
                        machine: launch.machine.clone(),
                        policy: launch.policy.clone(),
                        placeholders: launch.placeholders.clone(),
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
                    ca_dir: launch.ca_dir.clone(),
                    supplied_only: launch.supplied_only,
                    _owned: Some(interceptor),
                });
                tracing::info!("credential interceptor started on a running machine");
            }
        }
        let names: Vec<&str> = launch
            .policy
            .credentials
            .iter()
            .map(|b| b.name.as_str())
            .collect();
        tracing::info!(bindings = ?names, "credential bindings replaced");
        state.policy = launch.policy;
        Ok(())
    }
}

/// Where each binding of `launch` resolves from once it is in force: a
/// binding the machine already has keeps its source (which may be a value its
/// boot was handed); a new one takes the launch's source, except on a machine
/// whose values are supplied, where it has none until a value is sent: such a
/// machine must never resolve from this host's environment.
fn next_sources(
    launch: &CredentialLaunch,
    current: &BTreeMap<String, SecretRef>,
    supplied_only: bool,
) -> BTreeMap<String, SecretRef> {
    launch
        .policy
        .credentials
        .iter()
        .filter_map(|binding| {
            let source = match current.get(&binding.name) {
                Some(kept) => Some(kept.clone()),
                None if supplied_only => None,
                None => launch.sources.get(&binding.name).cloned(),
            };
            source.map(|source| (binding.name.clone(), source))
        })
        .collect()
}

/// Resolves each binding from its secret reference on every request, through
/// the same reader (and audit trail) as every other machine secret, so a
/// rotated file or variable takes effect on the next request. A value handed
/// to the running machine through [`CREDENTIALS_SOCKET`] takes precedence.
struct SecretRefResolver {
    sources: Arc<Mutex<BTreeMap<String, SecretRef>>>,
    live: LiveValues,
}

impl CredentialResolver for SecretRefResolver {
    fn resolve(
        &self,
        request: &CredentialRequest,
    ) -> std::result::Result<zeroize::Zeroizing<String>, ResolveError> {
        if let Some(value) = self
            .live
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&request.binding)
        {
            return Ok(value.clone());
        }
        let source = self
            .sources
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&request.binding)
            .cloned()
            .ok_or(ResolveError::Unknown)?;
        crate::secrets::resolve_secret_ref_classified(
            &request.binding,
            &source,
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
    }

    /// New bindings reach a running machine whole: a kept binding keeps its
    /// source and value, a removed one loses both, and a new one resolves from
    /// its own source — or, on a machine whose values are supplied, only from
    /// a value sent for it.
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
            let message = serde_json::json!({ "launch": next }).to_string();
            assert_eq!(send(dir.path(), &message), "ok");

            let resolver = resolver_of(&live);
            let sources = resolver.sources.lock().unwrap().clone();
            assert_eq!(
                sources["a"].from_env.as_deref(),
                Some("SMOLVM_CREDENTIAL_0"),
                "a kept binding resolves where it did"
            );
            assert!(
                !sources.contains_key("b"),
                "a removed binding has no source"
            );
            assert_eq!(
                sources.get("c").and_then(|s| s.from_env.as_deref()),
                (!supplied_only).then_some("C_KEY"),
                "a new binding of a supplied machine never reads this host's environment"
            );
            let held = resolver.live.lock().unwrap();
            assert_eq!(held.get("a").map(|v| v.as_str()), Some("va"));
            assert!(!held.contains_key("b"), "a removed binding drops its value");
            drop(held);
            assert!(matches!(
                resolver.resolve(&request("b", "api.b.com")),
                Err(ResolveError::Unknown)
            ));
            // Values now name the new bindings, not the removed one.
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

    /// A machine that booted without bindings serves the socket too, and its
    /// first bindings start the interceptor and publish it to the network.
    #[test]
    fn the_first_bindings_start_an_interceptor_on_a_running_machine() {
        let dir = tempfile::tempdir().unwrap();
        let slot = smolvm_network::LateHttpsIntercept::new();
        serve_without_bindings(dir.path(), slot);
        assert!(send(dir.path(), r#"{"values":{"a":"x"}}"#).contains("no credential binding 'a'"));
        assert_eq!(send(dir.path(), r#"{"values":{}}"#), "ok");
        assert!(slot.get().is_none());

        let launch = launch_in(dir.path(), &["a=A_KEY@api.a.com"], true);
        launch.ensure_ca().unwrap();
        let message = serde_json::json!({ "launch": launch }).to_string();
        assert_eq!(send(dir.path(), &message), "ok");
        assert!(
            slot.get().is_some(),
            "HTTPS now goes through the interceptor"
        );
        assert_eq!(send(dir.path(), r#"{"values":{"a":"x"}}"#), "ok");
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
        let resolver = SecretRefResolver {
            sources: Arc::new(Mutex::new([("refresh".into(), source)].into())),
            live: LiveValues::default(),
        };
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
