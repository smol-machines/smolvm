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
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Socket in a running machine's data directory that takes new values for its
/// bindings, so a rotated credential reaches a machine without a restart.
pub const CREDENTIALS_SOCKET: &str = "credentials.sock";

/// Largest request the credentials socket reads: every binding's value is at
/// most a few KiB.
const MAX_CREDENTIALS_REQUEST_BYTES: u64 = 1024 * 1024;

/// Values handed to a running boot process through [`CREDENTIALS_SOCKET`], by
/// binding name. A binding with one resolves to it instead of its reference.
type LiveValues = Arc<Mutex<BTreeMap<String, zeroize::Zeroizing<String>>>>;

/// Name of the directory inside a machine's data dir that holds its
/// credential CA.
pub const CA_DIR_NAME: &str = "credentials";

/// Subdirectory of a CA directory holding the CAs added for hosts the machine CA does not permit, one per directory
/// (`0`, `1`, …), each name-constrained to the hosts it was added for.
const EXTRA_CA_DIR: &str = "extra";

/// The DNS subtrees `policy`'s bindings need a CA to permit, as the machine CA is generated for.
fn binding_subtrees(policy: &CredentialPolicy) -> Vec<String> {
    policy
        .credentials
        .iter()
        .flat_map(|binding| binding.allowed_hosts.iter())
        .map(|host| smolvm_protocol::credentials::host_subtree(host).to_string())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// The CAs added to `ca_dir` for hosts its machine CA does not permit, oldest first.
pub fn load_extra_cas(ca_dir: &Path, owner: &str) -> Vec<MachineCa> {
    let mut dirs: Vec<(u32, PathBuf)> = std::fs::read_dir(ca_dir.join(EXTRA_CA_DIR))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| Some((e.file_name().to_str()?.parse().ok()?, e.path())))
        .collect();
    dirs.sort();
    dirs.into_iter()
        .filter_map(|(_, dir)| MachineCa::load(&dir, owner).ok())
        .collect()
}

/// Make every host `policy` binds signable by a CA the guest trusts: a host no CA in `ca_dir` permits gets a new CA
/// of its own, name-constrained to just the uncovered hosts (the machine CA's constraint is never widened), and the
/// guest's `ca.pem` becomes the machine CA followed by every added one. A machine CA saved before it recorded its
/// hosts permits the hosts `generated_for` binds. True when a CA was added, so a running guest must rebuild its trust.
pub fn ensure_cas_for(
    ca_dir: &Path,
    owner: &str,
    policy: &CredentialPolicy,
    generated_for: &CredentialPolicy,
) -> Result<bool> {
    if !MachineCa::exists(ca_dir) {
        return Ok(false);
    }
    fn ca_err(e: impl std::fmt::Display) -> Error {
        Error::config("credentials", format!("machine CA: {e:#}"))
    }
    MachineCa::record_permitted_if_missing(ca_dir, &binding_subtrees(generated_for))
        .map_err(ca_err)?;
    let primary = MachineCa::load(ca_dir, owner).map_err(ca_err)?;
    let mut extras = load_extra_cas(ca_dir, owner);
    let uncovered: Vec<String> = binding_subtrees(policy)
        .into_iter()
        .filter(|host| !primary.permits(host) && !extras.iter().any(|ca| ca.permits(host)))
        .collect();
    let added = !uncovered.is_empty();
    if added {
        let ca = MachineCa::generate(owner, &uncovered).map_err(ca_err)?;
        let dir = ca_dir.join(EXTRA_CA_DIR).join(extras.len().to_string());
        ca.save(&dir).map_err(ca_err)?;
        extras.push(ca);
    }
    if !extras.is_empty() {
        let mut bundle = primary.certificate_pem().to_string();
        for ca in &extras {
            if !bundle.ends_with('\n') {
                bundle.push('\n');
            }
            bundle.push_str(ca.certificate_pem());
        }
        // in place: the guest reads it through its read-only mount
        std::fs::write(
            MachineCa::guest_dir(ca_dir).join(smolvm_credentials::ca::GUEST_CA_FILE),
            bundle,
        )
        .map_err(|e| Error::config("credentials", format!("write guest CA bundle: {e}")))?;
    }
    Ok(added)
}

/// A machine's credential bindings after a change ([`plan_binding_change`]).
pub struct BindingChange {
    /// The bindings after the change.
    pub policy: CredentialPolicy,
    /// Binding name → placeholder: those of kept bindings unchanged, a new one for each added binding.
    pub placeholders: BTreeMap<String, String>,
    /// A CA was added for a new host: a running guest must rebuild its trust before it reaches that host.
    pub trust_changed: bool,
    /// When the trust changed, the guest's CA bundle as just written, to hand a running guest directly.
    pub guest_ca: Option<String>,
}

/// Plan replacing `record`'s bindings with `policy`: validated against the machine's DNS allow-list as at create,
/// placeholders kept for bindings that stay (the guest already holds them) and minted for added ones, and a CA added
/// for any host no CA of the machine's lineage permits. Writes CA files only; the caller persists the record and
/// hands a running machine the change.
pub fn plan_binding_change(
    machine: &str,
    record: &VmRecord,
    policy: CredentialPolicy,
) -> Result<BindingChange> {
    policy
        .validate(record.dns_filter_hosts.as_deref())
        .map_err(|e| Error::config("credentials", e.to_string()))?;
    // Bindings turn outbound networking on at launch, so a machine whose
    // networking is off (`machine update --no-net`, which also clears its
    // bindings) would reach the internet again while `machine status` reports
    // networking off. A machine that already has bindings and no networking of
    // its own was created before bindings implied networking: its bindings
    // already give it egress, so changing them opens nothing new.
    refuse_bindings_without_network(machine, record, &policy)?;
    let minted = smolvm_credentials::generate_placeholders(&policy);
    let placeholders: BTreeMap<String, String> = policy
        .credentials
        .iter()
        .filter_map(|b| {
            let kept = record.credential_placeholders.get(&b.name).cloned();
            kept.or_else(|| minted.get(&b.name).cloned())
                .map(|p| (b.name.clone(), p))
        })
        .collect();
    let owner = record.golden.as_deref().unwrap_or(machine);
    let before = record.credential_policy.clone().unwrap_or_default();
    let trust_changed = ensure_cas_for(&ca_dir(owner), owner, &policy, &before)?;
    let guest_ca = trust_changed
        .then(|| {
            std::fs::read_to_string(
                MachineCa::guest_dir(&ca_dir(owner)).join(smolvm_credentials::ca::GUEST_CA_FILE),
            )
        })
        .transpose()
        .map_err(|e| Error::config("credentials", format!("read guest CA bundle: {e}")))?;
    Ok(BindingChange {
        policy,
        placeholders,
        trust_changed,
        guest_ca,
    })
}

/// Refuse giving `record` the bindings of `policy` when its networking is off: bindings turn outbound networking on
/// at launch. A machine that already has bindings and no networking of its own was created before bindings implied
/// networking; its bindings already give it egress, so changing them opens nothing new.
fn refuse_bindings_without_network(
    machine: &str,
    record: &VmRecord,
    policy: &CredentialPolicy,
) -> Result<()> {
    let has_bindings = record
        .credential_policy
        .as_ref()
        .is_some_and(|p| !p.is_empty());
    if policy.is_empty() || has_bindings || record.outbound_without_credentials() {
        return Ok(());
    }
    Err(Error::config(
        "credentials",
        format!(
            "machine '{machine}' has networking off, and credential bindings need outbound \
             networking; enable it first (`smolvm machine update --name {machine} --net` on \
             the stopped machine)"
        ),
    ))
}

/// What [`set_bindings`] did.
pub struct BindingsSet {
    /// The record as saved, with the new bindings.
    pub record: VmRecord,
    /// The running machine took them at once (it booted with bindings, so its interceptor runs).
    pub live: bool,
    /// The machine runs but booted without bindings: they apply from its next start.
    pub at_next_start: bool,
}

/// Who changes a machine's bindings, which decides where their values may come from.
#[derive(Debug, Clone, Copy)]
pub enum BindingsChanger<'a> {
    /// This host's operator (the CLI), defining the bindings named in `defines`: those read their values from this
    /// host (a `[secrets]` reference, the environment `machine start` ran with, or a value the operator hands the
    /// running machine). Every other binding keeps where its values come from.
    Operator {
        /// The bindings this command defines.
        defines: &'a [String],
    },
    /// An HTTP API caller or an embedder. A binding it adds or changes in any way (variable, hosts, header) takes
    /// only the values that caller supplies, never this host's, now or at any later start; one it leaves exactly as
    /// it was keeps its source. So it can neither route a host variable or secret to a host of its choosing nor
    /// redirect an operator's binding, and the value already held for it, to a new host.
    Untrusted,
}

/// Serializes changes to one machine's bindings, and the values handed to it for them, across processes: a value
/// read for a binding as one change sees it can never reach the binding as another change left it.
pub struct BindingsLock {
    machine: String,
    path: PathBuf,
    file: std::fs::File,
}

impl BindingsLock {
    /// Remove the lock file once the machine turns out not to exist (a delete raced the caller's lookup), so a
    /// change to a machine that is gone leaves nothing behind.
    pub fn remove_if_machine_gone(&self) {
        if still_names(&self.path, &self.file) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// The lock file of [`lock_bindings`] for the machine whose data directory is `data_dir`. It sits in the directory of
/// all machines, which belongs to this host's user, beside the machine's data directory rather than inside it: that
/// directory belongs to the machine's own user, and a process escaped from the machine must not be able to swap the
/// lock for a link or a FIFO that a root CLI or server then opens.
fn bindings_lock_beside(data_dir: &Path) -> PathBuf {
    let mut name = data_dir.file_name().unwrap_or_default().to_os_string();
    name.push(".credential-bindings.lock");
    data_dir.with_file_name(name)
}

/// Take [`BindingsLock`] for machine `name`, waiting for whoever holds it.
pub fn lock_bindings(name: &str) -> Result<BindingsLock> {
    // unit tests never write into this host's machine directory
    #[cfg(test)]
    let data_dir = std::env::temp_dir()
        .join(format!("smolvm-test-bindings-locks-{}", std::process::id()))
        .join(crate::agent::vm_dir_hash(name));
    #[cfg(not(test))]
    let data_dir = crate::agent::vm_data_dir(name);
    lock_bindings_at(
        &bindings_lock_beside(&data_dir),
        name,
        BINDINGS_LOCK_TIMEOUT,
    )
}

/// Remove the lock file of the machine whose data directory is `data_dir`, once the machine is deleted.
pub(crate) fn remove_bindings_lock(data_dir: &Path) {
    let path = bindings_lock_beside(data_dir);
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            tracing::warn!(path = %path.display(), %error, "could not remove credential bindings lock")
        }
    }
}

/// How long a change waits for another change to the same machine's bindings before giving up: a change holds the
/// lock for a record write and a socket round trip, so a holder past this is stuck, and a caller (an API handler
/// among them) must not wait on it forever.
const BINDINGS_LOCK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Open the lock file, creating it, without following a link or blocking on a FIFO. It is private to its owner
/// (0600): anyone who could open it could hold it and stall every change to the machine's bindings. A file this call
/// creates goes, when root creates it (`sudo smolvm …`), to the owner of the directory, so this host's user can still
/// take it. A file that already exists is never changed: it is refused when it belongs to anyone but this user, root
/// or that directory's owner, is open to others, or has another name (a hard link to some other file, which root
/// must never take over).
fn open_bindings_lock(path: &Path) -> std::io::Result<std::fs::File> {
    let open = |create: bool| {
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true);
        if create {
            options.create_new(true);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
        }
        options.open(path)
    };
    let (file, created) = match open(true) {
        Ok(file) => (file, true),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (open(false)?, false),
        Err(error) => return Err(error),
    };
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(std::io::Error::other(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::MetadataExt;
        let parent = std::fs::metadata(path.parent().unwrap_or(Path::new("/")))?;
        let me = unsafe { libc::geteuid() };
        if created {
            if me == 0
                && parent.uid() != 0
                && unsafe { libc::fchown(file.as_raw_fd(), parent.uid(), parent.gid()) } != 0
            {
                return Err(std::io::Error::last_os_error());
            }
        } else {
            let refuse = |why: String| {
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!("{} {why}; remove it", path.display()),
                ))
            };
            if meta.nlink() != 1 {
                return refuse(format!("has {} names", meta.nlink()));
            }
            if ![me, 0, parent.uid()].contains(&meta.uid()) {
                return refuse(format!("belongs to another user (uid {})", meta.uid()));
            }
            if meta.mode() & 0o077 != 0 {
                return refuse(format!(
                    "is open to others (mode {:o})",
                    meta.mode() & 0o777
                ));
            }
        }
    }
    #[cfg(not(unix))]
    let _ = created;
    Ok(file)
}

/// Whether `path` still names the file `file` has open: a delete may unlink it between the open and the lock.
fn still_names(path: &Path, file: &std::fs::File) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        match (std::fs::symlink_metadata(path), file.metadata()) {
            (Ok(named), Ok(open)) => named.dev() == open.dev() && named.ino() == open.ino(),
            _ => false,
        }
    }
    #[cfg(not(unix))]
    {
        // only a deleted machine's lock is removed, and a change to a deleted machine finds no record to change
        let _ = (path, file);
        true
    }
}

/// Take the lock at `path`, waiting at most `timeout` for whoever holds it.
fn lock_bindings_at(path: &Path, name: &str, timeout: std::time::Duration) -> Result<BindingsLock> {
    let fail = |e: std::io::Error| Error::agent("credential bindings lock", e.to_string());
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(fail)?;
    }
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let file = open_bindings_lock(path).map_err(fail)?;
        match file.try_lock() {
            Ok(()) => {
                if still_names(path, &file) {
                    return Ok(BindingsLock {
                        machine: name.to_string(),
                        path: path.to_path_buf(),
                        file,
                    });
                }
            }
            Err(std::fs::TryLockError::WouldBlock) => {
                if std::time::Instant::now() >= deadline {
                    return Err(Error::agent_conflict(
                        "credential bindings lock",
                        format!(
                            "another change to machine '{name}''s credential bindings has held them for over \
                             {}s; try again once it finishes",
                            timeout.as_secs_f32()
                        ),
                    ));
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(std::fs::TryLockError::Error(error)) => return Err(fail(error)),
        }
    }
}

/// Which of the bindings in `next` take only supplied values, and which variables stay withheld from the workload's
/// plaintext environment, after `changer` replaces `record`'s bindings with `next`.
fn provenance_after(
    record: &VmRecord,
    next: &CredentialPolicy,
    changer: BindingsChanger<'_>,
) -> (BTreeSet<String>, BTreeSet<String>) {
    let before = record.credential_policy.as_ref();
    let mut supplied: BTreeSet<String> = record
        .credentials_supplied_bindings
        .iter()
        .filter(|name| next.binding(name).is_some())
        .cloned()
        .collect();
    let mut withheld = record.credential_withheld_variables.clone();
    match changer {
        BindingsChanger::Operator { defines } => {
            for name in defines {
                supplied.remove(name);
            }
        }
        BindingsChanger::Untrusted => {
            for binding in &next.credentials {
                if before.and_then(|p| p.binding(&binding.name)) != Some(binding) {
                    supplied.insert(binding.name.clone());
                }
            }
            // A binding defined from this host may read an operator's secret reference, which then feeds the
            // interceptor and is withheld from the guest; removing or changing the binding must not make it
            // plaintext. A binding this caller set never read one, so it cannot withhold the operator's variables.
            withheld.extend(
                before
                    .iter()
                    .flat_map(|p| p.credentials.iter())
                    .filter(|b| record.credential_host_sourced(&b.name))
                    .filter(|b| next.binding(&b.name) != Some(*b))
                    .filter(|b| record.secret_refs.contains_key(&b.environment_variable))
                    .map(|b| b.environment_variable.clone()),
            );
        }
    }
    // only a reference the machine still has can be withheld, so the set never outgrows the machine's secrets
    withheld.retain(|var| record.secret_refs.contains_key(var));
    (supplied, withheld)
}

/// Replace `name`'s credential bindings with the policy `build` makes from its record as it is under `lock`
/// ([`plan_binding_change`]), saved for its next start and handed at once to the machine when it runs. A machine that
/// booted without bindings runs no interceptor, so it takes them from its next start. Where each binding's values
/// come from follows `changer`. Hold `lock` until any values for the new bindings have been handed over too.
pub fn set_bindings(
    name: &str,
    lock: &BindingsLock,
    changer: BindingsChanger<'_>,
    build: impl FnOnce(&VmRecord) -> Result<CredentialPolicy>,
) -> Result<BindingsSet> {
    set_bindings_in(&crate::db::SmolvmDb::open()?, name, lock, changer, build)
}

/// [`set_bindings`] against `db`, for a runtime that keeps its own database.
pub fn set_bindings_in(
    db: &crate::db::SmolvmDb,
    name: &str,
    lock: &BindingsLock,
    changer: BindingsChanger<'_>,
    build: impl FnOnce(&VmRecord) -> Result<CredentialPolicy>,
) -> Result<BindingsSet> {
    if lock.machine != name {
        return Err(Error::agent(
            "credential bindings lock",
            format!("held for machine '{}', not '{name}'", lock.machine),
        ));
    }
    let Some(record) = db.get_vm(name)? else {
        lock.remove_if_machine_gone();
        return Err(Error::vm_not_found(name));
    };
    let policy = build(&record)?;
    let change = plan_binding_change(name, &record, policy)?;
    let (supplied, withheld) = provenance_after(&record, &change.policy, changer);
    let saved = db
        // the machine planned for, never one deleted and created again under its name since
        .try_update_reviewed_vm_durable(&record, |r| {
            // checked again as the record is now: networking may have been turned off since it was read
            refuse_bindings_without_network(name, r, &change.policy)?;
            r.credential_policy = (!change.policy.is_empty()).then(|| change.policy.clone());
            r.credential_placeholders = change.placeholders.clone();
            r.credentials_supplied_bindings = supplied.clone();
            r.credential_withheld_variables = withheld.clone();
            Ok(())
        })?
        .ok_or_else(|| Error::vm_not_found(name))?;
    let running = crate::agent::state_probe::resolve_state(name, &saved)
        == crate::config::RecordState::Running;
    // whether its interceptor runs, not whether the record has bindings now: removing a machine's last binding leaves
    // the interceptor serving, and adding one back must reach it
    let interceptor = crate::agent::vm_data_dir(name)
        .join(CREDENTIALS_SOCKET)
        .exists();
    let live = running && interceptor;
    if live {
        // the host sources of the bindings this host's operator defined, and none for any other
        let sources = CredentialLaunch::for_record(name, &saved)
            .map(|launch| launch.sources)
            .unwrap_or_default();
        crate::agent::apply_live_credential_bindings(name, &change, &sources)?;
    }
    Ok(BindingsSet {
        record: saved,
        live,
        at_next_start: running && !interceptor,
    })
}

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
/// the variables pointing HTTP clients at the machine CA. A variable in
/// `withheld` (one that backed a binding an untrusted caller later changed)
/// never carries plaintext either. Returns the refs to resolve into the
/// environment and the credential variables to add.
pub fn workload_env(
    policy: Option<&CredentialPolicy>,
    placeholders: &BTreeMap<String, String>,
    secret_refs: &BTreeMap<String, SecretRef>,
    withheld: &BTreeSet<String>,
) -> (BTreeMap<String, SecretRef>, Vec<(String, String)>) {
    let policy = policy.filter(|p| !p.is_empty());
    let refs = secret_refs
        .iter()
        .filter(|(name, _)| {
            !withheld.contains(*name)
                && !policy.is_some_and(|policy| {
                    policy
                        .credentials
                        .iter()
                        .any(|b| &b.environment_variable == *name)
                })
        })
        .map(|(name, r)| (name.clone(), r.clone()))
        .collect();
    let Some(policy) = policy else {
        return (refs, Vec::new());
    };
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
    /// Variables withheld from the workload's plaintext environment although
    /// no binding names them now ([`VmRecord::credential_withheld_variables`]).
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub withheld_variables: BTreeSet<String>,
}

impl CredentialLaunch {
    /// Describe the launch for a record. `None` when the machine has no
    /// credential policy. Pure: the CA is created by [`Self::ensure_ca`].
    /// Only a binding this host's operator defined has a host source
    /// ([`VmRecord::credential_host_sourced`]); every other one resolves from
    /// supplied values alone.
    pub fn for_record(machine: &str, record: &VmRecord) -> Option<Self> {
        let mut launch = Self::from_parts(
            machine,
            record.credential_policy.as_ref()?,
            &record.credential_placeholders,
            &record.secret_refs,
            record.golden.as_deref(),
        )?;
        launch.supplied_only = record.credentials_supplied_by_api;
        launch
            .sources
            .retain(|binding, _| record.credential_host_sourced(binding));
        launch.withheld_variables = record.credential_withheld_variables.clone();
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
            withheld_variables: BTreeSet::new(),
        })
    }

    /// Create the lineage's CA on first use. Called by the launcher before the
    /// guest CA directory is mounted.
    pub fn ensure_ca(&self) -> Result<()> {
        if MachineCa::exists(&self.ca_dir) {
            // a binding changed while the machine was stopped may name a host no CA permits yet
            return ensure_cas_for(&self.ca_dir, &self.ca_owner, &self.policy, &self.policy)
                .map(|_| ());
        }
        // A wildcard's parent is the subtree the CA may sign in; the name
        // constraint on it already covers every subdomain.
        let hosts: Vec<String> = self
            .policy
            .credentials
            .iter()
            .flat_map(|binding| binding.allowed_hosts.iter())
            .map(|host| smolvm_protocol::credentials::host_subtree(host).to_string())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
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
            recorded_ownership: false,
            owner: None,
        }
    }

    /// Start the interceptor for this machine. The returned handle must live
    /// as long as the VM; dropping it stops substitution. With the machine's
    /// data directory, it also serves [`CREDENTIALS_SOCKET`] there.
    pub fn start_interceptor(&self, vm_dir: Option<&Path>) -> Result<Interceptor> {
        let ca = MachineCa::load(&self.ca_dir, &self.ca_owner)
            .map_err(|e| Error::config("credentials", format!("load machine CA: {e:#}")))?
            .with_permitted(binding_subtrees(&self.policy));
        let live = LiveValues::default();
        let sources = Arc::new(std::sync::RwLock::new(self.sources.clone()));
        let interceptor = Interceptor::spawn(
            InterceptorConfig {
                machine: self.machine.clone(),
                policy: self.policy.clone(),
                placeholders: self.placeholders.clone(),
                ca,
                extra_cas: load_extra_cas(&self.ca_dir, &self.ca_owner),
                upstream_roots_pem: Vec::new(),
            },
            Arc::new(SecretRefResolver {
                sources: sources.clone(),
                live: live.clone(),
            }),
        )
        .map_err(|e| Error::config("credentials", format!("start interceptor: {e:#}")))?;
        if let Some(dir) = vm_dir {
            serve_live_values(
                dir,
                &self.policy,
                live,
                Some(LiveBindings {
                    control: interceptor.control(),
                    sources,
                    ca_dir: self.ca_dir.clone(),
                    ca_owner: self.ca_owner.clone(),
                }),
            );
        }
        Ok(interceptor)
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

/// Keep the values held for `machine` whose binding is in `keep`, then hold
/// `values` over them; returns what is now held.
pub fn retain_and_supply_values(
    machine: &str,
    keep: &[&str],
    values: SuppliedValues,
) -> SuppliedValues {
    let mut held = SUPPLIED.lock().unwrap_or_else(|e| e.into_inner());
    let mut merged = held.remove(machine).unwrap_or_default();
    merged.retain(|binding, _| keep.contains(&binding.as_str()));
    merged.extend(values);
    if !merged.is_empty() {
        held.insert(machine.to_string(), merged.clone());
    }
    merged
}

/// Drop whatever was supplied for `machine`.
pub fn forget_values(machine: &str) {
    supply_values(machine, BTreeMap::new());
}

/// Name of the variable carrying a supplied value into the boot process.
fn supplied_var(index: usize) -> String {
    format!("SMOLVM_CREDENTIAL_{index}")
}

impl CredentialLaunch {
    /// Point bindings at the values supplied for this machine, and return the
    /// environment the boot process needs for it: `Some(value)` to set,
    /// `None` to remove. A supplied value travels in a variable private to the
    /// boot process, so it never lands in the boot config on disk. A binding
    /// with no host source and no value is pointed at a variable that is
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
            if value.is_none() && !self.supplied_only && self.sources.contains_key(&binding.name) {
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

/// What a bindings change reaches in the machine's process: the interceptor, the sources its resolver reads, and the
/// CA directory the caller added a CA to.
struct LiveBindings {
    control: smolvm_credentials::InterceptorControl,
    sources: Arc<std::sync::RwLock<BTreeMap<String, SecretRef>>>,
    ca_dir: PathBuf,
    ca_owner: String,
}

/// Take the boot process's sources and held values from the bindings `current` to `next`. A binding left exactly as
/// it was keeps both. One added or changed in any way (variable, hosts, header) drops the value held for it, so a
/// value handed over for one destination never follows the binding to another, and resolves from `next_sources`
/// alone: the trusted caller names there the host source of each binding this host's operator defined, and a binding
/// it does not name resolves only from a value handed over after the change, never from this process's environment.
fn replace_live_bindings(
    current: &CredentialPolicy,
    next: &CredentialPolicy,
    next_sources: &BTreeMap<String, SecretRef>,
    sources: &mut BTreeMap<String, SecretRef>,
    live: &mut BTreeMap<String, zeroize::Zeroizing<String>>,
) {
    sources.retain(|name, _| next.binding(name).is_some());
    live.retain(|name, _| next.binding(name).is_some());
    for binding in &next.credentials {
        if current.binding(&binding.name) == Some(binding) {
            continue;
        }
        live.remove(&binding.name);
        match next_sources.get(&binding.name) {
            Some(source) => sources.insert(binding.name.clone(), source.clone()),
            None => sources.remove(&binding.name),
        };
    }
}

/// The request handing a running machine its new bindings over [`CREDENTIALS_SOCKET`], with the host source of each
/// binding this host's operator defined in `sources`. `sources` sits beside `bindings`, not inside it: a boot process
/// that predates it (v1.36) refuses an unknown top-level field as a malformed request and keeps the bindings it has,
/// where it would quietly drop a nested one and resolve every added binding from its own environment.
pub(crate) fn live_bindings_request(
    change: &BindingChange,
    sources: &BTreeMap<String, SecretRef>,
) -> String {
    serde_json::json!({
        "bindings": { "policy": change.policy, "placeholders": change.placeholders },
        "sources": sources,
    })
    .to_string()
}

/// Serve [`CREDENTIALS_SOCKET`] in `vm_dir`: each connection sends
/// `{"values":{"<binding>":"<value>",…}}` or `{"bindings":{"policy":…,"placeholders":…},"sources":…}` and gets back
/// `ok` or `error: <reason>`. Values replace those the machine resolves for the bindings named, from its next request
/// on; a name that is not a binding changes nothing. Bindings replace the machine's bindings
/// ([`replace_live_bindings`]): a removed one is no longer substituted (its hosts stay intercepted, their responses
/// checked for the values sent there) and its values are dropped, and a CA the caller added for a new host signs that
/// host from the next connection. A change is refused, the running machine keeping its bindings, sources and held
/// values, if connections already spliced to a host it covers do not end in time or another change is being applied.
fn serve_live_values(
    vm_dir: &Path,
    policy: &CredentialPolicy,
    live: LiveValues,
    change: Option<LiveBindings>,
) {
    #[derive(Deserialize)]
    struct Bindings {
        policy: CredentialPolicy,
        placeholders: BTreeMap<String, String>,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Request {
        #[serde(default)]
        values: BTreeMap<String, String>,
        #[serde(default)]
        bindings: Option<Bindings>,
        /// Host sources of the bindings this host's operator defined ([`live_bindings_request`]). A bindings change
        /// without it, from a caller that predates it, leaves every added or changed binding to values handed over.
        #[serde(default)]
        sources: BTreeMap<String, SecretRef>,
    }
    let bindings: Arc<Mutex<CredentialPolicy>> = Arc::new(Mutex::new(policy.clone()));
    let path = vm_dir.join(CREDENTIALS_SOCKET);
    let _ = std::fs::remove_file(&path);
    crate::network::launch::serve_control_socket(
        path,
        "credentials-control",
        MAX_CREDENTIALS_REQUEST_BYTES,
        move |request| {
            let request: Request =
                serde_json::from_str(request).map_err(|_| "malformed request".to_string())?;
            let mut current = bindings.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(next) = request.bindings {
                let Some(change) = change.as_ref() else {
                    return Err("this machine cannot change its bindings while it runs".to_string());
                };
                // Ends the connections spliced to hosts the new bindings cover first, or refuses with nothing
                // changed: sources, held values and the bindings stay as they are.
                let prepared = change.control.prepare(&next.policy)?;
                replace_live_bindings(
                    &current,
                    &next.policy,
                    &request.sources,
                    &mut change.sources.write().unwrap_or_else(|e| e.into_inner()),
                    &mut live.lock().unwrap_or_else(|e| e.into_inner()),
                );
                let names: Vec<String> = next
                    .policy
                    .credentials
                    .iter()
                    .map(|b| b.name.clone())
                    .collect();
                *current = next.policy.clone();
                prepared.commit(
                    next.policy,
                    next.placeholders,
                    load_extra_cas(&change.ca_dir, &change.ca_owner),
                );
                tracing::info!(bindings = ?names, "credential bindings replaced");
            }
            if let Some(unknown) = request.values.keys().find(|k| current.binding(k).is_none()) {
                return Err(format!("no credential binding '{unknown}'"));
            }
            for (binding, value) in &request.values {
                smolvm_credentials::check_credential_value(binding, value)?;
            }
            if request.values.is_empty() {
                return Ok(());
            }
            let names: Vec<String> = request.values.keys().cloned().collect();
            live.lock().unwrap_or_else(|e| e.into_inner()).extend(
                request
                    .values
                    .into_iter()
                    .map(|(name, value)| (name, zeroize::Zeroizing::new(value))),
            );
            tracing::info!(bindings = ?names, "credential values replaced");
            Ok(())
        },
    );
}

/// Resolves each binding from its secret reference on every request, through
/// the same reader (and audit trail) as every other machine secret, so a
/// rotated file or variable takes effect on the next request. A value handed
/// to the running machine through [`CREDENTIALS_SOCKET`] takes precedence.
struct SecretRefResolver {
    sources: Arc<std::sync::RwLock<BTreeMap<String, SecretRef>>>,
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
            .read()
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

    fn binding(name: &str, host: &str) -> CredentialBinding {
        CredentialBinding {
            name: name.into(),
            environment_variable: format!("{}_KEY", name.to_uppercase()),
            allowed_hosts: vec![host.into()],
            injection_location: Default::default(),
            methods: smolvm_credentials::policy::DEFAULT_METHODS
                .iter()
                .map(|m| m.to_string())
                .collect(),
            set_header: None,
        }
    }

    /// A binding for a host no CA permits gets a CA of its own (the machine CA is never widened), a binding inside a
    /// permitted host needs none, and the guest's CA file holds every CA.
    #[test]
    fn a_new_host_gets_a_ca_of_its_own_and_a_covered_one_none() {
        let dir = tempfile::tempdir().unwrap();
        let first = CredentialPolicy {
            credentials: vec![binding("notion", "api.notion.com")],
        };
        MachineCa::generate("m", &binding_subtrees(&first))
            .unwrap()
            .save(dir.path())
            .unwrap();
        let guest = MachineCa::guest_dir(dir.path()).join(smolvm_credentials::ca::GUEST_CA_FILE);
        let certs = |p: &Path| {
            std::fs::read_to_string(p)
                .unwrap()
                .matches("BEGIN CERTIFICATE")
                .count()
        };
        assert!(
            !ensure_cas_for(dir.path(), "m", &first, &first).unwrap(),
            "nothing new"
        );
        let grown = CredentialPolicy {
            credentials: vec![
                binding("notion", "api.notion.com"),
                binding("gh", "api.github.com"),
            ],
        };
        assert!(
            ensure_cas_for(dir.path(), "m", &grown, &first).unwrap(),
            "a CA for api.github.com"
        );
        assert_eq!(load_extra_cas(dir.path(), "m").len(), 1);
        assert_eq!(certs(&guest), 2);
        let extra = &load_extra_cas(dir.path(), "m")[0];
        assert!(
            extra.permits("api.github.com") && !extra.permits("api.notion.com"),
            "constrained to the new host only"
        );
        let primary = MachineCa::load(dir.path(), "m").unwrap();
        assert!(
            !primary.permits("api.github.com"),
            "the machine CA is not widened"
        );
        assert!(
            !ensure_cas_for(dir.path(), "m", &grown, &first).unwrap(),
            "covered now: no second CA"
        );
        assert_eq!(load_extra_cas(dir.path(), "m").len(), 1);
    }

    /// A CA saved before it recorded its hosts permits those it was generated for, not those a later policy names.
    #[test]
    fn a_ca_saved_before_hosts_were_recorded_permits_its_first_policy_only() {
        let dir = tempfile::tempdir().unwrap();
        let first = CredentialPolicy {
            credentials: vec![binding("notion", "api.notion.com")],
        };
        MachineCa::generate("m", &binding_subtrees(&first))
            .unwrap()
            .save(dir.path())
            .unwrap();
        std::fs::remove_file(dir.path().join("ca.hosts")).unwrap();
        let grown = CredentialPolicy {
            credentials: vec![
                binding("notion", "api.notion.com"),
                binding("gh", "api.github.com"),
            ],
        };
        assert!(
            ensure_cas_for(dir.path(), "m", &grown, &first).unwrap(),
            "api.github.com is new to it"
        );
        assert!(MachineCa::load(dir.path(), "m")
            .unwrap()
            .permits("api.notion.com"));
    }

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

    /// A running machine takes a rotated value through its credentials socket
    /// and resolves it from the next request, over the value it booted with.
    #[test]
    fn values_sent_to_a_running_machine_replace_the_ones_it_booted_with() {
        use std::io::{Read, Write};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        std::fs::write(&path, "booted").unwrap();
        let policy = CredentialPolicy {
            credentials: vec![parse_credential_flag("github=GH_TOKEN@github.com").unwrap()],
        };
        let live = LiveValues::default();
        serve_live_values(dir.path(), &policy, live.clone(), None);
        let resolver = SecretRefResolver {
            sources: Arc::new(std::sync::RwLock::new(
                [("github".into(), crate::secrets::file_ref(path))].into(),
            )),
            live,
        };
        let request = CredentialRequest {
            machine: "rotate-test".into(),
            binding: "github".into(),
            host: "github.com".into(),
            port: 443,
            method: "GET".into(),
            path: "/".into(),
        };
        assert_eq!(resolver.resolve(&request).unwrap().as_str(), "booted");

        let send = |body: &str| {
            let mut stream =
                crate::platform::uds::UdsStream::connect(dir.path().join(CREDENTIALS_SOCKET))
                    .unwrap();
            stream.write_all(body.as_bytes()).unwrap();
            stream.shutdown(std::net::Shutdown::Write).unwrap();
            let mut reply = String::new();
            stream.read_to_string(&mut reply).unwrap();
            reply
        };
        assert_eq!(send(r#"{"values":{"github":"rotated"}}"#).trim(), "ok");
        assert_eq!(resolver.resolve(&request).unwrap().as_str(), "rotated");

        let refused = send(r#"{"values":{"other":"x"}}"#);
        assert!(
            refused.contains("no credential binding 'other'"),
            "{refused}"
        );
        assert_eq!(resolver.resolve(&request).unwrap().as_str(), "rotated");
    }

    #[test]
    fn file_backed_credential_uses_the_latest_host_value() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("refresh-token");
        let source = crate::secrets::file_ref(path.clone());
        let resolver = SecretRefResolver {
            sources: Arc::new(std::sync::RwLock::new([("refresh".into(), source)].into())),
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
        let (refs, env) = workload_env(Some(&policy), &placeholders, &refs, &BTreeSet::new());
        assert_eq!(refs.keys().collect::<Vec<_>>(), vec!["OTHER"]);
        assert_eq!(env[0], ("N_KEY".to_string(), placeholders["n"].clone()));
        assert!(env
            .iter()
            .any(|(k, v)| k == "SSL_CERT_FILE" && v == "/run/smolvm/ca-bundle.pem"));
        assert!(env.iter().all(|(_, v)| !v.contains("secret")));
        assert!(prepare_policy(&policy, Some(&["github.com".to_string()])).is_err());
    }

    /// A running machine's credentials socket, as its boot process serves it, booted with `policy` and `sources`.
    struct LiveMachine {
        dir: tempfile::TempDir,
        resolver: SecretRefResolver,
        _interceptor: Interceptor,
    }

    impl LiveMachine {
        fn boot(policy: &CredentialPolicy, sources: BTreeMap<String, SecretRef>) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let live = LiveValues::default();
            let sources = Arc::new(std::sync::RwLock::new(sources));
            let interceptor = Interceptor::spawn(
                InterceptorConfig {
                    machine: "live-test".into(),
                    policy: policy.clone(),
                    placeholders: smolvm_credentials::generate_placeholders(policy),
                    ca: MachineCa::generate("live-test", &binding_subtrees(policy)).unwrap(),
                    extra_cas: Vec::new(),
                    upstream_roots_pem: Vec::new(),
                },
                Arc::new(SecretRefResolver {
                    sources: sources.clone(),
                    live: live.clone(),
                }),
            )
            .unwrap();
            serve_live_values(
                dir.path(),
                policy,
                live.clone(),
                Some(LiveBindings {
                    control: interceptor.control(),
                    sources: sources.clone(),
                    ca_dir: dir.path().join("ca"),
                    ca_owner: "live-test".into(),
                }),
            );
            LiveMachine {
                dir,
                resolver: SecretRefResolver { sources, live },
                _interceptor: interceptor,
            }
        }

        fn send(&self, body: &str) -> String {
            use std::io::{Read, Write};
            let mut stream =
                crate::platform::uds::UdsStream::connect(self.dir.path().join(CREDENTIALS_SOCKET))
                    .unwrap();
            stream.write_all(body.as_bytes()).unwrap();
            stream.shutdown(std::net::Shutdown::Write).unwrap();
            let mut reply = String::new();
            stream.read_to_string(&mut reply).unwrap();
            reply.trim().to_string()
        }

        /// Hand the machine `policy` as its new bindings, as a host-side change does.
        fn rebind(&self, policy: &CredentialPolicy, sources: &BTreeMap<String, SecretRef>) {
            assert_eq!(
                self.send(&live_bindings_request(&change_to(policy), sources)),
                "ok"
            );
        }

        fn resolve(&self, binding: &str, host: &str) -> Option<String> {
            self.resolver
                .resolve(&CredentialRequest {
                    machine: "live-test".into(),
                    binding: binding.into(),
                    host: host.into(),
                    port: 443,
                    method: "GET".into(),
                    path: "/".into(),
                })
                .ok()
                .map(|v| v.to_string())
        }
    }

    fn change_to(policy: &CredentialPolicy) -> BindingChange {
        BindingChange {
            policy: policy.clone(),
            placeholders: smolvm_credentials::generate_placeholders(policy),
            trust_changed: false,
            guest_ca: None,
        }
    }

    /// A boot process from v1.36 kept running across a host upgrade must refuse a bindings change that carries
    /// sources, keeping the bindings it booted with, rather than quietly dropping them and resolving every added
    /// binding from its own environment. Its request shape, as it shipped.
    #[test]
    fn a_boot_process_that_predates_sources_refuses_the_change() {
        #[derive(Deserialize)]
        #[allow(dead_code)]
        struct Bindings {
            policy: CredentialPolicy,
            placeholders: BTreeMap<String, String>,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        #[allow(dead_code)]
        struct V136Request {
            #[serde(default)]
            values: BTreeMap<String, String>,
            #[serde(default)]
            bindings: Option<Bindings>,
        }
        let request = live_bindings_request(
            &change_to(&policy_of(&["gh=GH_TOKEN@attacker.example"])),
            &BTreeMap::new(),
        );
        assert!(serde_json::from_str::<V136Request>(&request).is_err());
        // values alone, which it still takes, keep their shape
        assert!(serde_json::from_str::<V136Request>(r#"{"values":{"gh":"v"}}"#).is_ok());
    }

    /// A bindings change from a caller that predates sources leaves an added binding to values handed over.
    #[test]
    fn a_bindings_change_without_sources_reads_no_host_value() {
        let machine = LiveMachine::boot(&policy_of(&["a=A_KEY@api.a.com"]), BTreeMap::new());
        let next = policy_of(&["a=A_KEY@api.a.com", "evil=PATH@attacker.example"]);
        let body = serde_json::json!({
            "bindings": {
                "policy": next,
                "placeholders": smolvm_credentials::generate_placeholders(&next),
            }
        });
        assert_eq!(machine.send(&body.to_string()), "ok");
        assert_eq!(machine.resolve("evil", "attacker.example"), None);
    }

    fn policy_of(specs: &[&str]) -> CredentialPolicy {
        CredentialPolicy {
            credentials: specs
                .iter()
                .map(|spec| parse_credential_flag(spec).unwrap())
                .collect(),
        }
    }

    /// A binding added to a running machine without a host source (every binding an API caller adds) never resolves
    /// from the boot process's environment, which it inherited from whoever started it: `PATH` stands in for
    /// `AWS_SECRET_ACCESS_KEY` in the serve process. One the operator added with a source resolves from that source.
    #[test]
    fn a_binding_added_live_never_reads_the_boot_process_environment() {
        let dir = tempfile::tempdir().unwrap();
        let token = dir.path().join("gh-token");
        std::fs::write(&token, "operator-file").unwrap();
        let machine = LiveMachine::boot(&policy_of(&["a=A_KEY@api.a.com"]), BTreeMap::new());
        assert!(std::env::var("PATH").is_ok_and(|v| !v.is_empty()));
        let next = policy_of(&[
            "a=A_KEY@api.a.com",
            "evil=PATH@attacker.example",
            "gh=GH_TOKEN@github.com",
        ]);
        machine.rebind(
            &next,
            &[("gh".to_string(), crate::secrets::file_ref(token))].into(),
        );
        assert_eq!(machine.resolve("evil", "attacker.example"), None);
        assert_eq!(
            machine.resolve("gh", "github.com").as_deref(),
            Some("operator-file")
        );
        // a value handed over for it afterwards is what it resolves to
        assert_eq!(machine.send(r#"{"values":{"evil":"supplied"}}"#), "ok");
        assert_eq!(
            machine.resolve("evil", "attacker.example").as_deref(),
            Some("supplied")
        );
    }

    /// Retargeting a binding (its hosts, its variable or its header) drops the value held for it and the source it
    /// booted with, so neither reaches the new destination; a binding left exactly as it was keeps both.
    #[test]
    fn a_retargeted_binding_never_takes_its_held_value_to_the_new_host() {
        let dir = tempfile::tempdir().unwrap();
        let token = dir.path().join("gh-token");
        std::fs::write(&token, "operator-file").unwrap();
        let booted = policy_of(&["gh=GH_TOKEN@github.com", "a=A_KEY@api.a.com"]);
        for retarget in [
            "gh=GH_TOKEN@attacker.example",
            "gh=OTHER_VAR@github.com",
            "gh=GH_TOKEN@github.com:set-header=x-token",
        ] {
            // each case starts from a machine that holds a value for gh
            let machine = LiveMachine::boot(
                &booted,
                [("gh".to_string(), crate::secrets::file_ref(token.clone()))].into(),
            );
            assert_eq!(
                machine.send(r#"{"values":{"gh":"operator-pushed","a":"kept"}}"#),
                "ok"
            );
            assert_eq!(
                machine.resolve("gh", "github.com").as_deref(),
                Some("operator-pushed")
            );
            machine.rebind(
                &policy_of(&[retarget, "a=A_KEY@api.a.com"]),
                &BTreeMap::new(),
            );
            for host in ["attacker.example", "github.com"] {
                assert_eq!(machine.resolve("gh", host), None, "{retarget} {host}");
            }
            assert_eq!(
                machine.resolve("a", "api.a.com").as_deref(),
                Some("kept"),
                "{retarget}"
            );
        }
    }

    /// A change the interceptor refuses (here another change is already prepared) leaves the boot process as it was:
    /// the held value, the source and the bindings the values are checked against.
    #[test]
    fn a_refused_binding_change_leaves_held_values_sources_and_bindings_alone() {
        let dir = tempfile::tempdir().unwrap();
        let token = dir.path().join("a-token");
        std::fs::write(&token, "a-file").unwrap();
        let booted = policy_of(&["gh=GH_TOKEN@github.com", "a=A_KEY@api.a.com"]);
        let machine = LiveMachine::boot(
            &booted,
            [("a".to_string(), crate::secrets::file_ref(token))].into(),
        );
        assert_eq!(machine.send(r#"{"values":{"gh":"operator-pushed"}}"#), "ok");
        let pending = machine
            ._interceptor
            .control()
            .prepare(&policy_of(&["other=O_KEY@other.example"]))
            .unwrap();
        let next = policy_of(&["gh=GH_TOKEN@attacker.example", "evil=PATH@attacker.example"]);
        let refused = machine.send(&live_bindings_request(&change_to(&next), &BTreeMap::new()));
        assert!(refused.contains("in progress"), "{refused}");
        assert_eq!(
            machine.resolve("gh", "github.com").as_deref(),
            Some("operator-pushed")
        );
        assert_eq!(machine.resolve("a", "api.a.com").as_deref(), Some("a-file"));
        // the bindings values are checked against are still the booted ones
        assert!(machine
            .send(r#"{"values":{"evil":"x"}}"#)
            .contains("no credential binding 'evil'"));
        assert_eq!(machine.send(r#"{"values":{"a":"pushed"}}"#), "ok");
        drop(pending);
    }

    fn bindings_db(
        name: &str,
        setup: impl FnOnce(&mut VmRecord),
    ) -> (tempfile::TempDir, crate::db::SmolvmDb) {
        let dir = tempfile::tempdir().unwrap();
        let db = crate::db::SmolvmDb::open_at(&dir.path().join("smolvm.db")).unwrap();
        let mut record = VmRecord::new(name.into(), 1, 512, Vec::new(), Vec::new(), true);
        setup(&mut record);
        db.insert_vm(name, &record).unwrap();
        (dir, db)
    }

    /// A bindings lock for `name` in a scratch directory, never in this host's machine directory.
    fn test_lock(name: &str) -> (tempfile::TempDir, BindingsLock) {
        let dir = tempfile::tempdir().unwrap();
        let lock = lock_bindings_at(
            &dir.path().join("m.credential-bindings.lock"),
            name,
            BINDINGS_LOCK_TIMEOUT,
        )
        .unwrap();
        (dir, lock)
    }

    fn change(
        db: &crate::db::SmolvmDb,
        name: &str,
        changer: BindingsChanger<'_>,
        specs: &[&str],
    ) -> Result<VmRecord> {
        let (_dir, lock) = test_lock(name);
        let policy = policy_of(specs);
        set_bindings_in(db, name, &lock, changer, |_| Ok(policy)).map(|set| set.record)
    }

    fn host_sources(name: &str, record: &VmRecord) -> Vec<String> {
        CredentialLaunch::for_record(name, record)
            .map(|launch| launch.sources.into_keys().collect())
            .unwrap_or_default()
    }

    /// A binding an API caller or embedder puts on a machine whose values come from this host (a CLI machine, or an
    /// API machine created without bindings) never reads this host's variables or secrets at a later start, whatever
    /// variable it names; one left exactly as the operator defined it keeps reading them, and the operator naming a
    /// binding again makes it read them.
    #[test]
    fn a_binding_set_by_an_untrusted_caller_never_reads_this_host_at_a_later_start() {
        let name = format!("cred-test-provenance-{}", std::process::id());
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("op-secret");
        std::fs::write(&secret, "operator-secret").unwrap();
        let (_db_dir, db) = bindings_db(&name, |r| {
            r.secret_refs
                .insert("OP_SECRET".into(), crate::secrets::file_ref(secret));
        });
        let operator = change(
            &db,
            &name,
            BindingsChanger::Operator {
                defines: &["gh".to_string()],
            },
            &["gh=GH_TOKEN@github.com"],
        )
        .unwrap();
        assert_eq!(host_sources(&name, &operator), vec!["gh"]);

        let api = change(
            &db,
            &name,
            BindingsChanger::Untrusted,
            &[
                "gh=GH_TOKEN@github.com",
                "evil=AWS_SECRET_ACCESS_KEY@attacker.example",
                "steal=OP_SECRET@attacker.example",
            ],
        )
        .unwrap();
        assert_eq!(host_sources(&name, &api), vec!["gh"]);
        let mut launch = CredentialLaunch::for_record(&name, &api).unwrap();
        let env = launch.child_env();
        // nothing supplied: both point at a variable the boot process does not get
        assert_eq!(env.len(), 2);
        assert!(env.iter().all(|(_, value)| value.is_none()));
        for binding in ["evil", "steal"] {
            let var = launch.sources[binding].from_env.clone().unwrap();
            assert!(var.starts_with("SMOLVM_CREDENTIAL_"), "{binding}: {var}");
        }

        // an operator command that carries them without naming them leaves them supplied-only
        let carried = change(
            &db,
            &name,
            BindingsChanger::Operator {
                defines: &["b".to_string()],
            },
            &[
                "gh=GH_TOKEN@github.com",
                "evil=AWS_SECRET_ACCESS_KEY@attacker.example",
                "steal=OP_SECRET@attacker.example",
                "b=B_KEY@api.b.com",
            ],
        )
        .unwrap();
        assert_eq!(host_sources(&name, &carried), vec!["b", "gh"]);

        // retargeting the operator's binding makes it supplied-only too
        let retargeted = change(
            &db,
            &name,
            BindingsChanger::Untrusted,
            &["gh=GH_TOKEN@attacker.example", "b=B_KEY@api.b.com"],
        )
        .unwrap();
        assert_eq!(host_sources(&name, &retargeted), vec!["b"]);

        // until the operator defines it again
        let redefined = change(
            &db,
            &name,
            BindingsChanger::Operator {
                defines: &["gh".to_string()],
            },
            &["gh=GH_TOKEN@github.com", "b=B_KEY@api.b.com"],
        )
        .unwrap();
        assert_eq!(host_sources(&name, &redefined), vec!["b", "gh"]);
    }

    /// Removing or renaming a binding over the API never turns the operator's secret reference that fed it into
    /// plaintext in the workload's environment.
    #[test]
    fn unbinding_a_variable_over_the_api_never_makes_its_secret_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("gh-token");
        std::fs::write(&secret, "ghp_operator").unwrap();
        for after in [&[][..], &["gh=RENAMED@github.com"][..]] {
            let name = format!("cred-test-withheld-{}-{}", std::process::id(), after.len());
            let (_db_dir, db) = bindings_db(&name, |r| {
                r.secret_refs
                    .insert("GH_TOKEN".into(), crate::secrets::file_ref(secret.clone()));
            });
            let bound = change(
                &db,
                &name,
                BindingsChanger::Operator {
                    defines: &["gh".to_string()],
                },
                &["gh=GH_TOKEN@github.com"],
            )
            .unwrap();
            let plaintext = |record: &VmRecord| {
                crate::secrets::record_env_with_secrets(record)
                    .unwrap()
                    .iter()
                    .any(|(_, value)| value.contains("ghp_operator"))
            };
            assert!(!plaintext(&bound));
            let changed = change(&db, &name, BindingsChanger::Untrusted, after).unwrap();
            assert!(!plaintext(&changed), "{after:?}");
            // an exec session the server answers without the record withholds it too
            let launch = CredentialLaunch::for_record(&name, &changed);
            let withheld = launch
                .as_ref()
                .map(|l| l.withheld_variables.clone())
                .unwrap_or_else(|| changed.credential_withheld_variables.clone());
            assert!(withheld.contains("GH_TOKEN"), "{after:?}");
        }
    }

    /// An API caller cannot withhold the operator's plaintext secrets: a binding it set itself never read one, so
    /// removing it withholds nothing, and the withheld set never names more than the machine's secret references.
    #[test]
    fn an_untrusted_caller_cannot_withhold_the_operators_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("db-url");
        std::fs::write(&secret, "postgres://operator").unwrap();
        let name = format!("cred-test-withhold-abuse-{}", std::process::id());
        let (_db_dir, db) = bindings_db(&name, |r| {
            r.secret_refs
                .insert("DB_URL".into(), crate::secrets::file_ref(secret.clone()));
        });
        for round in 0..3 {
            change(
                &db,
                &name,
                BindingsChanger::Untrusted,
                &[
                    &format!("x=DB_URL@a{round}.example"),
                    &format!("y=V{round}@b.example"),
                ],
            )
            .unwrap();
            let removed = change(&db, &name, BindingsChanger::Untrusted, &[]).unwrap();
            assert!(
                removed.credential_withheld_variables.is_empty(),
                "{:?}",
                removed.credential_withheld_variables
            );
            let env = crate::secrets::record_env_with_secrets(&removed).unwrap();
            assert!(env.contains(&("DB_URL".into(), "postgres://operator".into())));
        }

        // a withheld variable whose reference the machine no longer has is dropped at the next change
        let (_other_dir, other) = bindings_db(&format!("{name}-gone"), |r| {
            r.credential_withheld_variables.insert("GONE".into());
        });
        let after = change(
            &other,
            &format!("{name}-gone"),
            BindingsChanger::Untrusted,
            &[],
        )
        .unwrap();
        assert!(after.credential_withheld_variables.is_empty());
    }

    /// Bindings turn outbound networking on at launch, so a machine whose networking is off takes no binding change
    /// that adds one; a machine created before bindings implied networking keeps changing its bindings, and removing
    /// every binding is always allowed.
    #[test]
    fn a_binding_change_never_turns_networking_back_on() {
        let name = format!("cred-test-offline-{}", std::process::id());
        let (_db_dir, db) = bindings_db(&name, |r| r.network = false);
        let gh = BindingsChanger::Operator {
            defines: &["gh".to_string()],
        };
        for changer in [gh, BindingsChanger::Untrusted] {
            let refused = change(&db, &name, changer, &["gh=GH_TOKEN@github.com"]).unwrap_err();
            assert!(refused.to_string().contains("networking off"), "{refused}");
            let record = db.get_vm(&name).unwrap().unwrap();
            assert_eq!(record.credential_policy, None);
            assert!(!record.launch_network_plan().outbound);
        }
        change(&db, &name, BindingsChanger::Untrusted, &[]).unwrap();

        let legacy = format!("cred-test-legacy-{}", std::process::id());
        let (_legacy_dir, legacy_db) = bindings_db(&legacy, |r| {
            r.network = false;
            r.credential_policy = Some(policy_of(&["a=A_KEY@api.a.com"]));
        });
        let kept = change(
            &legacy_db,
            &legacy,
            gh,
            &["a=A_KEY@api.a.com", "gh=GH_TOKEN@github.com"],
        )
        .unwrap();
        assert_eq!(kept.credential_policy.unwrap().credentials.len(), 2);

        let online = format!("cred-test-online-{}", std::process::id());
        let (_online_dir, online_db) = bindings_db(&online, |_| {});
        change(&online_db, &online, gh, &["gh=GH_TOKEN@github.com"]).unwrap();
    }

    /// Networking turned off between reading the record and saving the bindings still refuses the change.
    #[test]
    fn networking_turned_off_during_a_binding_change_refuses_it() {
        let name = format!("cred-test-offline-race-{}", std::process::id());
        let (_db_dir, db) = bindings_db(&name, |_| {});
        let (_lock_dir, lock) = test_lock(&name);
        let refused = set_bindings_in(&db, &name, &lock, BindingsChanger::Untrusted, |_| {
            // as `machine update --no-net` would, after this change read the record
            db.update_vm(&name, |r| r.network = false).unwrap();
            Ok(policy_of(&["gh=GH_TOKEN@github.com"]))
        })
        .err()
        .expect("refused");
        assert!(refused.to_string().contains("networking off"), "{refused}");
        let record = db.get_vm(&name).unwrap().unwrap();
        assert_eq!(record.credential_policy, None);
        assert!(!record.launch_network_plan().outbound);
    }

    /// Turning networking off under a machine's bindings is refused: they would keep it reaching the internet while
    /// it reports networking off.
    #[test]
    fn networking_never_turns_off_under_bindings() {
        let mut record = VmRecord::new("offline".into(), 1, 512, Vec::new(), Vec::new(), true);
        record.credential_policy = Some(policy_of(&["gh=GH_TOKEN@github.com"]));
        let refused = record
            .replace_egress(false, Vec::new(), Vec::new())
            .unwrap_err();
        assert!(
            refused.to_string().contains("credential bindings"),
            "{refused}"
        );
        assert!(record.network);
        record.credential_policy = None;
        record
            .replace_egress(false, Vec::new(), Vec::new())
            .unwrap();
        assert!(!record.network);
    }

    /// Binding changes and the values handed over after them are serialized per machine across processes: a second
    /// holder (here another open of the lock file) waits until the first lets go.
    #[test]
    fn binding_changes_to_one_machine_wait_for_each_other() {
        if !crate::test_support::in_own_process!() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("m.credential-bindings.lock");
        let name = "cred-test-lock";
        let first = lock_bindings_at(&path, name, BINDINGS_LOCK_TIMEOUT).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let waiter = {
            let path = path.clone();
            std::thread::spawn(move || {
                let _second = lock_bindings_at(&path, name, BINDINGS_LOCK_TIMEOUT).unwrap();
                tx.send(()).unwrap();
            })
        };
        assert!(rx
            .recv_timeout(std::time::Duration::from_millis(200))
            .is_err());
        drop(first);
        rx.recv_timeout(std::time::Duration::from_secs(10)).unwrap();
        waiter.join().unwrap();

        // a lock held for one machine changes no other
        let (_db_dir, db) = bindings_db(name, |_| {});
        let (_other_dir, other) = test_lock("cred-test-lock-other");
        let refused = set_bindings_in(&db, name, &other, BindingsChanger::Untrusted, |_| {
            Ok(policy_of(&["gh=GH_TOKEN@github.com"]))
        });
        assert!(refused.is_err());
    }

    /// A holder that never lets go (a stuck process, or anyone else who got hold of the file) costs a waiter a bounded
    /// wait and a clear conflict, never a hang: an API handler waiting on it would stall the machine's lifecycle.
    #[test]
    fn a_held_bindings_lock_times_out_with_a_clear_error() {
        if !crate::test_support::in_own_process!() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("m.credential-bindings.lock");
        let _held = lock_bindings_at(&path, "stuck", BINDINGS_LOCK_TIMEOUT).unwrap();
        let started = std::time::Instant::now();
        let refused = lock_bindings_at(&path, "stuck", std::time::Duration::from_millis(300))
            .err()
            .expect("a held lock times out");
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        assert_eq!(refused.code(), "CONFLICT");
        assert!(refused.to_string().contains("machine 'stuck'"), "{refused}");
    }

    /// The lock sits beside the machine's data directory and goes with it on delete.
    #[test]
    fn a_deleted_machines_bindings_lock_is_removed() {
        let root = tempfile::tempdir().unwrap();
        let data_dir = root.path().join("0123456789abcdef");
        let path = bindings_lock_beside(&data_dir);
        assert_eq!(
            path,
            root.path()
                .join("0123456789abcdef.credential-bindings.lock")
        );
        drop(lock_bindings_at(&path, "m", BINDINGS_LOCK_TIMEOUT).unwrap());
        assert!(path.is_file());
        remove_bindings_lock(&data_dir);
        assert!(!path.exists());
        remove_bindings_lock(&data_dir);
    }

    /// Lock files are private to their owner, since anyone who can open one can hold it: created 0600, and an
    /// existing one that others can open, or a link in its place, refused rather than used or followed.
    #[cfg(unix)]
    #[test]
    fn bindings_lock_files_are_private_to_their_owner() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let dir = tempfile::tempdir().unwrap();
        let fresh = dir.path().join("a.credential-bindings.lock");
        drop(lock_bindings_at(&fresh, "a", BINDINGS_LOCK_TIMEOUT).unwrap());
        assert_eq!(mode(&fresh), 0o600);
        // and taken again as it is
        drop(lock_bindings_at(&fresh, "a", BINDINGS_LOCK_TIMEOUT).unwrap());

        let wide = dir.path().join("b.credential-bindings.lock");
        std::fs::write(&wide, "").unwrap();
        std::fs::set_permissions(&wide, std::fs::Permissions::from_mode(0o644)).unwrap();
        let refused = lock_bindings_at(&wide, "b", BINDINGS_LOCK_TIMEOUT)
            .err()
            .expect("refused");
        assert!(refused.to_string().contains("open to others"), "{refused}");
        assert_eq!(mode(&wide), 0o644);

        let target = dir.path().join("elsewhere");
        std::fs::write(&target, "").unwrap();
        let link = dir.path().join("c.credential-bindings.lock");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(lock_bindings_at(&link, "c", BINDINGS_LOCK_TIMEOUT).is_err());
    }

    /// An existing lock with another name (a hard link to some other file, which root would otherwise take over) is
    /// refused and never changed.
    #[cfg(unix)]
    #[test]
    fn a_hard_linked_lock_file_is_refused_and_left_alone() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let dir = tempfile::tempdir().unwrap();
        let precious = dir.path().join("sudoers");
        std::fs::write(&precious, "root ALL=(ALL) ALL").unwrap();
        std::fs::set_permissions(&precious, std::fs::Permissions::from_mode(0o600)).unwrap();
        let before = std::fs::metadata(&precious).unwrap();
        let lock = dir.path().join("d.credential-bindings.lock");
        std::fs::hard_link(&precious, &lock).unwrap();
        let refused = lock_bindings_at(&lock, "d", BINDINGS_LOCK_TIMEOUT)
            .err()
            .expect("refused");
        assert!(refused.to_string().contains("2 names"), "{refused}");
        let after = std::fs::metadata(&precious).unwrap();
        assert_eq!(
            (after.uid(), after.gid(), after.mode()),
            (before.uid(), before.gid(), before.mode())
        );
    }

    /// A machine deleted and created again under its name while a change was planned for the old one takes nothing:
    /// the new machine's record is never given bindings planned against the old.
    #[test]
    fn a_machine_recreated_during_a_binding_change_refuses_it() {
        let name = format!("cred-test-recreated-{}", std::process::id());
        let (_db_dir, db) = bindings_db(&name, |_| {});
        let (_lock_dir, lock) = test_lock(&name);
        let refused = set_bindings_in(&db, &name, &lock, BindingsChanger::Untrusted, |_| {
            db.remove_vm(&name).unwrap();
            let mut successor = VmRecord::new(name.clone(), 1, 512, Vec::new(), Vec::new(), true);
            successor.created_at += 1;
            db.insert_vm(&name, &successor).unwrap();
            Ok(policy_of(&["gh=GH_TOKEN@github.com"]))
        })
        .err()
        .expect("refused");
        assert_eq!(refused.code(), "CONFLICT", "{refused}");
        assert_eq!(db.get_vm(&name).unwrap().unwrap().credential_policy, None);
    }

    /// A change to a machine that does not exist leaves no lock file behind.
    #[test]
    fn a_change_to_a_missing_machine_leaves_no_lock_file() {
        let dir = tempfile::tempdir().unwrap();
        let db = crate::db::SmolvmDb::open_at(&dir.path().join("smolvm.db")).unwrap();
        let path = dir.path().join("m.credential-bindings.lock");
        let lock = lock_bindings_at(&path, "missing", BINDINGS_LOCK_TIMEOUT).unwrap();
        assert!(
            set_bindings_in(&db, "missing", &lock, BindingsChanger::Untrusted, |_| {
                Ok(CredentialPolicy::default())
            })
            .is_err()
        );
        assert!(!path.exists());
    }
}
