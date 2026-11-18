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
    Ok(BindingChange {
        policy,
        placeholders,
        trust_changed,
    })
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

/// Replace `name`'s credential bindings with `policy` ([`plan_binding_change`]), saved for its next start and handed
/// at once to the machine when it runs. A machine that booted without bindings runs no interceptor, so it takes them
/// from its next start. An added binding resolves from its variable, or from a value handed over after it
/// (`machine credentials refresh`, `PUT …/credential-values`).
pub fn set_bindings(name: &str, policy: CredentialPolicy) -> Result<BindingsSet> {
    let db = crate::db::SmolvmDb::open()?;
    let record = db.get_vm(name)?.ok_or_else(|| Error::vm_not_found(name))?;
    let change = plan_binding_change(name, &record, policy)?;
    let saved = db
        .update_vm_durable(name, |r| {
            r.credential_policy = (!change.policy.is_empty()).then(|| change.policy.clone());
            r.credential_placeholders = change.placeholders.clone();
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
        crate::agent::apply_live_credential_bindings(name, &change)?;
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

/// What a bindings change reaches in the machine's process: the interceptor, the sources its resolver reads, and the
/// CA directory the caller added a CA to.
struct LiveBindings {
    control: smolvm_credentials::InterceptorControl,
    sources: Arc<std::sync::RwLock<BTreeMap<String, SecretRef>>>,
    ca_dir: PathBuf,
    ca_owner: String,
}

/// Serve [`CREDENTIALS_SOCKET`] in `vm_dir`: each connection sends
/// `{"values":{"<binding>":"<value>",…}}` or `{"bindings":{"policy":…,"placeholders":…}}` and gets back `ok` or
/// `error: <reason>`. Values replace those the machine resolves for the bindings named, from its next request on; a
/// name that is not a binding changes nothing. Bindings replace the machine's bindings: an added one resolves from
/// its variable (or a value handed over after it), a removed one is no longer intercepted and its values are
/// dropped, and a CA the caller added for a new host signs that host from the next connection.
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
    }
    let bindings: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(
        policy.credentials.iter().map(|b| b.name.clone()).collect(),
    ));
    let path = vm_dir.join(CREDENTIALS_SOCKET);
    let _ = std::fs::remove_file(&path);
    crate::network::launch::serve_control_socket(
        path,
        "credentials-control",
        MAX_CREDENTIALS_REQUEST_BYTES,
        move |request| {
            let request: Request =
                serde_json::from_str(request).map_err(|_| "malformed request".to_string())?;
            if let Some(next) = request.bindings {
                let Some(change) = change.as_ref() else {
                    return Err("this machine cannot change its bindings while it runs".to_string());
                };
                let names: Vec<String> = next
                    .policy
                    .credentials
                    .iter()
                    .map(|b| b.name.clone())
                    .collect();
                {
                    let mut sources = change.sources.write().unwrap_or_else(|e| e.into_inner());
                    sources.retain(|name, _| names.contains(name));
                    for b in &next.policy.credentials {
                        sources.entry(b.name.clone()).or_insert_with(|| {
                            crate::secrets::env_ref(b.environment_variable.clone())
                        });
                    }
                }
                live.lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .retain(|name, _| names.contains(name));
                change.control.update(
                    next.policy,
                    next.placeholders,
                    load_extra_cas(&change.ca_dir, &change.ca_owner),
                );
                *bindings.lock().unwrap_or_else(|e| e.into_inner()) = names.clone();
                tracing::info!(bindings = ?names, "credential bindings replaced");
            }
            let known = bindings.lock().unwrap_or_else(|e| e.into_inner()).clone();
            if let Some(unknown) = request.values.keys().find(|k| !known.contains(k)) {
                return Err(format!("no credential binding '{unknown}'"));
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
