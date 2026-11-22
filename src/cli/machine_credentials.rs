//! A running machine's credential values, changed without a restart.
//!
//! A binding (`--credential NAME=ENV_VAR@HOST`) reads its value from the host when the machine starts, and the
//! machine's host process keeps that environment, so a rotated value used to need a teardown. `refresh` reads each
//! binding's variable from *this* process instead and hands the values to the running machine over its credentials
//! socket, where they take precedence from the next request: `capy run -c -- smolvm machine credentials refresh
//! --name notes` rotates Capy's values in place (Capy, 2026-11-18).
use clap::{Args, Subcommand};
use std::collections::BTreeMap;

/// Manage a machine's credential values
#[derive(Args, Debug)]
pub struct CredentialsCmd {
    #[command(subcommand)]
    pub cmd: CredentialsSub,
}

#[derive(Subcommand, Debug)]
pub enum CredentialsSub {
    /// Hand a running machine the current values of its credential bindings, read now from this
    /// shell's environment (each binding's ENV_VAR), without restarting it
    Refresh(RefreshCmd),

    /// Add credential bindings to a machine, live when it runs: each value is read now from this shell
    Add(AddCmd),

    /// Remove credential bindings from a machine, live when it runs
    Remove(RemoveCmd),
}

#[derive(Args, Debug)]
pub struct AddCmd {
    /// Machine to change (default: "default")
    #[arg(short = 'n', long, value_name = "NAME", env = smolvm::data::consts::ENV_SMOLVM_MACHINE_NAME)]
    pub name: Option<String>,

    /// A binding to add, as on `machine create`: NAME=ENV_VAR@HOST[,HOST...][:body][:set-header=HEADER]. A binding of
    /// the same name is replaced.
    #[arg(long = "credential", value_name = "SPEC", required = true)]
    pub credentials: Vec<String>,
}

#[derive(Args, Debug)]
pub struct RemoveCmd {
    /// Machine to change (default: "default")
    #[arg(short = 'n', long, value_name = "NAME", env = smolvm::data::consts::ENV_SMOLVM_MACHINE_NAME)]
    pub name: Option<String>,

    /// Bindings to remove
    #[arg(value_name = "BINDING", required = true)]
    pub bindings: Vec<String>,
}

/// Say what a bindings change did.
fn report(name: &str, set: &smolvm::credentials::BindingsSet) {
    if set.live {
        eprintln!("machine '{name}' uses its new credential bindings from its next request");
    } else if set.at_next_start {
        eprintln!(
            "machine '{name}' booted without credential bindings: they apply from its next start"
        );
    } else {
        eprintln!("machine '{name}' uses its new credential bindings from its next start");
    }
}

impl AddCmd {
    pub fn run(self) -> smolvm::Result<()> {
        let name = self.name.unwrap_or_else(|| "default".to_string());
        let mut added = Vec::new();
        for spec in &self.credentials {
            let binding = smolvm::credentials::parse_credential_flag(spec)
                .map_err(|why| smolvm::Error::config("credentials", why))?;
            added.retain(|b: &smolvm::credentials::CredentialBinding| b.name != binding.name);
            added.push(binding);
        }
        // read before anything changes, so an unset variable changes nothing
        let vars: Vec<(String, String)> = added
            .iter()
            .map(|b| (b.name.clone(), b.environment_variable.clone()))
            .collect();
        let names: Vec<String> = vars.iter().map(|(n, _)| n.clone()).collect();
        let values = refresh_values(&vars, &names, |var| std::env::var(var).ok())
            .map_err(|why| smolvm::Error::config("credentials", why))?;
        // held until the values are handed over, so no other change can retarget a binding in between
        let lock = smolvm::credentials::lock_bindings(&name)?;
        let set = smolvm::credentials::set_bindings(
            &name,
            &lock,
            smolvm::credentials::BindingsChanger::Operator { defines: &names },
            |record| {
                let mut policy = record.credential_policy.clone().unwrap_or_default();
                policy
                    .credentials
                    .retain(|b| !added.iter().any(|a| a.name == b.name));
                policy.credentials.extend(added.iter().cloned());
                Ok(policy)
            },
        )?;
        let host_sourced: BTreeMap<_, _> = values
            .into_iter()
            .filter(|(binding, _)| set.record.credential_host_sourced(binding))
            .collect();
        if set.live && !host_sourced.is_empty() {
            smolvm::agent::apply_live_credential_values(&name, &host_sourced)?;
        }
        report(&name, &set);
        Ok(())
    }
}

impl RemoveCmd {
    pub fn run(self) -> smolvm::Result<()> {
        let name = self.name.unwrap_or_else(|| "default".to_string());
        let lock = smolvm::credentials::lock_bindings(&name)?;
        let set = smolvm::credentials::set_bindings(
            &name,
            &lock,
            smolvm::credentials::BindingsChanger::Operator { defines: &[] },
            |record| {
                let mut policy = record.credential_policy.clone().unwrap_or_default();
                if let Some(unknown) = self
                    .bindings
                    .iter()
                    .find(|b| !policy.credentials.iter().any(|c| &c.name == *b))
                {
                    return Err(smolvm::Error::config(
                        "credentials",
                        format!("no credential binding '{unknown}'"),
                    ));
                }
                policy
                    .credentials
                    .retain(|b| !self.bindings.contains(&b.name));
                Ok(policy)
            },
        )?;
        report(&name, &set);
        Ok(())
    }
}

#[derive(Args, Debug)]
pub struct RefreshCmd {
    /// Machine to refresh (default: "default")
    #[arg(short = 'n', long, value_name = "NAME", env = smolvm::data::consts::ENV_SMOLVM_MACHINE_NAME)]
    pub name: Option<String>,

    /// Bindings to refresh (default: all of the machine's bindings)
    #[arg(value_name = "BINDING")]
    pub bindings: Vec<String>,
}

impl CredentialsCmd {
    pub fn run(self) -> smolvm::Result<()> {
        match self.cmd {
            CredentialsSub::Refresh(cmd) => cmd.run(),
            CredentialsSub::Add(cmd) => cmd.run(),
            CredentialsSub::Remove(cmd) => cmd.run(),
        }
    }
}

/// The values to hand over: each chosen binding's variable from `env`, or the bindings whose variable is unset.
pub fn refresh_values(
    bindings: &[(String, String)],
    chosen: &[String],
    env: impl Fn(&str) -> Option<String>,
) -> Result<BTreeMap<String, zeroize::Zeroizing<String>>, String> {
    if let Some(unknown) = chosen
        .iter()
        .find(|c| !bindings.iter().any(|(name, _)| name == *c))
    {
        return Err(format!("no credential binding '{unknown}'"));
    }
    let mut values = BTreeMap::new();
    let mut missing = Vec::new();
    for (name, var) in bindings
        .iter()
        .filter(|(name, _)| chosen.is_empty() || chosen.contains(name))
    {
        match env(var).filter(|v| !v.is_empty()) {
            Some(value) => {
                let value = zeroize::Zeroizing::new(value);
                smolvm_credentials::check_credential_value(name, &value)?;
                values.insert(name.clone(), value);
            }
            None => missing.push(format!("{name} (${var})")),
        }
    }
    if !missing.is_empty() {
        return Err(format!(
            "not set in this environment: {}",
            missing.join(", ")
        ));
    }
    Ok(values)
}

/// The bindings `refresh` reads from this shell: only those this host's operator defined. A binding an HTTP API caller
/// or embedder set takes only the values that caller supplies, so this shell's variable must never reach it.
pub fn host_sourced_bindings(record: &smolvm::config::VmRecord) -> Vec<(String, String)> {
    record
        .credential_policy
        .iter()
        .flat_map(|p| p.credentials.iter())
        .filter(|b| record.credential_host_sourced(&b.name))
        .map(|b| (b.name.clone(), b.environment_variable.clone()))
        .collect()
}

impl RefreshCmd {
    pub fn run(self) -> smolvm::Result<()> {
        let name = self.name.unwrap_or_else(|| "default".to_string());
        // held until the values are handed over, so no other change can retarget a binding in between
        let lock = smolvm::credentials::lock_bindings(&name)?;
        let Some(record) = smolvm::db::SmolvmDb::open()?.get_vm(&name)? else {
            lock.remove_if_machine_gone();
            return Err(smolvm::Error::config(
                "credentials",
                format!("machine '{name}' not found"),
            ));
        };
        if record.credentials_supplied_by_api {
            return Err(smolvm::Error::config(
                "credentials",
                format!(
                    "machine '{name}' takes its credential values from the API that created it; \
                     set them with PUT /api/v1/machines/{name}/credential-values"
                ),
            ));
        }
        let bindings = host_sourced_bindings(&record);
        if bindings.is_empty() {
            return Err(smolvm::Error::config(
                "credentials",
                format!("machine '{name}' has no credential bindings defined from this host"),
            ));
        }
        if let Some(supplied) = self.bindings.iter().find(|b| {
            record
                .credential_policy
                .as_ref()
                .and_then(|p| p.binding(b))
                .is_some()
                && !record.credential_host_sourced(b)
        }) {
            return Err(smolvm::Error::config(
                "credentials",
                format!(
                    "credential binding '{supplied}' of machine '{name}' was set over the API and takes \
                     its values only from PUT /api/v1/machines/{name}/credential-values"
                ),
            ));
        }
        let values = refresh_values(&bindings, &self.bindings, |var| std::env::var(var).ok())
            .map_err(|why| smolvm::Error::config("credentials", why))?;
        let names: Vec<&str> = values.keys().map(String::as_str).collect();
        if smolvm::agent::state_probe::resolve_state(&name, &record)
            != smolvm::config::RecordState::Running
        {
            eprintln!(
                "machine '{name}' is not running: it reads {} from the environment of whatever starts it next",
                names.join(", ")
            );
            return Ok(());
        }
        smolvm::agent::apply_live_credential_values(&name, &values)?;
        eprintln!(
            "machine '{name}' uses the new values of {} from its next request",
            names.join(", ")
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{host_sourced_bindings, refresh_values};

    /// `refresh` reads from this shell only the bindings this host's operator defined, never one an API caller or
    /// embedder set (here `evil`, naming a variable of this shell for its own host), nor any binding of a machine
    /// whose bindings all came from the API.
    #[test]
    fn refresh_reads_only_bindings_the_operator_defined() {
        let mut record =
            smolvm::config::VmRecord::new("m".into(), 1, 512, Vec::new(), Vec::new(), true);
        record.credential_policy = Some(smolvm::credentials::CredentialPolicy {
            credentials: vec![
                smolvm::credentials::parse_credential_flag("gh=GH_TOKEN@github.com").unwrap(),
                smolvm::credentials::parse_credential_flag(
                    "evil=AWS_SECRET_ACCESS_KEY@attacker.example",
                )
                .unwrap(),
            ],
        });
        record.credentials_supplied_bindings.insert("evil".into());
        assert_eq!(
            host_sourced_bindings(&record),
            vec![("gh".to_string(), "GH_TOKEN".to_string())]
        );
        let env = |v: &str| Some(format!("value-of-{v}"));
        let values = refresh_values(&host_sourced_bindings(&record), &[], env).unwrap();
        assert!(!values.contains_key("evil"));
        assert!(refresh_values(&host_sourced_bindings(&record), &["evil".into()], env).is_err());
        record.credentials_supplied_by_api = true;
        assert!(host_sourced_bindings(&record).is_empty());
    }

    fn bindings() -> Vec<(String, String)> {
        vec![
            ("notion".into(), "NOTION_API_KEY".into()),
            ("gh".into(), "GH_TOKEN".into()),
        ]
    }

    #[test]
    fn every_binding_is_read_from_this_environment() {
        let env = |v: &str| Some(format!("value-of-{v}"));
        let got = refresh_values(&bindings(), &[], env).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got["notion"].as_str(), "value-of-NOTION_API_KEY");
    }

    #[test]
    fn named_bindings_only_and_unknown_or_unset_ones_are_refused() {
        let env = |v: &str| (v == "GH_TOKEN").then(|| "t".to_string());
        assert_eq!(
            refresh_values(&bindings(), &["gh".into()], env)
                .unwrap()
                .len(),
            1
        );
        assert!(refresh_values(&bindings(), &["nope".into()], env)
            .unwrap_err()
            .contains("no credential binding 'nope'"));
        assert!(refresh_values(&bindings(), &[], env)
            .unwrap_err()
            .contains("notion ($NOTION_API_KEY)"));
    }
}
