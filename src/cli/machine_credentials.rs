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
                values.insert(name.clone(), zeroize::Zeroizing::new(value));
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

impl RefreshCmd {
    pub fn run(self) -> smolvm::Result<()> {
        let name = self.name.unwrap_or_else(|| "default".to_string());
        let record = smolvm::db::SmolvmDb::open()?
            .get_vm(&name)?
            .ok_or_else(|| {
                smolvm::Error::config("credentials", format!("machine '{name}' not found"))
            })?;
        if record.credentials_supplied_by_api {
            return Err(smolvm::Error::config(
                "credentials",
                format!(
                    "machine '{name}' takes its credential values from the API that created it; \
                     set them with PUT /api/v1/machines/{name}/credential-values"
                ),
            ));
        }
        let bindings: Vec<(String, String)> = record
            .credential_policy
            .iter()
            .flat_map(|p| p.credentials.iter())
            .map(|b| (b.name.clone(), b.environment_variable.clone()))
            .collect();
        if bindings.is_empty() {
            return Err(smolvm::Error::config(
                "credentials",
                format!("machine '{name}' has no credential bindings"),
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
    use super::refresh_values;

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
