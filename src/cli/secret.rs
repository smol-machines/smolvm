//! `smolvm secret` — manage the host-side encrypted secret store.
//!
//! Secrets are stored encrypted in `~/.config/smolvm/secrets.toml` with a
//! local master key at `~/.local/share/smolvm/secrets.key`. At workload
//! launch time, referenced secrets are decrypted and injected into the
//! target process env via the existing vsock `env` plumbing.

use clap::{Args, Subcommand};
use smolvm::secrets::{SecretKind, SecretStore};
use smolvm::Result;
use std::path::PathBuf;

/// Manage host-side secrets for injection into workloads.
#[derive(Subcommand, Debug)]
pub enum SecretCmd {
    /// Store a secret. Prompts for the value if not given on the command line
    /// or via a source flag.
    Set(SetCmd),

    /// List stored secrets by name (values are never printed).
    #[command(visible_alias = "ls")]
    List,

    /// Delete a stored secret by name.
    #[command(visible_alias = "rm")]
    Delete(DeleteCmd),

    /// Print a stored secret's plaintext value (requires --yes).
    Show(ShowCmd),

    /// Print the filesystem path to the secret store TOML.
    Path,
}

impl SecretCmd {
    pub fn run(self) -> Result<()> {
        match self {
            SecretCmd::Set(cmd) => cmd.run(),
            SecretCmd::List => run_list(),
            SecretCmd::Delete(cmd) => cmd.run(),
            SecretCmd::Show(cmd) => cmd.run(),
            SecretCmd::Path => {
                let p = SecretStore::store_path()?;
                println!("{}", p.display());
                Ok(())
            }
        }
    }
}

// ============================================================================
// set
// ============================================================================

/// Store a secret.
///
/// By default, stores a literal value encrypted at rest. Use `--from-env` or
/// `--from-file` to store an indirection — the actual value is read from the
/// host environment or filesystem at workload launch time.
#[derive(Args, Debug)]
pub struct SetCmd {
    /// Secret name (used as the guest env var when referenced as
    /// `{ from_store = "NAME" }` in a Smolfile).
    pub name: String,

    /// Inline value. If omitted and no --from-* flag is used, reads from
    /// stdin with tty echo disabled.
    #[arg(conflicts_with_all = ["from_env", "from_file"])]
    pub value: Option<String>,

    /// Store an indirection to a host environment variable (value is read
    /// at workload launch time, not stored on disk).
    #[arg(long, value_name = "VAR", conflicts_with = "from_file")]
    pub from_env: Option<String>,

    /// Store an indirection to a host file path (contents are read at
    /// workload launch time, not stored on disk).
    #[arg(long, value_name = "PATH")]
    pub from_file: Option<PathBuf>,
}

impl SetCmd {
    pub fn run(self) -> Result<()> {
        SecretStore::with_lock(|store| self.apply(store))?;
        println!("Stored secret '{}'.", self.name);
        Ok(())
    }

    fn apply(&self, store: &mut SecretStore) -> Result<()> {
        if let Some(env_var) = &self.from_env {
            store.set_env(&self.name, env_var)?;
        } else if let Some(path) = &self.from_file {
            // Require the file to exist at set time. This gives one
            // consistent persisted shape (canonicalized absolute path
            // with symlinks resolved) instead of a filesystem-timing-
            // dependent mixture. It also catches typos up front.
            // If the user wants a ref to a file they haven't created
            // yet, they create the file first — one extra step, no
            // surprises.
            let canonical = std::fs::canonicalize(path).map_err(|e| {
                smolvm::Error::config(
                    "set file secret",
                    format!("file '{}' must exist at set time: {}", path.display(), e),
                )
            })?;
            // `canonicalize` resolves the last symlink to its target,
            // so by the time we reach `set_file` the path no longer
            // points through a symlink chain. `set_file` enforces the
            // absolute-path invariant as a final gate.
            store.set_file(&self.name, &canonical)?;
        } else if let Some(v) = &self.value {
            store.set_value(&self.name, v)?;
        } else {
            // Prompt for value without echo.
            let value = rpassword::prompt_password(format!("Value for '{}': ", self.name))
                .map_err(|e| smolvm::Error::config("read secret from tty", e.to_string()))?;
            if value.is_empty() {
                return Err(smolvm::Error::config(
                    "set secret",
                    "empty value is not allowed",
                ));
            }
            store.set_value(&self.name, &value)?;
        }

        Ok(())
    }
}

// ============================================================================
// list
// ============================================================================

fn run_list() -> Result<()> {
    let store = SecretStore::load()?;
    let entries = store.list();
    if entries.is_empty() {
        println!("No secrets stored.");
        if let Ok(p) = SecretStore::store_path() {
            println!();
            println!("Store location: {}", p.display());
            println!("Add one with: smolvm secret set <NAME>");
        }
        return Ok(());
    }

    // Widest name for alignment.
    let w = entries
        .iter()
        .map(|(n, _)| n.len())
        .max()
        .unwrap_or(4)
        .max(4);

    println!("{:<width$}  SOURCE", "NAME", width = w);
    for (name, kind) in entries {
        println!("{:<width$}  {}", name, display_kind(kind), width = w);
    }
    Ok(())
}

fn display_kind(k: SecretKind) -> &'static str {
    k.as_str()
}

// ============================================================================
// delete
// ============================================================================

/// Delete a stored secret by name.
#[derive(Args, Debug)]
pub struct DeleteCmd {
    /// Name of the secret to delete.
    pub name: String,
}

impl DeleteCmd {
    pub fn run(self) -> Result<()> {
        SecretStore::with_lock(|store| {
            if !store.delete(&self.name) {
                return Err(smolvm::Error::config(
                    "delete secret",
                    format!("no secret named '{}'", self.name),
                ));
            }
            Ok(())
        })?;
        println!("Deleted secret '{}'.", self.name);
        Ok(())
    }
}

// ============================================================================
// show
// ============================================================================

/// Reveal a stored secret's plaintext value.
///
/// Requires `--yes` to confirm you actually want the value printed to stdout
/// (where it could leak into terminal scrollback, pipes, shell history, etc).
#[derive(Args, Debug)]
pub struct ShowCmd {
    /// Name of the secret to reveal.
    pub name: String,

    /// Confirm that you want the plaintext value on stdout.
    #[arg(long)]
    pub yes: bool,
}

impl ShowCmd {
    pub fn run(self) -> Result<()> {
        if !self.yes {
            return Err(smolvm::Error::config(
                "show secret",
                "refusing to print plaintext without --yes",
            ));
        }
        let store = SecretStore::load()?;
        let value = store.reveal_as_error(&self.name)?;
        // println adds a newline; use print! and then explicit newline so the
        // final write is a single atomic operation.
        print!("{}", &*value);
        println!();
        Ok(())
    }
}
