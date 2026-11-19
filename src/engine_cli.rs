//! Route internal engine commands through the embedding executable's CLI.

use std::{
    io,
    path::{Path, PathBuf},
    process::Command,
    sync::OnceLock,
};

struct Registration {
    executable: PathBuf,
    prefix: &'static [&'static str],
}

static REGISTRATION: OnceLock<Registration> = OnceLock::new();

/// Register the argument prefix under which this executable exposes the engine.
/// Call at CLI entry, before starting runtime work. Standalone engines need no
/// registration; an embedding CLI such as `smol` registers `&["_engine"]`.
pub fn register(prefix: &'static [&'static str]) -> io::Result<()> {
    let executable = std::env::current_exe()?.canonicalize()?;
    let registration = REGISTRATION.get_or_init(|| Registration {
        executable: executable.clone(),
        prefix,
    });
    if registration.executable != executable || registration.prefix != prefix {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "the engine CLI prefix is already registered",
        ));
    }
    Ok(())
}

pub(crate) fn command(executable: &Path) -> Command {
    configured_command(executable, REGISTRATION.get())
}

fn configured_command(executable: &Path, registration: Option<&Registration>) -> Command {
    let mut command = Command::new(executable);
    if let Some(registration) = registration {
        // An SDK may supply a different, standalone boot helper. Never give
        // that helper the embedding application's command prefix.
        if executable == registration.executable
            || executable.canonicalize().ok().as_ref() == Some(&registration.executable)
        {
            command.args(registration.prefix);
        }
    }
    command
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_commands_use_the_embedding_prefix_only_for_the_registered_executable() {
        let root = tempfile::tempdir().unwrap();
        let executable = root.path().join("renamed smol");
        std::fs::write(&executable, []).unwrap();
        let registration = Registration {
            executable: executable.canonicalize().unwrap(),
            prefix: &["_engine"],
        };
        let mut command = configured_command(&executable, Some(&registration));
        command.args(["machine", "delete", "--name", "builder", "-f"]);
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            ["_engine", "machine", "delete", "--name", "builder", "-f"]
        );
        assert_eq!(
            configured_command(&root.path().join("smolvm"), Some(&registration))
                .get_args()
                .count(),
            0
        );
        assert_eq!(configured_command(&executable, None).get_args().count(), 0);
        #[cfg(unix)]
        {
            let link = root.path().join("linked smol");
            std::os::unix::fs::symlink(&executable, &link).unwrap();
            assert_eq!(
                configured_command(&link, Some(&registration))
                    .get_args()
                    .collect::<Vec<_>>(),
                ["_engine"]
            );
        }
    }
}
