//! `smolvm completion <shell>` prints a static completion script.
//!
//! The script comes from the clap command tree. Hidden internal commands
//! (`_boot-vm` and the other re-exec helpers) are dropped first, so tab
//! completion offers the same commands as `smolvm --help`. Installing the
//! script is left to the caller.

use std::io::{self, Write};

use clap::Command;
use clap_complete::{Generator, Shell};

pub const AFTER_HELP: &str = "\
Prints the script to stdout and does not install it. Load it from your shell's startup file:

  echo 'eval \"$(smolvm completion bash)\"' >> ~/.bashrc
  echo 'source <(smolvm completion zsh)' >> ~/.zshrc
  mkdir -p ~/.config/fish/completions
  smolvm completion fish > ~/.config/fish/completions/smolvm.fish
  smolvm completion powershell >> $PROFILE

The zsh script can also be written to a file named `_smolvm` on `fpath` (that is the name zsh looks up).
";

/// A copy of `cmd` with hidden subcommands removed, at every level.
///
/// clap_complete lists every subcommand, including ones marked `hide`, so the
/// internal re-exec helpers would show up next to `machine` and `pack`.
/// Rebuilding the tree is the way to drop them: `Command` has no public
/// remove-subcommand.
pub fn without_hidden(cmd: &Command) -> Command {
    let mut visible = Command::new(cmd.get_name().to_owned());
    if let Some(about) = cmd.get_about() {
        visible = visible.about(about.to_string());
    }
    for alias in cmd.get_visible_aliases() {
        visible = visible.visible_alias(alias.to_owned());
    }
    for arg in cmd.get_arguments() {
        visible = visible.arg(arg.clone());
    }
    for sub in cmd.get_subcommands() {
        if sub.is_hide_set() {
            continue;
        }
        visible = visible.subcommand(without_hidden(sub));
    }
    visible
}

/// Write `shell`'s completion script for `cmd` to `out`.
///
/// The script is buffered first. `clap_complete` treats a closed stdout
/// (`smolvm completion bash | head`) as a fatal write error; a full buffer
/// lets us surface that as a normal `ErrorKind::BrokenPipe` instead.
pub fn write(shell: Shell, cmd: &mut Command, out: &mut dyn Write) -> io::Result<()> {
    cmd.set_bin_name("smolvm");
    cmd.build();
    let mut buf = Vec::new();
    shell.try_generate(cmd, &mut buf)?;
    out.write_all(&buf)?;
    out.flush()
}

/// Print `shell`'s completion script to stdout.
pub fn print(shell: Shell, cmd: &mut Command) -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    match write(shell, cmd, &mut stdout) {
        Err(err) if err.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        result => result,
    }
}
