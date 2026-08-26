//! smolvm CLI entry point.

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

mod cli;

/// smolvm - build and run portable, self-contained virtual machines
#[derive(Parser, Debug)]
#[command(name = "smolvm", bin_name = "smolvm")]
#[command(
    about = "Build and run portable, self-contained virtual machines",
    after_help = "Agents: run `smolvm --help` for full documentation including CLI reference and Smolfile schema"
)]
#[command(
    long_about = include_str!("../AGENTS.md")
)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Manage machines (create, start, stop, exec)
    /// (boxed: the machine arg structs dwarf every other variant)
    #[command(subcommand, visible_alias = "vm")]
    Machine(Box<cli::machine::MachineCmd>),

    /// Start the HTTP API server for programmatic control
    #[command(subcommand)]
    Serve(cli::serve::ServeCmd),

    /// Package and run self-contained VM executables
    #[command(subcommand)]
    Pack(Box<cli::pack::PackCmd>),

    /// Manage smolvm configuration (registries, defaults)
    #[command(subcommand)]
    Config(cli::config::ConfigCmd),

    /// Internal: boot a VM subprocess (not for direct use)
    #[command(name = "_boot-vm", hide = true)]
    BootVm {
        /// Path to boot config JSON file
        config: std::path::PathBuf,
    },

    /// Internal: run the shared CUDA daemon (not for direct use)
    #[command(name = "_cuda-daemon", hide = true)]
    CudaDaemon {
        /// Control-socket path to bind
        socket: std::path::PathBuf,
    },

    /// Internal: serve one isolating fork-clone connection in its own process
    /// (Path 3 per-clone worker; not for direct use)
    #[command(name = "_cuda-clone-worker", hide = true)]
    CudaCloneWorker {
        /// Accepted connection fd handed over by the daemon
        fd: i32,
    },

    /// Internal: own an NVIDIA MPS controller until the CUDA daemon exits
    #[command(name = "_cuda-mps-supervisor", hide = true)]
    CudaMpsSupervisor {
        /// Bidirectional lifecycle fd handed over by the CUDA daemon
        fd: i32,
    },

    /// Internal: clean up an ephemeral VM after its command exits (not for direct use)
    #[command(name = "_cleanup-ephemeral", hide = true)]
    CleanupEphemeral {
        /// Ephemeral VM name (its data dir + DB record are both keyed by this)
        vm_name: String,
        /// VM process PID
        pid: i32,
        /// Process start time for PID-reuse verification (0 = unknown, skips strict check)
        start_time: u64,
    },
}

/// Executable file stems that are a normal smolvm install, not a packed stub
/// that lost its sidecar.
///
/// `smolvm-bin` is the real binary the installer lays down; the `smolvm` on the
/// user's PATH is a launcher script that sets the library path and `exec`s it.
/// So on every ordinary invocation `current_exe()` is `smolvm-bin`, and treating
/// that as suspicious means warning every user on every command.
const PLAIN_CLI_NAMES: [&str; 2] = ["smolvm", "smolvm-bin"];

/// The "you appear to be a packed stub without its assets" note, or `None` when
/// this executable name is a normal install.
///
/// Split out from `main` so the name rule is testable — the regression this
/// guards against (warning on the shipped `smolvm-bin`) is invisible in a unit
/// test of anything coarser.
fn stray_stub_note(exe_stem: &str) -> Option<String> {
    if PLAIN_CLI_NAMES.contains(&exe_stem) {
        return None;
    }
    Some(format!(
        "note: no packed assets found for '{exe_stem}' (looked for a \
         '{exe_stem}.smolmachine' sidecar next to the executable); \
         running as the plain smolvm CLI. If this is a packed \
         binary, keep its .smolmachine file alongside it."
    ))
}

fn main() {
    // Honor an explicit SMOLVM_DATA_DIR for EVERY command (so the CLI and serve
    // agree on where smolvm state lives) before anything computes a path. The
    // auto /var/lib/smolvm default is serve-only (applied in its run()). Done
    // first, single-threaded, so the set_var is safe.
    smolvm::process::apply_system_data_root(/* allow_auto */ false);

    // Auto-detect packed binary mode BEFORE parsing the normal CLI.
    // If this executable has a `.smolmachine` sidecar, appended assets,
    // or a Mach-O section with packed data, run as a packed binary instead.
    //
    // EXCEPTION: skip auto-detection when re-invoked as `_boot-vm`. On Windows
    // (and any non-fork path) pack rehydrate boots the VM by re-spawning this
    // same packed executable as `current_exe _boot-vm <config.json>`. That child
    // still carries the packed footer/sidecar, so without this guard it would
    // re-trigger packed-mode detection and rehydrate again instead of booting
    // the VM from the config it was handed.
    // Internal re-invocations (`_boot-vm`, `_cuda-daemon`) run the same packed
    // executable but must do their job, not re-trigger packed rehydration.
    let internal = matches!(
        std::env::args_os()
            .nth(1)
            .as_deref()
            .and_then(|s| s.to_str()),
        Some("_boot-vm")
            | Some("_cuda-daemon")
            | Some("_cuda-clone-worker")
            | Some("_cuda-mps-supervisor")
    );
    if !internal {
        if let Some(mode) = smolvm_pack::detect_packed_mode() {
            cli::pack_run::run_as_packed_binary(mode);
        }
        // A packed stub separated from its `.smolmachine` sidecar is
        // byte-identical to the plain CLI, so detection can't hard-fail —
        // but silently becoming a different program strands users (QA
        // BUG-167). An unexpected executable name is the tell: say what
        // happened before falling through to the normal CLI.
        let exe_name = std::env::current_exe()
            .ok()
            .and_then(|p| p.file_stem().map(|s| s.to_string_lossy().into_owned()));
        if let Some(name) = exe_name {
            if let Some(note) = stray_stub_note(&name) {
                eprintln!("{note}");
            }
        }
    }

    let cli = Cli::parse();

    // Initialize logging based on RUST_LOG or default to warn
    init_logging();

    tracing::debug!(version = smolvm::VERSION, "starting smolvm");

    // Execute command
    // Note: orphan cleanup is handled per-command (skipped for ephemeral `machine run`).
    let result = match cli.command {
        Commands::Machine(cmd) => (*cmd).run(),
        Commands::Serve(cmd) => cmd.run(),
        Commands::Pack(cmd) => (*cmd).run(),
        Commands::Config(cmd) => cmd.run(),
        Commands::BootVm { config } => cli::internal_boot::run(config),
        #[cfg(unix)]
        Commands::CudaDaemon { socket } => {
            smolvm::cuda_daemon::run(&socket).map_err(smolvm::Error::Io)
        }
        #[cfg(not(unix))]
        Commands::CudaDaemon { .. } => Err(smolvm::Error::Io(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "the shared CUDA daemon is unix-only",
        ))),
        #[cfg(unix)]
        Commands::CudaCloneWorker { fd } => {
            smolvm::cuda_daemon::run_clone_worker(fd).map_err(smolvm::Error::Io)
        }
        #[cfg(not(unix))]
        Commands::CudaCloneWorker { .. } => Err(smolvm::Error::Io(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "the CUDA clone worker is unix-only",
        ))),
        #[cfg(target_os = "linux")]
        Commands::CudaMpsSupervisor { fd } => {
            smolvm::cuda_daemon::run_mps_supervisor(fd).map_err(smolvm::Error::Io)
        }
        #[cfg(not(target_os = "linux"))]
        Commands::CudaMpsSupervisor { .. } => Err(smolvm::Error::Io(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "NVIDIA MPS supervision is Linux-only",
        ))),
        Commands::CleanupEphemeral {
            vm_name,
            pid,
            start_time,
        } => {
            cli::cleanup_ephemeral::run(&vm_name, pid, start_time);
            Ok(())
        }
    };

    // Handle errors
    if let Err(e) = result {
        tracing::debug!(error = %e, "command failed");
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

/// Initialize the tracing subscriber.
///
/// JSON mode is enabled via `SMOLVM_LOG_FORMAT=json` env var or when
/// running as `smolvm serve --json-logs`. Default is human-readable.
fn init_logging() {
    let json = std::env::var("SMOLVM_LOG_FORMAT")
        .map(|v| v == "json")
        .unwrap_or(false);

    // Skip EnvFilter::try_from_default_env() when RUST_LOG is not set —
    // avoids parsing an env var that doesn't exist.
    let filter = match std::env::var_os("RUST_LOG") {
        Some(_) => {
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("smolvm=warn"))
        }
        None => EnvFilter::new("smolvm=warn"),
    };

    if json {
        tracing_subscriber::fmt()
            .json()
            .with_writer(std::io::stderr)
            .with_env_filter(filter)
            .with_current_span(true)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_env_filter(filter)
            .with_target(false)
            .init();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shipped_binary_name_is_not_flagged() {
        // The regression this file exists to prevent: install.sh ships
        // `smolvm-bin` behind a `smolvm` launcher, so flagging it printed a
        // note on EVERY command of a correct install (shipped in 1.7.0).
        assert_eq!(stray_stub_note("smolvm-bin"), None);
    }

    #[test]
    fn the_launcher_name_is_not_flagged() {
        assert_eq!(stray_stub_note("smolvm"), None);
    }

    #[test]
    fn a_renamed_stub_is_still_flagged() {
        let note = stray_stub_note("myapp").expect("a foreign name should warn");
        assert!(
            note.contains("myapp.smolmachine"),
            "names the sidecar to add"
        );
        assert!(
            note.contains("plain smolvm CLI"),
            "says what it fell back to"
        );
    }
}
