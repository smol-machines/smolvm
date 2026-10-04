//! Provisioning of the operator's egress watchlist into each VM.
//!
//! `smolvm serve start --egress-watchlist <PATH>` names the source file. Every
//! VM gets a copy in its data directory before it boots (the network runtime
//! reads the copy, since after its privilege drop it can no longer reach the
//! source), and a refresher rewrites every copy when the source changes. A
//! source edit that does not parse is refused and the last good list kept.
//!
//! Without the flag nothing is copied, and a copy left by an earlier run is
//! removed at boot, so the feature is fully off.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime};

use smolvm_network::watchlist::{Watchlist, EGRESS_WATCHLIST_FILE};

/// How often the refresher checks the source for a change.
const REFRESH_INTERVAL: Duration = Duration::from_secs(30);

struct Source {
    path: PathBuf,
    state: Mutex<SourceState>,
}

struct SourceState {
    /// The last contents that parsed, copied verbatim into each VM.
    contents: Vec<u8>,
    modified: Option<SystemTime>,
    /// Data directories this process wrote a copy into.
    provisioned: HashSet<PathBuf>,
}

static SOURCE: OnceLock<Source> = OnceLock::new();

/// Read and validate the watchlist at `path`, returning its bytes.
fn read_valid(path: &Path) -> Result<Vec<u8>, String> {
    let contents = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let text =
        std::str::from_utf8(&contents).map_err(|_| format!("{} is not UTF-8", path.display()))?;
    Watchlist::parse(text).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(contents)
}

/// Enable the watchlist for this process from `path`. Refuses a file that does
/// not parse, so `serve` fails at startup rather than running unwatched.
pub fn enable(path: PathBuf) -> Result<(), String> {
    let contents = read_valid(&path)?;
    let modified = std::fs::metadata(&path).and_then(|m| m.modified()).ok();
    SOURCE
        .set(Source {
            path,
            state: Mutex::new(SourceState {
                contents,
                modified,
                provisioned: HashSet::new(),
            }),
        })
        .map_err(|_| "the egress watchlist is already enabled".to_string())?;
    std::thread::Builder::new()
        .name("egress-watchlist".into())
        .spawn(refresh_loop)
        .map_err(|e| format!("start the watchlist refresher: {e}"))?;
    Ok(())
}

/// Write `contents` to `<dir>/egress-watchlist` atomically and world-readable,
/// so a VMM running as its own uid can read it and never sees a partial file.
fn write_copy(dir: &Path, contents: &[u8]) -> std::io::Result<()> {
    let mut temp = tempfile::NamedTempFile::new_in(dir)?;
    std::io::Write::write_all(&mut temp, contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temp.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o644))?;
    }
    temp.persist(dir.join(EGRESS_WATCHLIST_FILE))
        .map_err(|e| e.error)?;
    Ok(())
}

/// Give the VM whose data directory is `dir` its copy of the watchlist, just
/// before it boots. With no watchlist enabled, remove any stale copy instead.
pub fn provision(dir: &Path) {
    let Some(source) = SOURCE.get() else {
        let _ = std::fs::remove_file(dir.join(EGRESS_WATCHLIST_FILE));
        return;
    };
    let Ok(mut state) = source.state.lock() else {
        return;
    };
    match write_copy(dir, &state.contents) {
        Ok(()) => {
            state.provisioned.insert(dir.to_path_buf());
        }
        Err(e) => {
            tracing::warn!(dir = %dir.display(), error = %e, "egress watchlist copy not written")
        }
    }
}

/// Every copy to rewrite: the directories this process provisioned, plus any
/// VM data directory already holding a copy from an earlier run.
fn copies(state: &SourceState) -> HashSet<PathBuf> {
    let mut dirs = state.provisioned.clone();
    if let Ok(entries) = std::fs::read_dir(super::vm_cache_root()) {
        for entry in entries.flatten() {
            let dir = entry.path();
            if dir.join(EGRESS_WATCHLIST_FILE).is_file() {
                dirs.insert(dir);
            }
        }
    }
    dirs
}

fn refresh_loop() {
    let Some(source) = SOURCE.get() else {
        return;
    };
    loop {
        std::thread::sleep(REFRESH_INTERVAL);
        refresh_once(source);
    }
}

fn refresh_once(source: &Source) {
    let modified = std::fs::metadata(&source.path)
        .and_then(|m| m.modified())
        .ok();
    let Ok(mut state) = source.state.lock() else {
        return;
    };
    if modified == state.modified {
        return;
    }
    state.modified = modified;
    match read_valid(&source.path) {
        Ok(contents) => {
            state.contents = contents;
            let dirs = copies(&state);
            for dir in &dirs {
                if let Err(e) = write_copy(dir, &state.contents) {
                    tracing::warn!(dir = %dir.display(), error = %e, "egress watchlist copy not refreshed");
                }
            }
            tracing::info!(copies = dirs.len(), "egress watchlist refreshed");
        }
        Err(e) => tracing::warn!(
            error = %e,
            "egress watchlist changed but does not parse; keeping the previous list"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str =
        "w1 dns-sha256:0000000000000000000000000000000000000000000000000000000000000000\n";

    #[test]
    fn a_copy_is_written_whole_and_world_readable() {
        let dir = tempfile::tempdir().unwrap();
        write_copy(dir.path(), VALID.as_bytes()).unwrap();
        let copy = dir.path().join(EGRESS_WATCHLIST_FILE);
        assert_eq!(std::fs::read_to_string(&copy).unwrap(), VALID);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&copy).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o644);
        }
    }

    #[test]
    fn a_source_that_does_not_parse_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let bad = dir.path().join("list");
        std::fs::write(&bad, "not a watchlist line\n").unwrap();
        assert!(read_valid(&bad).unwrap_err().contains("line 1"));
        let good = dir.path().join("good");
        std::fs::write(&good, VALID).unwrap();
        assert_eq!(read_valid(&good).unwrap(), VALID.as_bytes());
    }

    #[test]
    fn a_changed_source_rewrites_every_copy_and_a_bad_edit_keeps_the_last() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("list");
        std::fs::write(&path, VALID).unwrap();
        let vm = root.path().join("vm");
        std::fs::create_dir(&vm).unwrap();
        let source = Source {
            path: path.clone(),
            state: Mutex::new(SourceState {
                contents: VALID.as_bytes().to_vec(),
                modified: None,
                provisioned: HashSet::from([vm.clone()]),
            }),
        };
        let updated = VALID.replace("w1", "w2");
        std::fs::write(&path, &updated).unwrap();
        refresh_once(&source);
        assert_eq!(
            std::fs::read_to_string(vm.join(EGRESS_WATCHLIST_FILE)).unwrap(),
            updated
        );

        std::fs::write(&path, "broken\n").unwrap();
        source.state.lock().unwrap().modified = None;
        refresh_once(&source);
        assert_eq!(
            std::fs::read_to_string(vm.join(EGRESS_WATCHLIST_FILE)).unwrap(),
            updated,
            "a bad edit leaves the last good copy"
        );
    }

    #[test]
    fn without_a_watchlist_a_stale_copy_is_removed() {
        let dir = tempfile::tempdir().unwrap();
        let copy = dir.path().join(EGRESS_WATCHLIST_FILE);
        std::fs::write(&copy, VALID).unwrap();
        if SOURCE.get().is_none() {
            provision(dir.path());
            assert!(!copy.exists());
        }
    }
}
