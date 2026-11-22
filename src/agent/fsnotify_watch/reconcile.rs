//! Disk-backed metadata for replaying host changes after notification loss.
//! Only acknowledged changes advance the snapshot; memory does not grow with a burst.
use rusqlite::{params, Connection, OptionalExtension};
use std::{
    ffi::OsString,
    io,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Sql(rusqlite::Error),
    Cancelled,
    Incomplete(io::Error),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => e.fmt(f),
            Self::Sql(e) => e.fmt(f),
            Self::Incomplete(e) => write!(f, "incomplete notification scan: {e}"),
            Self::Cancelled => f.write_str("notification reconciliation cancelled"),
        }
    }
}
impl std::error::Error for Error {}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Self::Sql(e)
    }
}
#[derive(Debug, PartialEq, Eq)]
pub enum Change {
    Present {
        path: PathBuf,
        created: bool,
        directory: bool,
    },
    Removed {
        path: PathBuf,
        directory: bool,
    },
}

pub trait Sink {
    fn emit(&mut self, change: Change) -> bool;
    fn finish(&mut self) -> bool {
        true
    }
}
struct Callback<F>(F);
impl<F: FnMut(Change) -> bool> Sink for Callback<F> {
    fn emit(&mut self, c: Change) -> bool {
        (self.0)(c)
    }
}

pub struct Snapshot {
    db: Connection,
    generation: i64,
}
impl Snapshot {
    pub fn new() -> Result<Self, Error> {
        // SQLite creates a private temporary database and deletes it on close;
        // the page cache is bounded and larger trees spill to its temporary file.
        let db = Connection::open("")?;
        db.execute_batch("PRAGMA temp_store=FILE; PRAGMA cache_size=-2048; PRAGMA mmap_size=0;
            CREATE TABLE entries(path BLOB PRIMARY KEY, stamp BLOB NOT NULL, directory INTEGER NOT NULL, seen INTEGER NOT NULL) WITHOUT ROWID;")?;
        Ok(Self { db, generation: 0 })
    }

    pub fn reconcile(
        &mut self,
        roots: &[PathBuf],
        stop: &AtomicBool,
        emit: impl FnMut(Change) -> bool,
    ) -> Result<(), Error> {
        self.reconcile_sink(roots, stop, Callback(emit))
    }

    pub fn reconcile_sink(
        &mut self,
        roots: &[PathBuf],
        stop: &AtomicBool,
        mut emit: impl Sink,
    ) -> Result<(), Error> {
        let generation = self
            .generation
            .checked_add(1)
            .ok_or_else(|| io::Error::other("notification snapshot generation exhausted"))?;
        let tx = self.db.transaction()?;
        let mut incomplete = None;
        {
            let mut previous =
                tx.prepare_cached("SELECT stamp,directory FROM entries WHERE path=?1")?;
            let mut update=tx.prepare_cached("INSERT INTO entries(path,stamp,directory,seen) VALUES(?1,?2,?3,?4) ON CONFLICT(path) DO UPDATE SET stamp=excluded.stamp,directory=excluded.directory,seen=excluded.seen")?;
            for root in roots {
                let mut pending = Some(root.clone());
                let mut directories: Vec<(PathBuf, std::fs::ReadDir)> = Vec::new();
                loop {
                    if stop.load(Ordering::SeqCst) {
                        return Err(Error::Cancelled);
                    }
                    let path = if let Some(path) = pending.take() {
                        path
                    } else {
                        let Some(dir) = directories.last_mut() else {
                            break;
                        };
                        match dir.1.next() {
                            Some(Ok(entry)) => entry.path(),
                            Some(Err(error)) => {
                                preserve_scope(&tx, &dir.0, generation)?;
                                incomplete.get_or_insert(error);
                                directories.pop();
                                continue;
                            }
                            None => {
                                directories.pop();
                                continue;
                            }
                        }
                    };
                    let metadata = match std::fs::symlink_metadata(&path) {
                        Ok(m) => m,
                        Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                        Err(e) => {
                            preserve_scope(&tx, &path, generation)?;
                            incomplete.get_or_insert(e);
                            continue;
                        }
                    };
                    let key = encode_path(&path);
                    let stamp = stamp(&metadata);
                    let directory = metadata.is_dir();
                    let old: Option<(Vec<u8>, bool)> = previous
                        .query_row([&key], |r| Ok((r.get(0)?, r.get(1)?)))
                        .optional()?;
                    let changed = old.as_ref().is_none_or(|(old_stamp, old_dir)| {
                        old_stamp != &stamp || *old_dir != directory
                    });
                    if changed
                        && !emit.emit(Change::Present {
                            path: path.clone(),
                            created: old.is_none(),
                            directory,
                        })
                    {
                        return Err(Error::Cancelled);
                    }
                    update.execute(params![key, stamp, directory, generation])?;
                    if directory {
                        // No ignored names or depth/mtime cap: a recovery pass
                        // must include files old enough to have left a window.
                        match std::fs::read_dir(&path) {
                            Ok(dir) => directories.push((path.clone(), dir)),
                            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                            Err(e) => {
                                preserve_scope(&tx, &path, generation)?;
                                incomplete.get_or_insert(e);
                            }
                        }
                    }
                }
            }
            // Previous names are necessary to report deletion; scanning only
            // the present tree cannot reconstruct them. Stream rather than
            // collecting the result set in memory. Descendants precede parents.
            for root in roots {
                let key = encode_path(root);
                let mut prefix = key.clone();
                let separator = encode_path(Path::new(std::path::MAIN_SEPARATOR_STR));
                if !prefix.ends_with(&separator) {
                    prefix.extend_from_slice(&separator);
                }
                let mut upper = prefix.clone();
                // The final encoded separator byte is below 255 on Unix and
                // Windows, so this is the exclusive upper prefix boundary.
                *upper.last_mut().unwrap() += 1;
                let mut deleted=tx.prepare("SELECT path,directory FROM entries WHERE seen<>?1 AND (path=?2 OR (path>=?3 AND path<?4)) ORDER BY length(path) DESC,path")?;
                let mut rows = deleted.query(params![generation, key, prefix, upper])?;
                while let Some(row) = rows.next()? {
                    if stop.load(Ordering::SeqCst) {
                        return Err(Error::Cancelled);
                    }
                    let key: Vec<u8> = row.get(0)?;
                    if !emit.emit(Change::Removed {
                        path: decode_path(key),
                        directory: row.get(1)?,
                    }) {
                        return Err(Error::Cancelled);
                    }
                }
                drop(rows);
                drop(deleted);
                tx.execute(
                    "DELETE FROM entries WHERE seen<>?1 AND (path=?2 OR (path>=?3 AND path<?4))",
                    params![generation, key, prefix, upper],
                )?;
            }
        }
        // Commit only after delivery acknowledges the entire pass; a lost
        // connection or shutdown rolls back, making the next pass replayable.
        if !emit.finish() {
            return Err(Error::Cancelled);
        }
        tx.commit()?;
        self.generation = generation;
        match incomplete {
            Some(error) => Err(Error::Incomplete(error)),
            None => Ok(()),
        }
    }
}

/// Retain previously known names under an unreadable subtree: an access error
/// is not evidence that its files were removed. Other readable paths can commit.
fn preserve_scope(
    tx: &rusqlite::Transaction<'_>,
    path: &Path,
    generation: i64,
) -> Result<(), rusqlite::Error> {
    let key = encode_path(path);
    let mut prefix = key.clone();
    let separator = encode_path(Path::new(std::path::MAIN_SEPARATOR_STR));
    if !prefix.ends_with(&separator) {
        prefix.extend_from_slice(&separator);
    }
    let mut upper = prefix.clone();
    *upper.last_mut().unwrap() += 1;
    tx.execute(
        "UPDATE entries SET seen=?1 WHERE path=?2 OR (path>=?3 AND path<?4)",
        params![generation, key, prefix, upper],
    )?;
    Ok(())
}

fn stamp(m: &std::fs::Metadata) -> Vec<u8> {
    let mut s = Vec::with_capacity(72);
    s.push(u8::from(m.is_dir()));
    s.push(u8::from(m.file_type().is_symlink()));
    s.extend_from_slice(&m.len().to_le_bytes());
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        for v in [
            m.dev(),
            m.ino(),
            m.mode() as u64,
            m.uid() as u64,
            m.gid() as u64,
            m.mtime() as u64,
            m.mtime_nsec() as u64,
            m.ctime() as u64,
            m.ctime_nsec() as u64,
        ] {
            s.extend_from_slice(&v.to_le_bytes());
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        for v in [
            m.file_attributes() as u64,
            m.creation_time(),
            m.last_write_time(),
        ] {
            s.extend_from_slice(&v.to_le_bytes());
        }
    }
    s
}
fn encode_path(p: &Path) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        p.as_os_str().as_bytes().to_vec()
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        p.as_os_str()
            .encode_wide()
            .flat_map(u16::to_le_bytes)
            .collect()
    }
}
fn decode_path(p: Vec<u8>) -> PathBuf {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        OsString::from_vec(p).into()
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStringExt;
        OsString::from_wide(
            &p.as_chunks::<2>()
                .0
                .iter()
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .collect::<Vec<_>>(),
        )
        .into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Child half of `reconcile_runs_under_the_vmm_seccomp_filter`: confines this
    /// fresh process with the VMM's enforcing filter, then reconciles the tree
    /// named in `SMOLVM_TEST_RECONCILE_UNDER_SECCOMP`. A syscall the filter does
    /// not allow kills it with SIGSYS. Does nothing in a normal test run.
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn reconcile_under_seccomp_child() {
        let Some(root) = std::env::var_os("SMOLVM_TEST_RECONCILE_UNDER_SECCOMP") else {
            return;
        };
        let program =
            crate::process::build_seccomp_program(true, false).expect("build seccomp program");
        seccompiler::apply_filter(&program).expect("apply seccomp filter");
        let mut snapshot = Snapshot::new().expect("open snapshot");
        // A real workspace outgrows the snapshot's page cache and SQLite spills
        // it to a temporary file, which is where its VFS reaches stat(3). One
        // page makes this small tree spill the same way.
        snapshot
            .db
            .execute_batch("PRAGMA cache_size=1;")
            .expect("shrink cache");
        let stop = AtomicBool::new(false);
        let mut changes = 0_usize;
        snapshot
            .reconcile(&[PathBuf::from(root)], &stop, |_| {
                changes += 1;
                true
            })
            .expect("reconcile");
        assert!(changes > 0, "reconcile saw the tree");
    }

    /// The mount watcher reconciles inside the VMM after its seccomp filter is
    /// on, so everything a reconcile reaches, SQLite's VFS included, must be on
    /// the allowlist. Runs in a fresh process: work after a fork of the
    /// multithreaded test harness can deadlock on locks another thread held.
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn reconcile_runs_under_the_vmm_seccomp_filter() {
        let dir = tempfile::tempdir().unwrap();
        for d in 0..4 {
            let sub = dir.path().join(format!("d{d}"));
            std::fs::create_dir(&sub).unwrap();
            for f in 0..100 {
                std::fs::write(sub.join(f.to_string()), b"x").unwrap();
            }
        }
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "agent::fsnotify_watch::reconcile::tests::reconcile_under_seccomp_child",
                "--test-threads=1",
            ])
            .env("SMOLVM_TEST_RECONCILE_UNDER_SECCOMP", dir.path())
            .status()
            .unwrap();
        assert!(
            status.success(),
            "reconcile under the VMM filter: {status:?}"
        );
    }
    #[test]
    fn recovery_detects_deleted_trees_replacement_and_old_deep_files() {
        let root = tempfile::tempdir().unwrap();
        let base = root.path();
        let deep = base.join("node_modules/a/b/c/d/e/f");
        std::fs::create_dir_all(&deep).unwrap();
        for i in 0..512 {
            std::fs::write(deep.join(format!("{i}")), b"old").unwrap();
        }
        let deleted = base.join("deleted");
        std::fs::create_dir(&deleted).unwrap();
        std::fs::write(deleted.join("old"), b"gone").unwrap();
        let replaced = base.join("replaced");
        std::fs::write(&replaced, b"old").unwrap();
        let stop = AtomicBool::new(false);
        let mut snapshot = Snapshot::new().unwrap();
        snapshot.reconcile(&[base.into()], &stop, |_| true).unwrap();
        std::fs::remove_dir_all(&deleted).unwrap();
        for i in 0..512 {
            std::fs::write(deep.join(format!("{i}")), b"new").unwrap();
        }
        let staging = base.join("staging");
        std::fs::write(&staging, b"new").unwrap();
        std::fs::rename(staging, &replaced).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2100));
        let mut changes = Vec::new();
        snapshot
            .reconcile(&[base.into()], &stop, |c| {
                changes.push(c);
                true
            })
            .unwrap();
        assert!(changes.contains(&Change::Removed {
            path: deleted.join("old"),
            directory: false
        }));
        assert!(changes.contains(&Change::Removed {
            path: deleted,
            directory: true
        }));
        assert!(changes.contains(&Change::Present {
            path: replaced,
            created: false,
            directory: false
        }));
        for i in 0..512 {
            assert!(changes.contains(&Change::Present {
                path: deep.join(format!("{i}")),
                created: false,
                directory: false
            }));
        }
        snapshot
            .reconcile(&[base.into()], &stop, |c| {
                panic!("unchanged snapshot replayed: {c:?}")
            })
            .unwrap();
    }
    #[test]
    fn interrupted_delivery_replays_changes_and_deletions() {
        let root = tempfile::tempdir().unwrap();
        let base = root.path();
        let stop = AtomicBool::new(false);
        let mut snapshot = Snapshot::new().unwrap();
        std::fs::write(base.join("old"), b"gone").unwrap();
        snapshot.reconcile(&[base.into()], &stop, |_| true).unwrap();
        std::fs::remove_file(base.join("old")).unwrap();
        for i in 0..600 {
            std::fs::write(base.join(format!("new-{i}")), b"new").unwrap();
        }
        let mut delivered = 0;
        assert!(matches!(
            snapshot.reconcile(&[base.into()], &stop, |_| {
                delivered += 1;
                delivered < 256
            }),
            Err(Error::Cancelled)
        ));
        let mut changes = Vec::new();
        snapshot
            .reconcile(&[base.into()], &stop, |c| {
                changes.push(c);
                true
            })
            .unwrap();
        assert_eq!(
            changes
                .iter()
                .filter(|c| matches!(
                    c,
                    Change::Present {
                        created: true,
                        directory: false,
                        ..
                    }
                ))
                .count(),
            600
        );
        assert!(changes.contains(&Change::Removed {
            path: base.join("old"),
            directory: false
        }));
    }
    #[test]
    fn a_single_changed_path_does_not_rescan_or_remove_its_siblings() {
        let root = tempfile::tempdir().unwrap();
        let base = root.path();
        let stop = AtomicBool::new(false);
        let mut snapshot = Snapshot::new().unwrap();
        let first = base.join("a");
        let sibling = base.join("a-sibling");
        std::fs::create_dir(&first).unwrap();
        std::fs::write(first.join("old"), b"old").unwrap();
        std::fs::write(&sibling, b"original").unwrap();
        snapshot.reconcile(&[base.into()], &stop, |_| true).unwrap();
        std::fs::remove_dir_all(&first).unwrap();
        std::fs::write(&sibling, b"changed but not in this event").unwrap();
        let mut changes = Vec::new();
        snapshot
            .reconcile(std::slice::from_ref(&first), &stop, |c| {
                changes.push(c);
                true
            })
            .unwrap();
        assert_eq!(changes.len(), 2);
        assert!(changes.contains(&Change::Removed {
            path: first,
            directory: true
        }));
        changes.clear();
        snapshot
            .reconcile(std::slice::from_ref(&sibling), &stop, |c| {
                changes.push(c);
                true
            })
            .unwrap();
        assert_eq!(
            changes,
            vec![Change::Present {
                path: sibling,
                created: false,
                directory: false
            }]
        );
    }
    #[test]
    fn a_failed_final_partial_batch_does_not_commit_the_snapshot() {
        struct FailedFlush;
        impl Sink for FailedFlush {
            fn emit(&mut self, _: Change) -> bool {
                true
            }
            fn finish(&mut self) -> bool {
                false
            }
        }
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("partial");
        std::fs::write(&path, b"pending").unwrap();
        let stop = AtomicBool::new(false);
        let mut snapshot = Snapshot::new().unwrap();
        assert!(matches!(
            snapshot.reconcile_sink(&[root.path().into()], &stop, FailedFlush),
            Err(Error::Cancelled)
        ));
        let mut seen = false;
        snapshot
            .reconcile(&[root.path().into()], &stop, |c| {
                seen |= matches!(c,Change::Present {path:p,..} if p==path);
                true
            })
            .unwrap();
        assert!(seen);
    }
    #[cfg(unix)]
    #[test]
    fn raw_path_encoding_never_replaces_bytes() {
        use std::os::unix::ffi::OsStringExt;
        let path = PathBuf::from(OsString::from_vec(vec![b'/', 0xff, b'x']));
        assert_eq!(decode_path(encode_path(&path)), path);
    }
    #[cfg(unix)]
    #[test]
    fn names_round_trip_and_symlinks_do_not_escape_the_mount() {
        #[cfg(not(target_os = "macos"))]
        use std::os::unix::ffi::OsStringExt;
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("outside"), b"never scan").unwrap();
        symlink(outside.path(), root.path().join("link")).unwrap();
        #[cfg(target_os = "macos")]
        let file = root.path().join("雪"); // APFS rejects invalid UTF-8 names.
        #[cfg(not(target_os = "macos"))]
        let file = root.path().join(OsString::from_vec(vec![0xff, b'x']));
        std::fs::write(&file, b"old").unwrap();
        let mut snapshot = Snapshot::new().unwrap();
        let stop = AtomicBool::new(false);
        let mut initial = Vec::new();
        snapshot
            .reconcile(&[root.path().into()], &stop, |c| {
                initial.push(c);
                true
            })
            .unwrap();
        assert_eq!(initial.len(), 3);
        std::fs::remove_file(&file).unwrap();
        let mut changes = Vec::new();
        snapshot
            .reconcile(&[root.path().into()], &stop, |c| {
                changes.push(c);
                true
            })
            .unwrap();
        assert!(changes.contains(&Change::Removed {
            path: file,
            directory: false
        }));
    }

    #[test]
    fn exhausted_snapshot_storage_does_not_acknowledge_partial_recovery() {
        let root = tempfile::tempdir().unwrap();
        let stop = AtomicBool::new(false);
        let mut snapshot = Snapshot::new().unwrap();
        snapshot
            .reconcile(&[root.path().into()], &stop, |_| true)
            .unwrap();
        let pages: i64 = snapshot
            .db
            .query_row("PRAGMA page_count", [], |r| r.get(0))
            .unwrap();
        snapshot
            .db
            .pragma_update(None, "max_page_count", pages)
            .unwrap();
        for index in 0..512 {
            std::fs::write(root.path().join(format!("new-{index}")), b"pending").unwrap();
        }
        let error = snapshot
            .reconcile(&[root.path().into()], &stop, |_| true)
            .unwrap_err();
        assert!(
            matches!(error,Error::Sql(rusqlite::Error::SqliteFailure(e,_)) if e.extended_code==rusqlite::ffi::SQLITE_FULL)
        );
        snapshot
            .db
            .pragma_update(None, "max_page_count", 1_000_000)
            .unwrap();
        let mut created = 0;
        snapshot
            .reconcile(&[root.path().into()], &stop, |c| {
                if matches!(
                    c,
                    Change::Present {
                        created: true,
                        directory: false,
                        ..
                    }
                ) {
                    created += 1;
                }
                true
            })
            .unwrap();
        assert_eq!(created, 512);
    }
    #[cfg(unix)]
    #[test]
    fn unreadable_directories_preserve_names_and_do_not_block_readable_changes() {
        use std::os::unix::fs::PermissionsExt;
        struct Restore(PathBuf);
        impl Drop for Restore {
            fn drop(&mut self) {
                let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700));
            }
        }
        let root = tempfile::tempdir().unwrap();
        let denied = root.path().join("denied");
        std::fs::create_dir(&denied).unwrap();
        let _restore = Restore(denied.clone());
        let removed = denied.join("removed");
        std::fs::write(&removed, b"old").unwrap();
        let readable = root.path().join("readable");
        std::fs::write(&readable, b"old").unwrap();
        let stop = AtomicBool::new(false);
        let mut snapshot = Snapshot::new().unwrap();
        snapshot
            .reconcile(&[root.path().into()], &stop, |_| true)
            .unwrap();
        std::fs::remove_file(&removed).unwrap();
        std::fs::set_permissions(&denied, std::fs::Permissions::from_mode(0o0)).unwrap();
        // Root-capable test runners bypass mode bits; native unprivileged runs
        // exercise the failure, while those runners cannot manufacture it.
        if std::fs::read_dir(&denied).is_ok() {
            eprintln!("permission probe skipped: runner bypasses directory mode bits");
            return;
        }
        std::fs::write(&readable, b"changed").unwrap();
        let mut changes = Vec::new();
        let result = snapshot.reconcile(&[root.path().into()], &stop, |c| {
            changes.push(c);
            true
        });
        assert!(matches!(result, Err(Error::Incomplete(_))));
        assert!(changes.contains(&Change::Present {
            path: readable,
            created: false,
            directory: false
        }));
        assert!(!changes
            .iter()
            .any(|c| matches!(c,Change::Removed{path,..} if path==&removed)));
        std::fs::set_permissions(&denied, std::fs::Permissions::from_mode(0o700)).unwrap();
        changes.clear();
        snapshot
            .reconcile(&[root.path().into()], &stop, |c| {
                changes.push(c);
                true
            })
            .unwrap();
        assert!(changes.contains(&Change::Removed {
            path: removed,
            directory: false
        }));
    }
}
