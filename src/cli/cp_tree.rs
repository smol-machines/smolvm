//! Planning for `machine cp` of a host directory into a machine.
//!
//! The agent protocol moves one file at a time and knows nothing about
//! trees, so a directory upload is assembled on the client: walk the host
//! tree, create every guest directory in one `mkdir -p`, then write each
//! file with the single-file call. Everything here is pure (no I/O beyond
//! the walk itself) so the plan can be tested without a guest.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// One regular file to upload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedFile {
    /// Host path to read (a symlink's target when the entry was a link).
    pub host: PathBuf,
    /// Path relative to the copied directory, `/`-separated.
    pub relative: String,
    /// Size in bytes, used for the progress total.
    pub size: u64,
    /// Permission bits (`0o777` mask) of the host file.
    pub mode: u32,
}

/// What a directory upload has to do, in order.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CopyPlan {
    /// Directories relative to the copied directory, parents before
    /// children, `/`-separated. The root itself is `""` and comes first.
    pub dirs: Vec<String>,
    /// Files to write, in walk order.
    pub files: Vec<PlannedFile>,
    /// Entries skipped with a reason: dangling links, sockets, fifos,
    /// devices, and a link cycle.
    pub skipped: Vec<(String, String)>,
}

impl CopyPlan {
    /// Sum of the planned files' sizes.
    pub fn total_bytes(&self) -> u64 {
        self.files.iter().map(|f| f.size).sum()
    }
}

/// Walk `root` as `cp -rL` would: symlinks are followed (a link to a file is
/// copied as its content, a link to a directory as that directory), nested
/// directories are descended into, and anything that is neither a regular
/// file nor a directory is skipped with a reason. A link that loops back to
/// a directory already on the current path is skipped instead of recursed.
pub fn plan_directory(root: &Path) -> std::io::Result<CopyPlan> {
    let mut plan = CopyPlan {
        dirs: vec![String::new()],
        ..CopyPlan::default()
    };
    let mut on_path = HashSet::new();
    walk(root, "", &mut plan, &mut on_path)?;
    Ok(plan)
}

fn walk(
    dir: &Path,
    relative: &str,
    plan: &mut CopyPlan,
    on_path: &mut HashSet<PathBuf>,
) -> std::io::Result<()> {
    let canonical = dir.canonicalize()?;
    if !on_path.insert(canonical.clone()) {
        plan.skipped.push((
            relative.to_string(),
            "symlink loops back to a directory being copied".to_string(),
        ));
        return Ok(());
    }
    let mut entries: Vec<_> = std::fs::read_dir(dir)?.collect::<Result<_, _>>()?;
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let name = entry.file_name().to_string_lossy().into_owned();
        let rel = join_relative(relative, &name);
        let host = entry.path();
        // `metadata` follows symlinks, which is what `cp -rL` does; a
        // dangling link is reported rather than aborting the whole copy.
        let meta = match std::fs::metadata(&host) {
            Ok(meta) => meta,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                plan.skipped.push((rel, "dangling symlink".to_string()));
                continue;
            }
            Err(e) => return Err(e),
        };
        if meta.is_dir() {
            plan.dirs.push(rel.clone());
            walk(&host, &rel, plan, on_path)?;
        } else if meta.is_file() {
            plan.files.push(PlannedFile {
                host,
                relative: rel,
                size: meta.len(),
                mode: permission_bits(&meta),
            });
        } else {
            plan.skipped
                .push((rel, "not a regular file or directory".to_string()));
        }
    }
    on_path.remove(&canonical);
    Ok(())
}

fn join_relative(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_string()
    } else {
        format!("{parent}/{name}")
    }
}

#[cfg(unix)]
fn permission_bits(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o777
}

#[cfg(not(unix))]
fn permission_bits(meta: &std::fs::Metadata) -> u32 {
    if meta.permissions().readonly() {
        0o444
    } else {
        0o644
    }
}

/// Where the copied directory lands, as `cp -r SRC DST` decides it: when
/// `DST` is an existing directory the source is copied *into* it under its
/// own basename (`cp -r src /data` makes `/data/src`); otherwise `DST`
/// itself becomes the copy (`cp -r src /data/new` makes `/data/new`).
pub fn resolve_destination(dst: &str, src_basename: &str, dst_is_dir: bool) -> String {
    let trimmed = dst.trim_end_matches('/');
    let trimmed = if trimmed.is_empty() { "/" } else { trimmed };
    if dst_is_dir {
        guest_join(trimmed, src_basename)
    } else {
        trimmed.to_string()
    }
}

/// Join a guest path and a relative, `/`-separated path.
pub fn guest_join(base: &str, relative: &str) -> String {
    if relative.is_empty() {
        base.to_string()
    } else if base.ends_with('/') {
        format!("{base}{relative}")
    } else {
        format!("{base}/{relative}")
    }
}

/// Single-quote a string for a POSIX shell: everything inside single quotes
/// is literal except `'` itself, which is written as `'\''`.
pub fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// The one shell command that creates every directory of the plan under
/// `dest_root`, parents first, and optionally chowns them.
pub fn mkdir_command(dest_root: &str, dirs: &[String], owner: Option<(u32, u32)>) -> String {
    let quoted: Vec<String> = dirs
        .iter()
        .map(|d| shell_quote(&guest_join(dest_root, d)))
        .collect();
    let list = quoted.join(" ");
    match owner {
        Some((uid, gid)) => format!("mkdir -p {list} && chown {uid}:{gid} {list}"),
        None => format!("mkdir -p {list}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("src/nested")).unwrap();
        std::fs::create_dir_all(root.join("empty")).unwrap();
        std::fs::write(root.join("README"), b"hello").unwrap();
        std::fs::write(root.join("src/main.rs"), b"fn main() {}").unwrap();
        std::fs::write(root.join("src/nested/deep.txt"), b"x").unwrap();
        dir
    }

    #[test]
    fn plan_lists_every_directory_before_its_children_and_every_file() {
        let dir = tree();
        let plan = plan_directory(dir.path()).unwrap();
        assert_eq!(plan.dirs, vec!["", "empty", "src", "src/nested"]);
        let files: Vec<(&str, u64)> = plan
            .files
            .iter()
            .map(|f| (f.relative.as_str(), f.size))
            .collect();
        assert_eq!(
            files,
            vec![
                ("README", 5),
                ("src/main.rs", 12),
                ("src/nested/deep.txt", 1)
            ]
        );
        assert_eq!(plan.total_bytes(), 18);
        assert!(plan.skipped.is_empty());
        assert_eq!(plan.files[0].host, dir.path().join("README"));
    }

    #[cfg(unix)]
    #[test]
    fn plan_keeps_permission_bits_and_follows_symlinks() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = tree();
        let root = dir.path();
        std::fs::set_permissions(root.join("README"), std::fs::Permissions::from_mode(0o755))
            .unwrap();
        symlink(root.join("README"), root.join("link-to-file")).unwrap();
        symlink(root.join("src"), root.join("link-to-dir")).unwrap();
        symlink("/nonexistent/target", root.join("dangling")).unwrap();

        let plan = plan_directory(root).unwrap();
        let readme = plan.files.iter().find(|f| f.relative == "README").unwrap();
        assert_eq!(readme.mode, 0o755);
        let via_link = plan
            .files
            .iter()
            .find(|f| f.relative == "link-to-file")
            .unwrap();
        assert_eq!(via_link.size, 5);
        assert_eq!(via_link.mode, 0o755);
        assert!(plan.dirs.contains(&"link-to-dir".to_string()));
        assert!(plan.dirs.contains(&"link-to-dir/nested".to_string()));
        assert!(plan
            .files
            .iter()
            .any(|f| f.relative == "link-to-dir/nested/deep.txt"));
        assert_eq!(
            plan.skipped,
            vec![("dangling".to_string(), "dangling symlink".to_string())]
        );
    }

    #[cfg(unix)]
    #[test]
    fn plan_skips_a_symlink_cycle_instead_of_recursing_forever() {
        use std::os::unix::fs::symlink;
        let dir = tree();
        let root = dir.path();
        symlink(root, root.join("src/nested/loop")).unwrap();
        let plan = plan_directory(root).unwrap();
        assert_eq!(plan.skipped.len(), 1);
        assert_eq!(plan.skipped[0].0, "src/nested/loop");
        assert!(plan.skipped[0].1.contains("loops"));
        // Files are still listed exactly once.
        assert_eq!(plan.files.len(), 3);
    }

    #[test]
    fn destination_follows_cp_r() {
        // Existing directory: copy goes inside it under the source basename.
        assert_eq!(resolve_destination("/data", "src", true), "/data/src");
        assert_eq!(resolve_destination("/data/", "src", true), "/data/src");
        assert_eq!(resolve_destination("/", "src", true), "/src");
        // Anything else: the destination is the copy.
        assert_eq!(resolve_destination("/data/new", "src", false), "/data/new");
        assert_eq!(resolve_destination("/data/new/", "src", false), "/data/new");
    }

    #[test]
    fn mkdir_command_quotes_every_path_and_keeps_parent_order() {
        let dirs = vec![String::new(), "a b".to_string(), "a b/it's".to_string()];
        assert_eq!(
            mkdir_command("/dst", &dirs, None),
            "mkdir -p '/dst' '/dst/a b' '/dst/a b/it'\\''s'"
        );
        assert_eq!(
            mkdir_command("/dst", &dirs[..1], Some((1000, 1000))),
            "mkdir -p '/dst' && chown 1000:1000 '/dst'"
        );
    }

    #[test]
    fn shell_quote_is_literal_for_metacharacters() {
        assert_eq!(shell_quote("$HOME; rm -rf *"), "'$HOME; rm -rf *'");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
    }
}
