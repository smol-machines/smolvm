//! Log rotation utilities for machine console logs.
//!
//! Provides automatic log rotation when log files exceed a size threshold.
//! Rotated logs follow the pattern: `filename.1`, `filename.2`, etc.

use crate::data::consts::BYTES_PER_MIB;
use std::fs;
use std::io;
use std::path::Path;

/// Maximum log file size before rotation (10 MB).
const MAX_LOG_SIZE: u64 = 10 * BYTES_PER_MIB;

/// Maximum number of rotated log files to keep.
const MAX_LOG_FILES: usize = 3;

/// Rotate a log file if it exceeds the size limit.
///
/// If the log file is larger than `MAX_LOG_SIZE`, it will be rotated:
/// - Current log -> `log.1`
/// - `log.1` -> `log.2`
/// - `log.2` -> `log.3`
/// - `log.3` -> deleted
///
/// Returns `Ok(true)` if rotation occurred, `Ok(false)` if no rotation needed.
pub fn rotate_if_needed(log_path: &Path) -> io::Result<bool> {
    let metadata = match fs::metadata(log_path) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };

    if metadata.len() < MAX_LOG_SIZE {
        return Ok(false);
    }

    rotate(log_path)?;
    Ok(true)
}

/// Force rotate a log file regardless of size.
///
/// Rotates the log file following the same pattern as `rotate_if_needed`.
///
/// The active (live) log is rotated with **copy-truncate** semantics rather
/// than a rename. The live console log is written by libkrun through an
/// intentionally-leaked append fd bound to the file's inode for the VM's whole
/// lifetime (see `KrunFunctions::console_output_to_file`). A `rename` would
/// leave that leaked fd pointing at the renamed inode (`.1`), so libkrun would
/// keep appending to `.1` — which then rotates onward and gets deleted, losing
/// all live output, while `tail agent-console.log` sees a frozen file.
///
/// Instead we copy the live file's contents to `.1` and then truncate the
/// original in place. Because the leaked fd is `O_APPEND`, its next write lands
/// at offset 0 of the now-empty inode, so the writer stays valid and continues
/// into the same file. Already-rotated `.1`/`.2`/`.3` files are nobody's live
/// fd, so they are still shifted with plain renames.
///
/// Tradeoff: like `logrotate`'s own `copytruncate`, any bytes written between
/// the copy and the truncate are lost. We minimise that window by truncating
/// immediately after the copy; under active writing a tiny loss is the accepted
/// copy-truncate semantics.
pub fn rotate(log_path: &Path) -> io::Result<()> {
    let log_str = log_path.display().to_string();

    // Delete the oldest rotated file if it exists
    let oldest = format!("{}.{}", log_str, MAX_LOG_FILES);
    if Path::new(&oldest).exists() {
        fs::remove_file(&oldest)?;
    }

    // Rotate existing files: .2 -> .3, .1 -> .2 (plain renames — nothing holds
    // an open fd to these already-rotated files).
    for i in (1..MAX_LOG_FILES).rev() {
        let from = format!("{}.{}", log_str, i);
        let to = format!("{}.{}", log_str, i + 1);
        if Path::new(&from).exists() {
            fs::rename(&from, &to)?;
        }
    }

    // Copy-truncate the live log to .1, preserving the leaked writer fd's inode.
    let first_rotated = format!("{}.1", log_str);
    fs::copy(log_path, &first_rotated)?;
    truncate_in_place(log_path)?;

    Ok(())
}

/// Truncate a file to zero length in place, keeping its inode (and therefore any
/// already-open fds) valid. Uses `OpenOptions::write(true).truncate(true)` which
/// maps to `open(..., O_TRUNC)` — it does not create a new inode.
fn truncate_in_place(log_path: &Path) -> io::Result<()> {
    fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(log_path)?;
    Ok(())
}

/// Get the total size of all log files (current + rotated).
pub fn total_log_size(log_path: &Path) -> io::Result<u64> {
    let mut total = 0u64;
    let log_str = log_path.display().to_string();

    // Current log
    if let Ok(metadata) = fs::metadata(log_path) {
        total += metadata.len();
    }

    // Rotated logs
    for i in 1..=MAX_LOG_FILES {
        let rotated = format!("{}.{}", log_str, i);
        if let Ok(metadata) = fs::metadata(&rotated) {
            total += metadata.len();
        }
    }

    Ok(total)
}

/// Clean up all log files (current + rotated).
pub fn cleanup_logs(log_path: &Path) -> io::Result<()> {
    let log_str = log_path.display().to_string();

    // Remove current log
    if log_path.exists() {
        fs::remove_file(log_path)?;
    }

    // Remove rotated logs
    for i in 1..=MAX_LOG_FILES {
        let rotated = format!("{}.{}", log_str, i);
        if Path::new(&rotated).exists() {
            fs::remove_file(&rotated)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn create_test_log(dir: &TempDir, content_size: usize) -> std::path::PathBuf {
        let log_path = dir.path().join("test.log");
        let mut file = fs::File::create(&log_path).unwrap();
        let content = vec![b'x'; content_size];
        file.write_all(&content).unwrap();
        log_path
    }

    #[test]
    fn test_no_rotation_needed() {
        let dir = TempDir::new().unwrap();
        let log_path = create_test_log(&dir, 1000); // 1KB, below threshold

        assert!(!rotate_if_needed(&log_path).unwrap());
        assert!(log_path.exists());
    }

    #[test]
    fn test_rotation_when_size_exceeded() {
        let dir = TempDir::new().unwrap();
        // Create a log that's over the threshold
        // Use smaller size for test to avoid memory issues
        let log_path = dir.path().join("test.log");
        {
            let mut file = fs::File::create(&log_path).unwrap();
            // Write enough to trigger rotation (we'll temporarily reduce threshold)
            file.write_all(&vec![b'x'; 1000]).unwrap();
        }

        // Force rotate to test the rotation logic
        rotate(&log_path).unwrap();

        // Copy-truncate keeps the live file (now empty) and copies data to .1.
        assert!(log_path.exists());
        assert_eq!(fs::metadata(&log_path).unwrap().len(), 0);
        let rotated = dir.path().join("test.log.1");
        assert!(rotated.exists());
    }

    #[test]
    fn test_rotation_chain() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("test.log");

        // Create .1 and .2 files
        fs::write(dir.path().join("test.log.1"), b"old1").unwrap();
        fs::write(dir.path().join("test.log.2"), b"old2").unwrap();
        fs::write(&log_path, b"current").unwrap();

        rotate(&log_path).unwrap();

        // Check rotation happened correctly. Copy-truncate leaves the live file
        // present but empty; its data is copied into .1.
        assert!(log_path.exists());
        assert_eq!(fs::metadata(&log_path).unwrap().len(), 0);
        assert_eq!(
            fs::read_to_string(dir.path().join("test.log.1")).unwrap(),
            "current"
        );
        assert_eq!(
            fs::read_to_string(dir.path().join("test.log.2")).unwrap(),
            "old1"
        );
        assert_eq!(
            fs::read_to_string(dir.path().join("test.log.3")).unwrap(),
            "old2"
        );
    }

    #[test]
    fn test_oldest_file_deleted() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("test.log");

        // Create all rotated files
        fs::write(&log_path, b"current").unwrap();
        fs::write(dir.path().join("test.log.1"), b"old1").unwrap();
        fs::write(dir.path().join("test.log.2"), b"old2").unwrap();
        fs::write(dir.path().join("test.log.3"), b"old3").unwrap();

        rotate(&log_path).unwrap();

        // .3 should have been deleted, then recreated from .2
        assert_eq!(
            fs::read_to_string(dir.path().join("test.log.3")).unwrap(),
            "old2"
        );
    }

    #[test]
    fn test_total_log_size() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("test.log");

        fs::write(&log_path, b"12345").unwrap(); // 5 bytes
        fs::write(dir.path().join("test.log.1"), b"123").unwrap(); // 3 bytes
        fs::write(dir.path().join("test.log.2"), b"12").unwrap(); // 2 bytes

        assert_eq!(total_log_size(&log_path).unwrap(), 10);
    }

    #[test]
    fn test_cleanup_logs() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("test.log");

        fs::write(&log_path, b"current").unwrap();
        fs::write(dir.path().join("test.log.1"), b"old1").unwrap();
        fs::write(dir.path().join("test.log.2"), b"old2").unwrap();

        cleanup_logs(&log_path).unwrap();

        assert!(!log_path.exists());
        assert!(!dir.path().join("test.log.1").exists());
        assert!(!dir.path().join("test.log.2").exists());
    }

    // Regression test for C2: rotation must not rename the live file out from
    // under a writer that holds a leaked append fd (as libkrun does for the VM
    // console). Copy-truncate must keep that fd valid and pointing at the same
    // inode, so pre-rotation data lands in .1 and post-rotation writes via the
    // held fd land in the (now truncated) live file — no data lost.
    #[test]
    fn test_copytruncate_preserves_open_append_fd() {
        use std::fs::OpenOptions;

        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("agent-console.log");

        // Open an append fd and keep it open across the rotation, mirroring the
        // leaked libkrun console fd.
        let mut writer = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .unwrap();

        writer.write_all(b"before-rotation\n").unwrap();
        writer.flush().unwrap();

        rotate(&log_path).unwrap();

        // The pre-rotation data was copied into .1.
        assert_eq!(
            fs::read_to_string(dir.path().join("agent-console.log.1")).unwrap(),
            "before-rotation\n"
        );
        // The live file still exists (same inode) and was truncated to empty.
        assert!(log_path.exists());
        assert_eq!(fs::metadata(&log_path).unwrap().len(), 0);

        // The still-open append fd keeps writing to the same inode; O_APPEND
        // means the next write lands at offset 0 of the truncated file.
        writer.write_all(b"after-rotation\n").unwrap();
        writer.flush().unwrap();

        // Post-rotation data is in the live file, not leaked into .1.
        assert_eq!(fs::read_to_string(&log_path).unwrap(), "after-rotation\n");
        assert_eq!(
            fs::read_to_string(dir.path().join("agent-console.log.1")).unwrap(),
            "before-rotation\n"
        );
    }

    #[test]
    fn test_rotate_nonexistent_file() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("nonexistent.log");

        // Should not error, just return false
        assert!(!rotate_if_needed(&log_path).unwrap());
    }
}
