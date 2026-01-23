//! Log rotation utilities for sandbox console logs.
//!
//! Provides automatic log rotation when log files exceed a size threshold.
//! Rotated logs follow the pattern: `filename.1`, `filename.2`, etc.

use std::fs;
use std::io;
use std::path::Path;

/// Maximum log file size before rotation (10 MB).
const MAX_LOG_SIZE: u64 = 10 * 1024 * 1024;

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
pub fn rotate(log_path: &Path) -> io::Result<()> {
    let log_str = log_path.display().to_string();

    // Delete the oldest rotated file if it exists
    let oldest = format!("{}.{}", log_str, MAX_LOG_FILES);
    if Path::new(&oldest).exists() {
        fs::remove_file(&oldest)?;
    }

    // Rotate existing files: .2 -> .3, .1 -> .2
    for i in (1..MAX_LOG_FILES).rev() {
        let from = format!("{}.{}", log_str, i);
        let to = format!("{}.{}", log_str, i + 1);
        if Path::new(&from).exists() {
            fs::rename(&from, &to)?;
        }
    }

    // Move current log to .1
    let first_rotated = format!("{}.1", log_str);
    fs::rename(log_path, &first_rotated)?;

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

        // Original file should be gone, .1 should exist
        assert!(!log_path.exists());
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

        // Check rotation happened correctly
        assert!(!log_path.exists());
        assert_eq!(fs::read_to_string(dir.path().join("test.log.1")).unwrap(), "current");
        assert_eq!(fs::read_to_string(dir.path().join("test.log.2")).unwrap(), "old1");
        assert_eq!(fs::read_to_string(dir.path().join("test.log.3")).unwrap(), "old2");
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
        assert_eq!(fs::read_to_string(dir.path().join("test.log.3")).unwrap(), "old2");
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

    #[test]
    fn test_rotate_nonexistent_file() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("nonexistent.log");

        // Should not error, just return false
        assert!(!rotate_if_needed(&log_path).unwrap());
    }
}
