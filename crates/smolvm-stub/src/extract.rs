//! Asset extraction for packed binaries.
//!
//! Extracts compressed assets to a cache directory for subsequent runs.
//! Supports both embedded assets (v1) and sidecar file mode (v2).

use smolvm_pack::format::{PackFooter, SIDECAR_EXTENSION};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// Marker file indicating extraction is complete.
const EXTRACTION_MARKER: &str = ".smolvm-extracted";

/// Check if footer indicates sidecar mode.
fn is_sidecar_mode(footer: &PackFooter) -> bool {
    footer.assets_offset == 0
}

/// Get sidecar file path for the given executable.
fn sidecar_path_for(exe_path: &Path) -> PathBuf {
    let filename = exe_path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    exe_path.with_file_name(format!("{}{}", filename, SIDECAR_EXTENSION))
}

/// Get the cache directory for a given checksum.
pub fn get_cache_dir(checksum: u32) -> std::io::Result<PathBuf> {
    let base = dirs::cache_dir()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no cache directory"))?;

    Ok(base.join("smolvm-pack").join(format!("{:08x}", checksum)))
}

/// Check if assets have already been extracted.
pub fn is_extracted(cache_dir: &Path) -> bool {
    cache_dir.join(EXTRACTION_MARKER).exists()
}

/// Extract assets from the packed binary to the cache directory.
pub fn extract_to_cache(
    exe_path: &Path,
    cache_dir: &Path,
    footer: &PackFooter,
    debug: bool,
) -> std::io::Result<()> {
    // Create cache directory
    fs::create_dir_all(cache_dir)?;

    if is_sidecar_mode(footer) {
        // Sidecar mode: read from .smoldata file
        // Sidecar format: compressed_assets (assets_size) + manifest + footer
        let sidecar = sidecar_path_for(exe_path);

        if debug {
            eprintln!(
                "debug: reading {} bytes of compressed assets from sidecar {}",
                footer.assets_size,
                sidecar.display()
            );
        }

        if !sidecar.exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("sidecar file not found: {}", sidecar.display()),
            ));
        }

        let sidecar_file = File::open(&sidecar)?;

        // Limit reader to just the assets portion (exclude manifest + footer)
        let limited_reader = sidecar_file.take(footer.assets_size);

        // Decompress with zstd
        let decoder = zstd::stream::Decoder::new(limited_reader)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        // Extract tar archive
        let mut archive = tar::Archive::new(decoder);
        archive.unpack(cache_dir)?;
    } else {
        // Embedded mode: read compressed assets from the executable
        let mut exe_file = File::open(exe_path)?;
        exe_file.seek(SeekFrom::Start(footer.assets_offset))?;

        if debug {
            eprintln!(
                "debug: reading {} bytes of compressed assets from offset {}",
                footer.assets_size, footer.assets_offset
            );
        }

        // Create a reader that limits to assets_size bytes
        let limited_reader = (&mut exe_file).take(footer.assets_size);

        // Decompress with zstd
        let decoder = zstd::stream::Decoder::new(limited_reader)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        // Extract tar archive
        let mut archive = tar::Archive::new(decoder);
        archive.unpack(cache_dir)?;
    }

    if debug {
        eprintln!("debug: extracted assets to {}", cache_dir.display());
    }

    // Extract agent-rootfs.tar to agent-rootfs directory
    let rootfs_tar = cache_dir.join("agent-rootfs.tar");
    let rootfs_dir = cache_dir.join("agent-rootfs");
    if rootfs_tar.exists() && !rootfs_dir.exists() {
        if debug {
            eprintln!("debug: extracting agent-rootfs.tar...");
        }
        fs::create_dir_all(&rootfs_dir)?;
        let tar_file = File::open(&rootfs_tar)?;
        let mut archive = tar::Archive::new(tar_file);
        archive.unpack(&rootfs_dir)?;
    }

    // Extract OCI layer tars to layers/{digest}/ directories
    // Layer tar files are named like "f6b4fb944634.tar" (short digest)
    // We need to extract them so the agent can use them
    let layers_dir = cache_dir.join("layers");
    if layers_dir.exists() {
        if debug {
            eprintln!("debug: extracting OCI layers...");
        }
        for entry in fs::read_dir(&layers_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().map_or(false, |ext| ext == "tar") {
                let stem = path.file_stem().unwrap_or_default().to_string_lossy();
                let layer_dir = layers_dir.join(&*stem);
                if !layer_dir.exists() {
                    if debug {
                        eprintln!("debug: extracting layer {}...", stem);
                    }
                    fs::create_dir_all(&layer_dir)?;
                    let tar_file = File::open(&path)?;
                    let mut archive = tar::Archive::new(tar_file);
                    archive.unpack(&layer_dir)?;
                }
            }
        }
    }

    // Write marker file
    fs::write(cache_dir.join(EXTRACTION_MARKER), "")?;

    // Make libraries executable (they need to be loadable)
    let lib_dir = cache_dir.join("lib");
    if lib_dir.exists() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for entry in fs::read_dir(&lib_dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_file() {
                    let mut perms = fs::metadata(&path)?.permissions();
                    perms.set_mode(0o755);
                    fs::set_permissions(&path, perms)?;
                }
            }
        }
    }

    Ok(())
}

/// Clean up old cached extractions (keep only the most recent N).
#[allow(dead_code)] // Reserved for future cache management CLI
pub fn cleanup_old_caches(keep: usize) -> std::io::Result<()> {
    let base = match dirs::cache_dir() {
        Some(d) => d.join("smolvm-pack"),
        None => return Ok(()),
    };

    if !base.exists() {
        return Ok(());
    }

    // Collect all cache directories with their modification times
    let mut entries: Vec<(PathBuf, std::time::SystemTime)> = vec![];

    for entry in fs::read_dir(&base)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            if let Ok(metadata) = fs::metadata(&path) {
                if let Ok(modified) = metadata.modified() {
                    entries.push((path, modified));
                }
            }
        }
    }

    // Sort by modification time (newest first)
    entries.sort_by(|a, b| b.1.cmp(&a.1));

    // Remove all but the most recent `keep` entries
    for (path, _) in entries.into_iter().skip(keep) {
        let _ = fs::remove_dir_all(path);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_dir_format() {
        // Verify checksum is hex-formatted in path
        let dir = get_cache_dir(0xDEADBEEF).unwrap();
        assert!(dir.to_string_lossy().contains("deadbeef"));
    }

    #[test]
    fn test_cache_dir_collision_risk() {
        // CRC32 is only 32 bits - collision is possible with ~77k binaries (birthday problem)
        // Different content could get same checksum and share cache
        // This documents the limitation - not a bug per se, but worth knowing
        let dir1 = get_cache_dir(0x12345678).unwrap();
        let dir2 = get_cache_dir(0x12345678).unwrap();
        assert_eq!(dir1, dir2); // Same checksum = same cache dir (collision!)
    }

    #[test]
    fn test_is_extracted() {
        let temp_dir = tempfile::tempdir().unwrap();

        // Not extracted without marker
        assert!(!is_extracted(temp_dir.path()));

        // Extracted with marker
        fs::write(temp_dir.path().join(EXTRACTION_MARKER), "").unwrap();
        assert!(is_extracted(temp_dir.path()));
    }

    #[test]
    fn test_is_extracted_race_condition() {
        // If extraction is interrupted, marker won't exist but partial files will
        // This tests that we don't consider partial extraction as complete
        let temp_dir = tempfile::tempdir().unwrap();

        // Simulate partial extraction - files exist but no marker
        fs::create_dir_all(temp_dir.path().join("lib")).unwrap();
        fs::write(temp_dir.path().join("lib/libkrun.dylib"), "partial").unwrap();

        // Should NOT be considered extracted
        assert!(!is_extracted(temp_dir.path()));
    }

    #[test]
    fn test_is_extracted_marker_is_directory() {
        // Edge case: what if marker path is a directory instead of file?
        let temp_dir = tempfile::tempdir().unwrap();

        // Create marker as directory (malicious or bug)
        fs::create_dir(temp_dir.path().join(EXTRACTION_MARKER)).unwrap();

        // .exists() returns true for directories too!
        assert!(is_extracted(temp_dir.path())); // This might not be intended behavior
    }

    #[test]
    fn test_sidecar_mode_detection() {
        // assets_offset == 0 means sidecar mode (assets in separate file)
        let sidecar_footer = PackFooter {
            stub_size: 0,
            assets_offset: 0,
            assets_size: 1000,
            manifest_offset: 1000,
            manifest_size: 500,
            checksum: 0x12345678,
        };
        assert!(is_sidecar_mode(&sidecar_footer));

        // assets_offset > 0 means embedded mode (assets in binary)
        let embedded_footer = PackFooter {
            stub_size: 50000,
            assets_offset: 50000,
            assets_size: 1000,
            manifest_offset: 51000,
            manifest_size: 500,
            checksum: 0x12345678,
        };
        assert!(!is_sidecar_mode(&embedded_footer));
    }

    #[test]
    fn test_sidecar_path_special_characters() {
        // Paths with special characters
        let exe = Path::new("/path/with spaces/my-app");
        let sidecar = sidecar_path_for(exe);
        assert_eq!(
            sidecar,
            PathBuf::from("/path/with spaces/my-app.smoldata")
        );

        // Unicode in path
        let exe = Path::new("/путь/程序");
        let sidecar = sidecar_path_for(exe);
        assert!(sidecar.to_string_lossy().ends_with(".smoldata"));
    }
}
