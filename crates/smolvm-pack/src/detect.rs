//! Packed binary auto-detection.
//!
//! Determines whether the current executable is a packed binary and what mode
//! it is running in: section-embedded (macOS), append-embedded, sidecar, or
//! normal CLI.
//!
//! Called at the very start of `main()` before clap parsing so that a packed
//! binary (e.g. `./my-app echo hello`) shows packed-binary help rather
//! than the full smolvm CLI.

use crate::format::{PackFooter, FOOTER_SIZE};
use crate::packer::{read_footer_from_sidecar, sidecar_path_for};
use std::path::{Path, PathBuf};

/// The detected packed binary mode.
pub enum PackedMode {
    /// Assets embedded in a Mach-O `__SMOLVM,__smolvm` section (macOS single-file).
    #[cfg(target_os = "macos")]
    Section {
        /// Parsed manifest from the section.
        manifest: Box<crate::format::PackManifest>,
        /// CRC32 checksum from the section header.
        checksum: u32,
        /// Pointer to compressed assets in the section (valid for process lifetime).
        assets_ptr: *const u8,
        /// Size of compressed assets.
        assets_size: usize,
    },
    /// Assets appended to the binary (Linux single-file, or macOS fallback).
    Embedded {
        /// Path to the current executable.
        exe_path: PathBuf,
        /// Footer read from end of binary.
        footer: PackFooter,
    },
    /// Assets in a `.smolmachine` sidecar file alongside the binary.
    Sidecar {
        /// Path to the `.smolmachine` file.
        sidecar_path: PathBuf,
        /// Footer read from end of sidecar.
        footer: PackFooter,
    },
}

/// Detect whether this process is running as a packed binary.
///
/// Checks in order:
/// 1. macOS Mach-O section (`__SMOLVM,__smolvm`) with `SMOLSECT` magic
/// 2. `<exe>.smolmachine` sidecar file with valid footer
/// 3. `SMOLPACK` footer appended to own binary with `assets_offset > 0`
///
/// Returns `None` for normal `smolvm` invocations (no false positives).
pub fn detect_packed_mode() -> Option<PackedMode> {
    let exe_path = std::env::current_exe().ok()?;

    // 1. macOS section mode
    #[cfg(target_os = "macos")]
    {
        if let Some(mode) = try_section_mode() {
            return Some(mode);
        }
    }

    // 2. Sidecar mode: <exe>.smolmachine next to binary
    if let Some(mode) = try_sidecar_mode(&exe_path) {
        return Some(mode);
    }

    // 3. Embedded-append mode: SMOLPACK footer at end of own binary
    if let Some(mode) = try_embedded_mode(&exe_path) {
        return Some(mode);
    }

    None
}

fn try_sidecar_mode(exe_path: &Path) -> Option<PackedMode> {
    let sidecar = sidecar_path_for(exe_path);
    if !sidecar.exists() {
        return None;
    }
    let footer = read_footer_from_sidecar(&sidecar).ok()?;
    Some(PackedMode::Sidecar {
        sidecar_path: sidecar,
        footer,
    })
}

fn try_embedded_mode(exe_path: &Path) -> Option<PackedMode> {
    let footer = read_footer_direct(exe_path).ok()?;
    // assets_offset > 0 means assets are appended after the stub in the binary
    if footer.assets_offset > 0 {
        Some(PackedMode::Embedded {
            exe_path: exe_path.to_path_buf(),
            footer,
        })
    } else {
        None
    }
}

/// Read footer directly from end of file without trying sidecar first.
///
/// Unlike `packer::read_footer()` which checks for a sidecar, this reads
/// the last 64 bytes of the given file and parses them as a `PackFooter`.
fn read_footer_direct(path: &Path) -> crate::Result<PackFooter> {
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom};

    let mut file = File::open(path)?;
    let file_size = file.metadata()?.len();
    if file_size < FOOTER_SIZE as u64 {
        return Err(crate::PackError::InvalidMagic);
    }
    file.seek(SeekFrom::End(-(FOOTER_SIZE as i64)))?;
    let mut buf = [0u8; FOOTER_SIZE];
    file.read_exact(&mut buf)?;
    PackFooter::from_bytes(&buf)
}

// ---------------------------------------------------------------------------
// macOS Mach-O section reading
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
fn try_section_mode() -> Option<PackedMode> {
    let embedded = read_embedded_section()?;
    Some(PackedMode::Section {
        manifest: Box::new(embedded.manifest),
        checksum: embedded.header.checksum,
        assets_ptr: embedded.assets_ptr,
        assets_size: embedded.assets_size,
    })
}

/// Data read from the `__SMOLVM,__smolvm` Mach-O section.
#[cfg(target_os = "macos")]
struct EmbeddedData {
    header: crate::format::SectionHeader,
    manifest: crate::format::PackManifest,
    assets_ptr: *const u8,
    assets_size: usize,
}

/// Try to read embedded data from the `__SMOLVM,__smolvm` Mach-O section.
///
/// Returns `None` if:
/// - Not running on macOS
/// - Section doesn't exist
/// - Section contains only the build-time placeholder (not `SMOLSECT` magic)
#[cfg(target_os = "macos")]
fn read_embedded_section() -> Option<EmbeddedData> {
    use crate::format::{PackManifest, SectionHeader, SECTION_HEADER_SIZE, SECTION_MAGIC};

    extern "C" {
        fn getsectiondata(
            mhp: *const MachHeader64,
            segname: *const i8,
            sectname: *const i8,
            size: *mut usize,
        ) -> *const u8;
    }

    #[repr(C)]
    struct MachHeader64 {
        magic: u32,
        cputype: i32,
        cpusubtype: i32,
        filetype: u32,
        ncmds: u32,
        sizeofcmds: u32,
        flags: u32,
        reserved: u32,
    }

    extern "C" {
        fn _dyld_get_image_header(image_index: u32) -> *const MachHeader64;
    }

    unsafe {
        let header = _dyld_get_image_header(0);
        if header.is_null() {
            return None;
        }

        let segname = c"__SMOLVM";
        let sectname = c"__smolvm";
        let mut size: usize = 0;

        let data_ptr = getsectiondata(header, segname.as_ptr(), sectname.as_ptr(), &mut size);

        if data_ptr.is_null() || size < SECTION_HEADER_SIZE {
            return None;
        }

        // Check for SMOLSECT magic (placeholder contains different marker)
        let magic_bytes = std::slice::from_raw_parts(data_ptr, 8);
        if magic_bytes != SECTION_MAGIC {
            return None;
        }

        // Parse section header
        let header_bytes = std::slice::from_raw_parts(data_ptr, SECTION_HEADER_SIZE);
        let section_header = SectionHeader::from_bytes(header_bytes).ok()?;

        // Validate sizes
        let expected_size = SECTION_HEADER_SIZE
            + section_header.manifest_size as usize
            + section_header.assets_size as usize;
        if size < expected_size {
            return None;
        }

        // Parse manifest
        let manifest_start = data_ptr.add(SECTION_HEADER_SIZE);
        let manifest_bytes =
            std::slice::from_raw_parts(manifest_start, section_header.manifest_size as usize);
        let manifest = PackManifest::from_json(manifest_bytes).ok()?;

        // Assets follow the manifest
        let assets_ptr = manifest_start.add(section_header.manifest_size as usize);

        Some(EmbeddedData {
            header: section_header,
            manifest,
            assets_ptr,
            assets_size: section_header.assets_size as usize,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_returns_none_for_normal_binary() {
        // The test binary is a normal Rust executable, not a packed binary.
        assert!(detect_packed_mode().is_none());
    }

    #[test]
    fn test_read_footer_direct_rejects_short_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("short.bin");
        std::fs::write(&path, b"too short").unwrap();
        assert!(read_footer_direct(&path).is_err());
    }

    #[test]
    fn test_read_footer_direct_rejects_invalid_magic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("no_magic.bin");
        std::fs::write(&path, &[0u8; 128]).unwrap();
        assert!(read_footer_direct(&path).is_err());
    }
}
