//! Disk image helpers: sparse creation, template/copy-on-write cloning, and
//! resizing of the raw VM disk images.

use crate::data::consts::BYTES_PER_GIB;
use crate::data::disk::DiskType;
use crate::error::{Error, Result};
use crate::platform::Os;
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

/// Common search paths for e2fsprogs tools (mkfs.ext4, e2fsck, resize2fs).
const E2FSPROGS_PATH_PREFIXES: &[&str] = &[
    "/opt/homebrew/opt/e2fsprogs/sbin", // macOS ARM (Homebrew)
    "/usr/local/opt/e2fsprogs/sbin",    // macOS Intel (Homebrew)
    "/opt/homebrew/sbin",               // macOS ARM (Homebrew alt)
    "/usr/local/sbin",                  // macOS Intel (Homebrew alt)
    "/sbin",                            // Linux
    "/usr/sbin",                        // Linux alt
];

/// Find an e2fsprogs tool by name (e.g., "mkfs.ext4", "e2fsck", "resize2fs").
///
/// Searches common installation paths, then falls back to PATH lookup.
pub(crate) fn find_e2fsprogs_tool(name: &str) -> Option<String> {
    for prefix in E2FSPROGS_PATH_PREFIXES {
        let path = format!("{}/{}", prefix, name);
        if Path::new(&path).exists() {
            return Some(path);
        }
    }

    if std::process::Command::new(name)
        // Every e2fsprogs tool we care about supports `--version`; this is
        // the cheapest non-destructive probe that confirms the binary is
        // present on PATH and executable before we try to use it for real.
        .arg("--version")
        .output()
        .is_ok()
    {
        return Some(name.to_string());
    }

    None
}

/// Create a sparse disk image file.
pub(crate) fn create_sparse_disk<D: DiskType>(path: &Path, size_bytes: u64) -> Result<()> {
    use std::fs::OpenOptions;

    tracing::info!(
        path = %path.display(),
        disk_type = D::NAME,
        size_gb = size_bytes / BYTES_PER_GIB,
        "creating sparse {} disk",
        D::NAME,
    );

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| Error::storage("create sparse disk", e.to_string()))?;
    write_last_byte(
        &mut file,
        size_bytes,
        "seek to create disk",
        "write disk tail",
    )
}

/// Copy a disk from a pre-formatted template, resizing to target size.
///
/// On macOS, uses `clonefile()` for instant APFS copy-on-write cloning.
/// On Linux, falls back to `fs::copy` (which uses `copy_file_range` for
/// sparse-aware copying on supported filesystems).
pub(crate) fn copy_disk_from_template<D: DiskType>(
    disk_path: &Path,
    size_bytes: u64,
    template_path: &Path,
) -> Result<()> {
    use std::fs::OpenOptions;

    tracing::info!(
        template = %template_path.display(),
        target = %disk_path.display(),
        disk_type = D::NAME,
        "copying {} from template",
        D::NAME,
    );

    if let Some(parent) = disk_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| Error::storage("create directory", e.to_string()))?;
    }

    clone_or_copy_file(template_path, disk_path)?;

    // Extend the sparse file to the target size. The ext4 filesystem inside
    // is still at the template's original size — the guest agent expands it
    // at boot via resize2fs in a parallel thread (~10ms, non-blocking).
    // We do NOT run resize2fs on the host: it takes ~880ms to expand the
    // filesystem metadata synchronously, blocking the entire boot path.
    let current_size = std::fs::metadata(disk_path)
        .map_err(|e| Error::storage("read copied disk metadata", e.to_string()))?
        .len();
    if current_size < size_bytes {
        let mut file = OpenOptions::new()
            .write(true)
            .open(disk_path)
            .map_err(|e| Error::storage("open for resize", e.to_string()))?;
        write_last_byte(&mut file, size_bytes, "seek for resize", "extend disk")?;
    }

    tracing::info!(
        path = %disk_path.display(),
        disk_type = D::NAME,
        "{} copied from template",
        D::NAME
    );
    Ok(())
}

/// Expand a sparse disk image file to a new size.
pub(crate) fn expand_sparse_disk<D: DiskType>(path: &Path, new_size_gb: u64) -> Result<()> {
    use std::fs::OpenOptions;

    let new_size_bytes = new_size_gb * BYTES_PER_GIB;
    let current_size = std::fs::metadata(path)
        .map_err(|e| Error::storage("get disk metadata", e.to_string()))?
        .len();

    if new_size_bytes == current_size {
        // Already at target size — idempotent. This handles retries after a
        // partial failure where the disk was expanded but the DB wasn't updated.
        return Ok(());
    }
    if new_size_bytes < current_size {
        return Err(Error::storage(
            "expand disk",
            format!(
                "new size ({} GiB) must be larger than current size ({} GiB). Shrinking is not supported.",
                new_size_gb,
                current_size / BYTES_PER_GIB
            ),
        ));
    }

    tracing::info!(
        path = %path.display(),
        disk_type = D::NAME,
        current_gb = current_size / BYTES_PER_GIB,
        new_gb = new_size_gb,
        "expanding {} disk",
        D::NAME
    );

    let mut file = OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|e| Error::storage("open disk for expansion", e.to_string()))?;
    write_last_byte(
        &mut file,
        new_size_bytes,
        "seek to expand",
        "write to expand",
    )?;
    file.sync_all()
        .map_err(|e| Error::storage("sync after expand", e.to_string()))?;

    tracing::info!(
        path = %path.display(),
        disk_type = D::NAME,
        new_gb = new_size_gb,
        "{} disk expanded successfully",
        D::NAME
    );
    Ok(())
}

/// Format a disk with mkfs.ext4 (requires e2fsprogs).
pub(crate) fn format_disk_with_mkfs<D: DiskType>(disk_path: &Path) -> Result<()> {
    tracing::info!(
        path = %disk_path.display(),
        disk_type = D::NAME,
        "formatting {} disk with mkfs.ext4",
        D::NAME
    );

    let mkfs_path = find_e2fsprogs_tool("mkfs.ext4").ok_or_else(|| {
        let hint = if Os::current().is_macos() {
            "On macOS, install with: brew install e2fsprogs"
        } else {
            "On Linux, install with: apt install e2fsprogs (or equivalent)"
        };
        Error::storage(
            "find mkfs.ext4",
            format!(
                "mkfs.ext4 not found - required for {} disk formatting.\n  {}",
                D::NAME,
                hint
            ),
        )
    })?;

    let path_str = disk_path
        .to_str()
        .ok_or_else(|| Error::storage("validate path", "disk path contains invalid characters"))?;

    let output = std::process::Command::new(mkfs_path)
        .args([
            // Force creation on a regular file rather than requiring a block
            // device. Our "disk" here is a raw sparse image file on the host.
            "-F",
            // Quiet mode keeps stderr/stdout small on success. We only need the
            // detailed mkfs output when the command fails.
            "-q",
            // Set the reserved-blocks percentage flag.
            "-m",
            // Reserve 0% of blocks for root. This is a VM-owned data disk, not
            // a host root filesystem, so holding capacity back for root is just
            // wasted space.
            "0",
            // Specify ext4 feature flags explicitly.
            "-O",
            // Disable the journal. These disks are scratch/data images managed
            // by a VM, and dropping the journal reduces write amplification and
            // space overhead for our use case.
            "^has_journal",
            // Set the filesystem label.
            "-L",
            // The label lets the guest-side tooling distinguish storage and
            // overlay disks in logs and inspection output.
            D::VOLUME_LABEL,
            // The target sparse image file to format.
            path_str,
        ])
        .output()
        .map_err(|e| Error::storage("run mkfs.ext4", e.to_string()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::storage("format with mkfs.ext4", stderr.to_string()));
    }

    tracing::info!(
        path = %disk_path.display(),
        disk_type = D::NAME,
        "{} disk formatted successfully",
        D::NAME
    );
    Ok(())
}

pub(crate) fn write_last_byte(
    file: &mut std::fs::File,
    size_bytes: u64,
    seek_context: &str,
    write_context: &str,
) -> Result<()> {
    assert!(size_bytes > 0, "disk size must be greater than 0");

    file.seek(SeekFrom::Start(size_bytes - 1))
        .map_err(|e| Error::storage(seek_context, e.to_string()))?;
    file.write_all(&[0])
        .map_err(|e| Error::storage(write_context, e.to_string()))?;
    Ok(())
}

/// Clone a file using the platform-optimal copy method.
///
/// - macOS: `clonefile()` for instant APFS copy-on-write
/// - Linux: sparse copy via `SEEK_HOLE`/`SEEK_DATA` (copies only data regions)
/// - Fallback: `fs::copy`
///
/// Disk templates are sparse files (~500KB actual data in a 512MB logical file).
/// `std::fs::copy()` copies all bytes including zero regions. The sparse copy
/// path skips holes, reducing copy time from ~400ms to ~5ms.
pub fn clone_or_copy_file(src: &Path, dst: &Path) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        use std::ffi::CString;

        if dst.exists() {
            let _ = std::fs::remove_file(dst);
        }

        let src_c = CString::new(src.to_string_lossy().as_bytes())
            .map_err(|e| Error::storage("clonefile src path", e.to_string()))?;
        let dst_c = CString::new(dst.to_string_lossy().as_bytes())
            .map_err(|e| Error::storage("clonefile dst path", e.to_string()))?;

        let ret = unsafe { libc::clonefile(src_c.as_ptr(), dst_c.as_ptr(), 0) };
        if ret == 0 {
            tracing::debug!(src = %src.display(), dst = %dst.display(), "clonefile succeeded");
            return Ok(());
        }

        tracing::debug!(
            src = %src.display(),
            errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
            "clonefile failed, falling back to fs::copy"
        );
    }

    #[cfg(target_os = "linux")]
    {
        // TODO(reflink): try a FICLONE ioctl before sparse_copy for true
        // copy-on-write on btrfs/XFS hosts. (Fork clones already get
        // filesystem-independent block CoW via qcow2 overlays; this would only
        // speed up the remaining full-copy callers on reflink-capable hosts.)
        match sparse_copy(src, dst) {
            Ok(bytes) => {
                tracing::debug!(
                    src = %src.display(), dst = %dst.display(),
                    bytes_copied = bytes, "sparse copy succeeded"
                );
                return Ok(());
            }
            Err(e) => {
                tracing::debug!(src = %src.display(), error = %e, "sparse copy failed, falling back");
            }
        }
    }

    std::fs::copy(src, dst).map_err(|e| Error::storage("copy file", e.to_string()))?;
    Ok(())
}

/// Copy only data regions of a sparse file via SEEK_HOLE/SEEK_DATA.
#[cfg(target_os = "linux")]
fn sparse_copy(src: &Path, dst: &Path) -> std::io::Result<u64> {
    use std::os::unix::io::AsRawFd;

    let src_file = std::fs::File::open(src)?;
    let src_len = src_file.metadata()?.len();
    if src_len == 0 {
        std::fs::File::create(dst)?;
        return Ok(0);
    }

    let dst_file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(dst)?;
    dst_file.set_len(src_len)?;

    let src_fd = src_file.as_raw_fd();
    let dst_fd = dst_file.as_raw_fd();
    let mut total: u64 = 0;
    let mut offset: i64 = 0;
    let mut buf = vec![0u8; 256 * 1024];

    loop {
        let data_start = unsafe { libc::lseek(src_fd, offset, libc::SEEK_DATA) };
        if data_start < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENXIO) {
                break;
            }
            return Err(std::io::Error::last_os_error());
        }
        let hole_start = unsafe { libc::lseek(src_fd, data_start, libc::SEEK_HOLE) };
        let data_end = if hole_start < 0 {
            src_len as i64
        } else {
            hole_start
        };

        let mut pos = data_start;
        while pos < data_end {
            let to_read = std::cmp::min((data_end - pos) as usize, buf.len());
            let n =
                unsafe { libc::pread(src_fd, buf.as_mut_ptr() as *mut libc::c_void, to_read, pos) };
            if n <= 0 {
                break;
            }
            let written = unsafe {
                libc::pwrite(dst_fd, buf.as_ptr() as *const libc::c_void, n as usize, pos)
            };
            if written <= 0 {
                return Err(std::io::Error::last_os_error());
            }
            pos += n as i64;
            total += n as u64;
        }
        offset = data_end;
    }
    Ok(total)
}
