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

    // On Windows/NTFS a file is dense by default: seeking past the end and
    // writing a tail byte allocates every block in between (a 20 GiB disk would
    // need 20 GiB free, failing with ERROR_DISK_FULL). Mark the file sparse
    // first so only written extents consume host space — matching the implicit
    // sparse behavior of Unix filesystems.
    #[cfg(windows)]
    mark_file_sparse(file).map_err(|e| Error::storage("mark disk sparse", e.to_string()))?;

    file.seek(SeekFrom::Start(size_bytes - 1))
        .map_err(|e| Error::storage(seek_context, e.to_string()))?;
    file.write_all(&[0])
        .map_err(|e| Error::storage(write_context, e.to_string()))?;
    Ok(())
}

/// Mark an open file as sparse (Windows/NTFS) so writing a tail byte at a large
/// offset doesn't allocate every intermediate block. No-op semantics elsewhere
/// (Unix filesystems are sparse by default and never call this).
#[cfg(windows)]
fn mark_file_sparse(file: &std::fs::File) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::IO::DeviceIoControl;
    // FSCTL_SET_SPARSE control code (winioctl.h).
    const FSCTL_SET_SPARSE: u32 = 0x000900C4;
    let mut returned: u32 = 0;
    // SAFETY: `file` is a valid open handle; FSCTL_SET_SPARSE uses no in/out buffers.
    let ok = unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            FSCTL_SET_SPARSE,
            std::ptr::null(),
            0,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
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

    #[cfg(windows)]
    {
        // std::fs::copy materialises holes on NTFS, so a large-virtual sparse
        // template (e.g. a 10 GiB overlay with ~50 MB of real data) balloons to
        // its full logical size. Copy sparsely instead, mirroring the Linux path.
        match sparse_copy_windows(src, dst) {
            Ok(bytes) => {
                tracing::debug!(
                    src = %src.display(), dst = %dst.display(),
                    bytes_copied = bytes, "windows sparse copy succeeded"
                );
                return Ok(());
            }
            Err(e) => {
                tracing::debug!(src = %src.display(), error = %e, "windows sparse copy failed, falling back to fs::copy");
            }
        }
    }

    std::fs::copy(src, dst).map_err(|e| Error::storage("copy file", e.to_string()))?;
    Ok(())
}

/// Copy a sparse file on Windows/NTFS by replicating only its allocated regions,
/// leaving holes as holes — the Win32 analogue of the Linux `SEEK_HOLE`/`SEEK_DATA`
/// path. A scan-and-skip-zeros copy would have to read the whole logical size
/// (20+ GiB for a disk image) and, worse, allocate any non-zero region it finds;
/// `FSCTL_QUERY_ALLOCATED_RANGES` reports exactly the regions NTFS has backed, so
/// a 20 GiB image holding a few MB copies a few MB.
#[cfg(windows)]
fn sparse_copy_windows(src: &Path, dst: &Path) -> std::io::Result<u64> {
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::IO::DeviceIoControl;

    // FSCTL_QUERY_ALLOCATED_RANGES (winioctl.h) + its in/out record. LARGE_INTEGER
    // fields are signed 64-bit byte counts.
    const FSCTL_QUERY_ALLOCATED_RANGES: u32 = 0x0009_40CF;
    const ERROR_MORE_DATA: i32 = 234;
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct AllocatedRange {
        file_offset: i64,
        length: i64,
    }

    let mut src_file = std::fs::File::open(src)?;
    let src_len = src_file.metadata()?.len();
    if dst.exists() {
        std::fs::remove_file(dst)?;
    }
    let mut dst_file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(dst)?;
    if src_len == 0 {
        return Ok(0);
    }
    // Mark sparse BEFORE extending so the holes are never allocated.
    mark_file_sparse(&dst_file)?;
    dst_file.set_len(src_len)?;

    let mut total: u64 = 0;
    let mut buf = vec![0u8; 1024 * 1024];
    let mut out: Vec<AllocatedRange> = vec![AllocatedRange { file_offset: 0, length: 0 }; 1024];
    // Query allocated ranges starting at 0; the FSCTL fills as many as fit, and
    // signals ERROR_MORE_DATA when there are more (resume past the last range).
    let mut query = AllocatedRange { file_offset: 0, length: src_len as i64 };
    loop {
        let mut returned: u32 = 0;
        // SAFETY: src handle is live; `query` is a valid input record; `out` is a
        // valid, correctly-sized output array; `returned` is a writable out-param.
        let ok = unsafe {
            DeviceIoControl(
                src_file.as_raw_handle(),
                FSCTL_QUERY_ALLOCATED_RANGES,
                &query as *const _ as *const core::ffi::c_void,
                std::mem::size_of::<AllocatedRange>() as u32,
                out.as_mut_ptr() as *mut core::ffi::c_void,
                (out.len() * std::mem::size_of::<AllocatedRange>()) as u32,
                &mut returned,
                std::ptr::null_mut(),
            )
        };
        let more = ok == 0 && std::io::Error::last_os_error().raw_os_error() == Some(ERROR_MORE_DATA);
        if ok == 0 && !more {
            return Err(std::io::Error::last_os_error());
        }
        let count = returned as usize / std::mem::size_of::<AllocatedRange>();
        if count == 0 {
            break;
        }
        let mut resume = query.file_offset;
        for r in &out[..count] {
            let mut pos = r.file_offset as u64;
            let end = (r.file_offset + r.length) as u64;
            while pos < end {
                let want = std::cmp::min((end - pos) as usize, buf.len());
                src_file.seek(SeekFrom::Start(pos))?;
                src_file.read_exact(&mut buf[..want])?;
                dst_file.seek(SeekFrom::Start(pos))?;
                dst_file.write_all(&buf[..want])?;
                pos += want as u64;
                total += want as u64;
            }
            resume = r.file_offset + r.length;
        }
        if !more {
            break;
        }
        query.file_offset = resume;
        query.length = src_len as i64 - resume;
        if query.length <= 0 {
            break;
        }
    }
    tracing::debug!(total, "sparse_copy_windows: allocated-range copy done");
    Ok(total)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Seek, SeekFrom, Write};

    /// `clone_or_copy_file` must reproduce a sparse file byte-for-byte on every
    /// platform — including the Windows sparse-copy path, which skips zero runs.
    /// We build a file with a head data region, a large hole, and a tail data
    /// region, then assert the clone's length and full contents match.
    #[test]
    fn clone_or_copy_preserves_sparse_contents() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src.img");
        let dst = dir.path().join("dst.img");

        let logical_len: u64 = 8 * 1024 * 1024; // 8 MiB logical
        let head = b"HEAD-DATA-REGION";
        let tail = b"TAIL-DATA-REGION";
        {
            let mut f = std::fs::File::create(&src).unwrap();
            f.write_all(head).unwrap();
            f.set_len(logical_len).unwrap();
            f.seek(SeekFrom::Start(logical_len - tail.len() as u64))
                .unwrap();
            f.write_all(tail).unwrap();
        }

        clone_or_copy_file(&src, &dst).expect("clone_or_copy_file");

        let src_bytes = std::fs::read(&src).unwrap();
        let dst_bytes = std::fs::read(&dst).unwrap();
        assert_eq!(
            dst_bytes.len() as u64,
            logical_len,
            "clone must preserve logical length"
        );
        assert_eq!(src_bytes, dst_bytes, "clone must be byte-identical to source");
        assert_eq!(&dst_bytes[..head.len()], head);
        assert_eq!(&dst_bytes[dst_bytes.len() - tail.len()..], tail);

        // On Windows the whole point is that the clone stays sparse — the 8 MiB
        // hole must NOT be allocated on disk. GetCompressedFileSizeW reports the
        // real on-disk allocation; assert it's a tiny fraction of the logical size.
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            use windows_sys::Win32::Storage::FileSystem::GetCompressedFileSizeW;
            let wide: Vec<u16> = dst
                .as_os_str()
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            let mut high: u32 = 0;
            // SAFETY: `wide` is a valid NUL-terminated path; `high` is a writable out-param.
            let low = unsafe { GetCompressedFileSizeW(wide.as_ptr(), &mut high) };
            let allocated = ((high as u64) << 32) | (low as u64);
            assert!(
                allocated < logical_len / 2,
                "sparse clone must not allocate the full {logical_len} bytes (got {allocated} allocated)"
            );
        }
    }
}
