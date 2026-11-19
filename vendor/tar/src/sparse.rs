use std::fs::File;
use std::io;

/// Preserve an already-zero range as a hole without changing the file cursor or length.
///
/// On macOS, explicitly release whole 64 KiB units inside `start..end` so APFS
/// does not allocate the intervening holes when flushing nearby writes. Partial
/// units are retained, preserving data adjacent to unaligned sparse extents.
/// Other platforms retain their normal seek-based sparse-file behavior.
///
/// The caller must ensure the range contains no data it wants to retain. Errors
/// are propagated instead of silently expanding a sparse file into a dense one.
pub fn punch_sparse_hole(file: &File, start: u64, end: u64) -> io::Result<()> {
    if start > end || end > i64::MAX as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid sparse hole range",
        ));
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::io::AsRawFd;
        const UNIT: u64 = 64 * 1024;
        let first = (start + UNIT - 1) / UNIT * UNIT;
        let last = end / UNIT * UNIT;
        if first >= last {
            return Ok(());
        }
        let hole = libc::fpunchhole_t {
            fp_flags: 0,
            reserved: 0,
            fp_offset: first as libc::off_t,
            fp_length: (last - first) as libc::off_t,
        };
        // SAFETY: file owns a live descriptor and hole is an initialized input
        // structure whose aligned, signed offsets were bounded above.
        let result = unsafe {
            libc::fcntl(
                file.as_raw_fd(),
                libc::F_PUNCHHOLE,
                &hole as *const libc::fpunchhole_t,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = file;
        Ok(())
    }
}
