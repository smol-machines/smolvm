/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/
use std::{
    collections::HashMap,
    env,
    fs::File,
    io::BufRead,
    ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, Not},
    os::fd::AsRawFd,
    path::Path,
    sync::LazyLock,
};

#[cfg(not(feature = "async"))]
use log::error;
use nix::mount::{mount, MntFlags, MsFlags};
#[cfg(feature = "async")]
use nix::sched::{unshare, CloneFlags};
#[cfg(not(feature = "async"))]
use nix::unistd::{fork, ForkResult};

use crate::error::{Error, Result};
#[cfg(not(feature = "async"))]
use crate::monitor::{monitor_subscribe, wait_pid, Topic};

struct Flag {
    clear: bool,
    flags: MsFlags,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Default)]
pub struct LoopParams {
    readonly: bool,
    auto_clear: bool,
    direct: bool,
}

#[repr(C)]
#[derive(Debug)]
pub struct LoopInfo {
    device: u64,
    inode: u64,
    rdevice: u64,
    offset: u64,
    size_limit: u64,
    number: u32,
    encrypt_type: u32,
    encrypt_key_size: u32,
    flags: u32,
    file_name: [u8; 64],
    crypt_name: [u8; 64],
    encrypt_key: [u8; 32],
    init: [u64; 2],
}

impl Default for LoopInfo {
    fn default() -> Self {
        LoopInfo {
            device: 0,
            inode: 0,
            rdevice: 0,
            offset: 0,
            size_limit: 0,
            number: 0,
            encrypt_type: 0,
            encrypt_key_size: 0,
            flags: 0,
            file_name: [0; 64],
            crypt_name: [0; 64],
            encrypt_key: [0; 32],
            init: [0; 2],
        }
    }
}

const LOOP_CONTROL_PATH: &str = "/dev/loop-control";
#[cfg(feature = "async")]
const LOOP_DEV_FORMAT: &str = "/dev/loop";
#[cfg(feature = "async")]
const EBUSY_STRING: &str = "device or resource busy";
const OVERLAY_LOWERDIR_PREFIX: &str = "lowerdir=";

#[allow(dead_code)]
#[derive(Debug, Default, Clone)]
struct MountInfo {
    /// id is a unique identifier of the mount (may be reused after umount).
    pub id: u32,
    /// parent is the ID of the parent mount (or of self for the root
    /// of this mount namespace's mount tree).
    pub parent: u32,
    /// major and minor are the major and the minor components of the Dev
    /// field of unix.Stat_t structure returned by unix.*Stat calls for
    /// files on this filesystem.
    pub major: u32,
    pub minor: u32,
    /// root is the pathname of the directory in the filesystem which forms
    /// the root of this mount.
    pub root: String,
    /// mountpoint is the pathname of the mount point relative to the
    /// process's root directory.
    pub mountpoint: String,
    /// options is a comma-separated list of mount options.
    pub options: String,
    /// optional are zero or more fields of the form "tag[:value]",
    /// separated by a space.  Currently, the possible optional fields are
    /// "shared", "master", "propagate_from", and "unbindable". For more
    /// information, see mount_namespaces(7) Linux man page.
    pub optional: String,
    /// fs_type is the filesystem type in the form "type[.subtype]".
    pub fs_type: String,
    /// source is filesystem-specific information, or "none".
    pub source: String,
    /// vfs_options is a comma-separated list of superblock options.
    pub vfs_options: String,
}

static MOUNT_FLAGS: LazyLock<HashMap<&'static str, Flag>> = LazyLock::new(|| {
    let mut mf = HashMap::new();
    let zero: MsFlags = MsFlags::empty();
    mf.insert(
        "async",
        Flag {
            clear: true,
            flags: MsFlags::MS_SYNCHRONOUS,
        },
    );
    mf.insert(
        "atime",
        Flag {
            clear: true,
            flags: MsFlags::MS_NOATIME,
        },
    );
    mf.insert(
        "bind",
        Flag {
            clear: false,
            flags: MsFlags::MS_BIND,
        },
    );
    mf.insert(
        "defaults",
        Flag {
            clear: false,
            flags: zero,
        },
    );
    mf.insert(
        "dev",
        Flag {
            clear: true,
            flags: MsFlags::MS_NODEV,
        },
    );
    mf.insert(
        "diratime",
        Flag {
            clear: true,
            flags: MsFlags::MS_NODIRATIME,
        },
    );
    mf.insert(
        "dirsync",
        Flag {
            clear: false,
            flags: MsFlags::MS_DIRSYNC,
        },
    );
    mf.insert(
        "exec",
        Flag {
            clear: true,
            flags: MsFlags::MS_NOEXEC,
        },
    );
    mf.insert(
        "mand",
        Flag {
            clear: false,
            flags: MsFlags::MS_MANDLOCK,
        },
    );
    mf.insert(
        "noatime",
        Flag {
            clear: false,
            flags: MsFlags::MS_NOATIME,
        },
    );
    mf.insert(
        "nodev",
        Flag {
            clear: false,
            flags: MsFlags::MS_NODEV,
        },
    );
    mf.insert(
        "nodiratime",
        Flag {
            clear: false,
            flags: MsFlags::MS_NODIRATIME,
        },
    );
    mf.insert(
        "noexec",
        Flag {
            clear: false,
            flags: MsFlags::MS_NOEXEC,
        },
    );
    mf.insert(
        "nomand",
        Flag {
            clear: true,
            flags: MsFlags::MS_MANDLOCK,
        },
    );
    mf.insert(
        "norelatime",
        Flag {
            clear: true,
            flags: MsFlags::MS_RELATIME,
        },
    );
    mf.insert(
        "nostrictatime",
        Flag {
            clear: true,
            flags: MsFlags::MS_STRICTATIME,
        },
    );
    mf.insert(
        "nosuid",
        Flag {
            clear: false,
            flags: MsFlags::MS_NOSUID,
        },
    );
    mf.insert(
        "rbind",
        Flag {
            clear: false,
            flags: MsFlags::MS_BIND.union(MsFlags::MS_REC),
        },
    );
    mf.insert(
        "relatime",
        Flag {
            clear: false,
            flags: MsFlags::MS_RELATIME,
        },
    );
    mf.insert(
        "remount",
        Flag {
            clear: false,
            flags: MsFlags::MS_REMOUNT,
        },
    );
    mf.insert(
        "ro",
        Flag {
            clear: false,
            flags: MsFlags::MS_RDONLY,
        },
    );
    mf.insert(
        "rw",
        Flag {
            clear: true,
            flags: MsFlags::MS_RDONLY,
        },
    );
    mf.insert(
        "strictatime",
        Flag {
            clear: false,
            flags: MsFlags::MS_STRICTATIME,
        },
    );
    mf.insert(
        "suid",
        Flag {
            clear: true,
            flags: MsFlags::MS_NOSUID,
        },
    );
    mf.insert(
        "sync",
        Flag {
            clear: false,
            flags: MsFlags::MS_SYNCHRONOUS,
        },
    );
    mf
});

const PROPAGATION_TYPES: MsFlags = MsFlags::MS_SHARED
    .union(MsFlags::MS_PRIVATE)
    .union(MsFlags::MS_SLAVE)
    .union(MsFlags::MS_UNBINDABLE);

const MS_PROPAGATION: MsFlags = PROPAGATION_TYPES
    .union(MsFlags::MS_REC)
    .union(MsFlags::MS_SILENT);

const MS_BIND_RO: MsFlags = MsFlags::MS_BIND.union(MsFlags::MS_RDONLY);

fn page_size() -> usize {
    let ret = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    assert!(ret > 0, "sysconf(_SC_PAGESIZE) failed");
    ret as usize
}

fn options_size(options: &[String]) -> usize {
    options.iter().fold(0, |sum, x| sum + x.len())
}

fn longest_common_prefix(dirs: &[String]) -> &str {
    if dirs.is_empty() {
        return "";
    }

    let first_dir = &dirs[0];

    for (i, byte) in first_dir.as_bytes().iter().enumerate() {
        for dir in dirs {
            if dir.as_bytes().get(i) != Some(byte) {
                let mut end = i;
                // guaranteed not to underflow since is_char_boundary(0) is always true
                while !first_dir.is_char_boundary(end) {
                    end -= 1;
                }

                return &first_dir[0..end];
            }
        }
    }

    first_dir
}

// NOTE: the snapshot id is based on digits.
// in order to avoid to get snapshots/x, should be back to parent dir.
// however, there is assumption that the common dir is ${root}/io.containerd.v1.overlayfs/snapshots.
fn trim_flawed_dir(s: &str) -> String {
    s[0..s.rfind('/').unwrap_or(0) + 1].to_owned()
}

#[derive(Default)]
struct LowerdirCompactor {
    options: Vec<String>,
    lowerdirs: Option<Vec<String>>,
    lowerdir_prefix: Option<String>,
}

impl LowerdirCompactor {
    fn new(options: &[String]) -> Self {
        Self {
            options: options.to_vec(),
            ..Self::default()
        }
    }

    fn lowerdirs(&mut self) -> &mut Self {
        self.lowerdirs = Some(
            self.options
                .iter()
                .filter(|x| x.starts_with(OVERLAY_LOWERDIR_PREFIX))
                .map(|x| x.strip_prefix(OVERLAY_LOWERDIR_PREFIX).unwrap_or(x))
                .flat_map(|x| x.split(':'))
                .map(str::to_string)
                .collect(),
        );
        self
    }

    fn lowerdir_prefix(&mut self) -> &mut Self {
        self.lowerdir_prefix = self
            .lowerdirs
            .as_ref()
            .filter(|x| x.len() > 1)
            .map(|x| longest_common_prefix(x))
            .map(trim_flawed_dir)
            .filter(|x| !x.is_empty() && x != "/");
        self
    }

    fn compact(&mut self) -> (Option<String>, Vec<String>) {
        self.lowerdirs().lowerdir_prefix();
        if let Some(chdir) = &self.lowerdir_prefix {
            let lowerdir_str = self
                .lowerdirs
                .as_ref()
                .unwrap_or(&Vec::new())
                .iter()
                .map(|x| x.strip_prefix(chdir).unwrap_or(x))
                .collect::<Vec<&str>>()
                .join(":");
            let replace = |x: &str| -> String {
                if x.starts_with(OVERLAY_LOWERDIR_PREFIX) {
                    format!("{}{}", OVERLAY_LOWERDIR_PREFIX, lowerdir_str)
                } else {
                    x.to_string()
                }
            };
            (
                self.lowerdir_prefix.clone(),
                self.options
                    .iter()
                    .map(|x| replace(x))
                    .collect::<Vec<String>>(),
            )
        } else {
            (None, self.options.to_vec())
        }
    }
}

enum MountExitCode {
    NixUnknownErr,
    ChdirErr,
    Success,
    NixOtherErr(i32),
}

impl From<i32> for MountExitCode {
    fn from(code: i32) -> Self {
        match code {
            -2 => MountExitCode::NixUnknownErr,
            -1 => MountExitCode::ChdirErr,
            0 => MountExitCode::Success,
            _ => MountExitCode::NixOtherErr(code),
        }
    }
}

impl From<MountExitCode> for i32 {
    fn from(code: MountExitCode) -> Self {
        match code {
            MountExitCode::NixUnknownErr => -2,
            MountExitCode::ChdirErr => -1,
            MountExitCode::Success => 0,
            MountExitCode::NixOtherErr(errno) => errno,
        }
    }
}

impl From<nix::errno::Errno> for MountExitCode {
    fn from(err: nix::errno::Errno) -> Self {
        match err {
            nix::errno::Errno::UnknownErrno => MountExitCode::NixUnknownErr,
            _ => MountExitCode::NixOtherErr(err as i32),
        }
    }
}

impl From<MountExitCode> for nix::errno::Errno {
    fn from(code: MountExitCode) -> Self {
        match code {
            MountExitCode::NixOtherErr(errno) => nix::errno::Errno::from_raw(errno),
            _ => nix::errno::Errno::UnknownErrno,
        }
    }
}

impl From<MountExitCode> for Result<()> {
    fn from(code: MountExitCode) -> Self {
        match code {
            MountExitCode::NixUnknownErr => Err(other!(
                "mount process exit unexpectedly, exit code: {}",
                nix::errno::Errno::from(code)
            )),
            MountExitCode::ChdirErr => Err(other!("mount process exit unexpectedly: chdir failed")),
            MountExitCode::Success => Ok(()),
            MountExitCode::NixOtherErr(errno) => Err(other!(
                "mount process exit unexpectedly, exit code: {}",
                nix::errno::Errno::from_raw(errno)
            )),
        }
    }
}

#[cfg(not(feature = "async"))]
pub fn mount_rootfs(
    fs_type: Option<&str>,
    source: Option<&str>,
    options: &[String],
    target: impl AsRef<Path>,
) -> Result<()> {
    //TODO add helper to mount fuse
    let max_size = page_size();
    // avoid hitting one page limit of mount argument buffer
    //
    // NOTE: 512 id a buffer during pagesize check.
    let (chdir, options) =
        if fs_type.unwrap_or("") == "overlay" && options_size(options) >= max_size - 512 {
            LowerdirCompactor::new(options).compact()
        } else {
            (None, options.to_vec())
        };

    let mut flags: MsFlags = MsFlags::empty();
    let mut data = Vec::new();
    options.iter().for_each(|x| {
        if let Some(f) = MOUNT_FLAGS.get(x.as_str()) {
            if f.clear {
                flags.bitand_assign(f.flags.not());
            } else {
                flags.bitor_assign(f.flags)
            }
        } else {
            data.push(x.as_str())
        }
    });

    let opt = data.join(",");
    if opt.len() > max_size {
        return Err(other!("mount option is too long"));
    }

    let data = if !data.is_empty() {
        Some(opt.as_str())
    } else {
        None
    };

    let s = monitor_subscribe(Topic::All)?;
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child, .. }) => {
            let code: MountExitCode = wait_pid(i32::from(child), s).into();
            code.into()
        }
        Ok(ForkResult::Child) => {
            if let Some(workdir) = chdir {
                env::set_current_dir(Path::new(&workdir)).unwrap_or_else(|_| {
                    unsafe { libc::_exit(i32::from(MountExitCode::ChdirErr)) };
                });
            }
            // mount with non-propagation first, or remount with changed data
            let oflags = flags.bitand(PROPAGATION_TYPES.not());
            let zero: MsFlags = MsFlags::empty();
            if flags.bitand(MsFlags::MS_REMOUNT).eq(&zero) || data.is_some() {
                mount(source, target.as_ref(), fs_type, oflags, data).unwrap_or_else(|err| {
                    error!(
                        "Mount {:?} to {} failed: {}",
                        source,
                        target.as_ref().display(),
                        err
                    );
                    let code: MountExitCode = err.into();
                    unsafe { libc::_exit(code.into()) };
                });
            }
            // change the propagation type
            if flags.bitand(PROPAGATION_TYPES).ne(&zero) {
                mount::<str, Path, str, str>(
                    None,
                    target.as_ref(),
                    None,
                    flags.bitand(MS_PROPAGATION),
                    None,
                )
                .unwrap_or_else(|err| {
                    error!(
                        "Change {} mount propagation faied: {}",
                        target.as_ref().display(),
                        err
                    );
                    let code: MountExitCode = err.into();
                    unsafe { libc::_exit(code.into()) };
                });
            }
            if oflags.bitand(MS_BIND_RO).eq(&MS_BIND_RO) {
                mount::<str, Path, str, str>(
                    None,
                    target.as_ref(),
                    None,
                    oflags.bitor(MsFlags::MS_REMOUNT),
                    None,
                )
                .unwrap_or_else(|err| {
                    error!(
                        "Change {} read-only failed: {}",
                        target.as_ref().display(),
                        err
                    );
                    let code: MountExitCode = err.into();
                    unsafe { libc::_exit(code.into()) };
                });
            }
            unsafe { libc::_exit(i32::from(MountExitCode::Success)) };
        }
        Err(_) => Err(other!("fork mount process failed")),
    }
}

#[cfg(feature = "async")]
pub fn mount_rootfs(
    fs_type: Option<&str>,
    source: Option<&str>,
    options: &[String],
    target: impl AsRef<Path>,
) -> Result<()> {
    //TODO add helper to mount fuse
    let max_size = page_size();
    // NOTE: 512 id a buffer during pagesize check.
    let (chdir, options) =
        if fs_type.unwrap_or("") == "overlay" && options_size(options) >= max_size - 512 {
            LowerdirCompactor::new(options).compact()
        } else {
            (None, options.to_vec())
        };

    let mut flags: MsFlags = MsFlags::empty();
    let mut data = Vec::new();
    let mut lo_setup = false;
    let mut loop_params = LoopParams::default();
    options.iter().for_each(|x| {
        if let Some(f) = MOUNT_FLAGS.get(x.as_str()) {
            if f.clear {
                flags.bitand_assign(f.flags.not());
            } else {
                flags.bitor_assign(f.flags)
            }
        } else if x.as_str() == "loop" {
            lo_setup = true;
        } else {
            data.push(x.as_str())
        }
    });
    let opt = data.join(",");

    let data = if !data.is_empty() {
        Some(opt.as_str())
    } else {
        None
    };

    if let Some(workdir) = chdir {
        unshare(CloneFlags::CLONE_FS)?;
        env::set_current_dir(Path::new(&workdir)).unwrap_or_else(|_| {
            unsafe { libc::_exit(i32::from(MountExitCode::ChdirErr)) };
        });
    }
    // mount with non-propagation first, or remount with changed data
    let oflags = flags.bitand(PROPAGATION_TYPES.not());
    if lo_setup {
        loop_params = LoopParams {
            readonly: oflags.bitand(MsFlags::MS_RDONLY) == MsFlags::MS_RDONLY,
            auto_clear: true,
            direct: false,
        };
    }
    let zero: MsFlags = MsFlags::empty();
    if flags.bitand(MsFlags::MS_REMOUNT).eq(&zero) || data.is_some() {
        let lo_file: String;
        let s = if lo_setup {
            lo_file = setup_loop(source, loop_params)?;
            Some(lo_file.as_str())
        } else {
            source
        };
        mount(s, target.as_ref(), fs_type, oflags, data).map_err(mount_error!(
            e,
            "Mount {:?} to {}",
            source,
            target.as_ref().display()
        ))?;
    }

    // change the propagation type
    if flags.bitand(PROPAGATION_TYPES).ne(&zero) {
        mount::<str, Path, str, str>(None, target.as_ref(), None, MS_PROPAGATION, None).map_err(
            mount_error!(e, "Change {} mount propagation", target.as_ref().display()),
        )?;
    }

    if oflags.bitand(MS_BIND_RO).eq(&MS_BIND_RO) {
        mount::<str, Path, str, str>(
            None,
            target.as_ref(),
            None,
            oflags.bitor(MsFlags::MS_REMOUNT),
            None,
        )
        .map_err(mount_error!(
            e,
            "Change {} read-only",
            target.as_ref().display()
        ))?;
    }

    Ok(())
}

#[cfg(feature = "async")]
fn setup_loop(source: Option<&str>, params: LoopParams) -> Result<String> {
    let src = source.ok_or(other!("loop source is None"))?;
    for _ in 0..100 {
        let num = get_free_loop_dev()?;
        let loop_dev = format!("{}{}", LOOP_DEV_FORMAT, num);
        match setup_loop_dev(src, loop_dev.as_str(), &params) {
            Ok(_) => return Ok(loop_dev),
            Err(e) => {
                if e.to_string().contains(EBUSY_STRING) {
                    continue;
                } else {
                    return Err(e);
                }
            }
        }
    }
    Err(Error::Other(
        "creating new loopback device after 100 times".to_string(),
    ))
}

pub fn get_free_loop_dev() -> Result<i32> {
    const LOOP_CTL_GET_FREE: i32 = 0x4c82;
    let loop_control = File::options()
        .read(true)
        .write(true)
        .open(LOOP_CONTROL_PATH)
        .map_err(|e| Error::IoError {
            context: format!("open {} error: ", LOOP_CONTROL_PATH),
            err: e,
        })?;
    unsafe {
        #[cfg(target_env = "gnu")]
        let ret = libc::ioctl(
            loop_control.as_raw_fd() as libc::c_int,
            LOOP_CTL_GET_FREE as libc::c_ulong,
        ) as i32;
        #[cfg(target_env = "musl")]
        let ret = libc::ioctl(
            loop_control.as_raw_fd() as libc::c_int,
            LOOP_CTL_GET_FREE as libc::c_int,
        ) as i32;
        match nix::errno::Errno::result(ret) {
            Ok(ret) => Ok(ret),
            Err(e) => Err(Error::Nix(e)),
        }
    }
}

pub fn setup_loop_dev(backing_file: &str, loop_dev: &str, params: &LoopParams) -> Result<File> {
    const LOOP_SET_FD: u32 = 0x4c00;
    const LOOP_CLR_FD: u32 = 0x4c01;
    const LOOP_SET_STATUS64: u32 = 0x4c04;
    const LOOP_SET_DIRECT_IO: u32 = 0x4c08;
    const LO_FLAGS_READ_ONLY: u32 = 0x1;
    const LO_FLAGS_AUTOCLEAR: u32 = 0x4;
    let mut open_options = File::options();
    open_options.read(true);
    if !params.readonly {
        open_options.write(true);
    }
    // 1. open backing file
    let back = open_options
        .open(backing_file)
        .map_err(|e| Error::IoError {
            context: format!("open {} error: ", backing_file),
            err: e,
        })?;
    let loop_dev = open_options.open(loop_dev).map_err(|e| Error::IoError {
        context: format!("open {} error: ", loop_dev),
        err: e,
    })?;
    // 2. set FD
    unsafe {
        #[cfg(target_env = "gnu")]
        let ret = libc::ioctl(
            loop_dev.as_raw_fd() as libc::c_int,
            LOOP_SET_FD as libc::c_ulong,
            back.as_raw_fd() as libc::c_int,
        );
        #[cfg(target_env = "musl")]
        let ret = libc::ioctl(
            loop_dev.as_raw_fd() as libc::c_int,
            LOOP_SET_FD as libc::c_int,
            back.as_raw_fd() as libc::c_int,
        );
        if let Err(e) = nix::errno::Errno::result(ret) {
            return Err(Error::Nix(e));
        }
    }
    // 3. set info
    let mut info = LoopInfo::default();
    let backing_file_truncated = if backing_file.len() > info.file_name.len() {
        &backing_file[0..info.file_name.len()]
    } else {
        backing_file
    };
    info.file_name[..backing_file_truncated.len()]
        .copy_from_slice(backing_file_truncated.as_bytes());
    if params.readonly {
        info.flags |= LO_FLAGS_READ_ONLY;
    }

    if params.auto_clear {
        info.flags |= LO_FLAGS_AUTOCLEAR;
    }
    unsafe {
        #[cfg(target_env = "gnu")]
        let ret = libc::ioctl(
            loop_dev.as_raw_fd() as libc::c_int,
            LOOP_SET_STATUS64 as libc::c_ulong,
            &info,
        );
        #[cfg(target_env = "musl")]
        let ret = libc::ioctl(
            loop_dev.as_raw_fd() as libc::c_int,
            LOOP_SET_STATUS64 as libc::c_int,
            &info,
        );
        #[cfg(target_env = "gnu")]
        if let Err(e) = nix::errno::Errno::result(ret) {
            libc::ioctl(
                loop_dev.as_raw_fd() as libc::c_int,
                LOOP_CLR_FD as libc::c_ulong,
                0,
            );
            return Err(Error::Nix(e));
        }
        #[cfg(target_env = "musl")]
        if let Err(e) = nix::errno::Errno::result(ret) {
            libc::ioctl(
                loop_dev.as_raw_fd() as libc::c_int,
                LOOP_CLR_FD as libc::c_int,
                0,
            );
            return Err(Error::Nix(e));
        }
    }

    // 4. Set Direct IO
    if params.direct {
        unsafe {
            #[cfg(target_env = "gnu")]
            let ret = libc::ioctl(
                loop_dev.as_raw_fd() as libc::c_int,
                LOOP_SET_DIRECT_IO as libc::c_ulong,
                1,
            );
            #[cfg(target_env = "musl")]
            let ret = libc::ioctl(
                loop_dev.as_raw_fd() as libc::c_int,
                LOOP_SET_DIRECT_IO as libc::c_int,
                1,
            );
            if let Err(e) = nix::errno::Errno::result(ret) {
                #[cfg(target_env = "gnu")]
                libc::ioctl(
                    loop_dev.as_raw_fd() as libc::c_int,
                    LOOP_CLR_FD as libc::c_ulong,
                    0,
                );
                #[cfg(target_env = "musl")]
                libc::ioctl(
                    loop_dev.as_raw_fd() as libc::c_int,
                    LOOP_CLR_FD as libc::c_int,
                    0,
                );
                return Err(Error::Nix(e));
            }
        }
    }
    Ok(loop_dev)
}

pub fn umount_recursive(target: Option<&str>, flags: i32) -> Result<()> {
    if let Some(target) = target {
        let mut mounts = get_mounts(Some(prefix_filter(target.to_string())))?;
        mounts.sort_by(|a, b| b.mountpoint.len().cmp(&a.mountpoint.len()));
        for target in &mounts {
            umount_all(Some(target.mountpoint.clone()), flags)?;
        }
    };
    Ok(())
}

fn umount_all(target: Option<String>, flags: i32) -> Result<()> {
    if let Some(target) = target {
        if let Err(e) = std::fs::metadata(target.clone()) {
            if e.kind() == std::io::ErrorKind::NotFound {
                return Ok(());
            }
        }
        loop {
            if let Err(e) = nix::mount::umount2(
                &std::path::PathBuf::from(&target),
                MntFlags::from_bits(flags).unwrap_or(MntFlags::empty()),
            ) {
                if e == nix::errno::Errno::EINVAL {
                    return Ok(());
                }
                return Err(Error::from(e));
            }
        }
    };
    Ok(())
}

fn prefix_filter(prefix: String) -> impl Fn(MountInfo) -> bool {
    move |m: MountInfo| !(m.mountpoint.clone() + "/").starts_with(&(prefix.clone() + "/"))
}

fn get_mounts<F>(f: Option<F>) -> Result<Vec<MountInfo>>
where
    F: Fn(MountInfo) -> bool,
{
    let mountinfo_path = "/proc/self/mountinfo";
    let file = std::fs::File::open(mountinfo_path).map_err(io_error!(e, "io_error"))?;
    let reader = std::io::BufReader::new(file);
    let lines: Vec<String> = reader.lines().map_while(|line| line.ok()).collect();
    let mount_points = lines
        .into_iter()
        .filter_map(|line| {
            /*
            See http://man7.org/linux/man-pages/man5/proc.5.html
            36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue
            (1)(2)(3)   (4)   (5)      (6)      (7)   (8) (9)   (10)         (11)
            (1) mount ID:  unique identifier of the mount (may be reused after umount)
            (2) parent ID:  ID of parent (or of self for the top of the mount tree)
            (3) major:minor:  value of st_dev for files on filesystem
            (4) root:  root of the mount within the filesystem
            (5) mount point:  mount point relative to the process's root
            (6) mount options:  per mount options
            (7) optional fields:  zero or more fields of the form "tag[:value]"
            (8) separator:  marks the end of the optional fields
            (9) filesystem type:  name of filesystem of the form "type[.subtype]"
            (10) mount source:  filesystem specific information or "none"
            (11) super options:  per super block options
            In other words, we have:
             * 6 mandatory fields	(1)..(6)
             * 0 or more optional fields	(7)
             * a separator field		(8)
             * 3 mandatory fields	(9)..(11)
             */
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 10 {
                // mountpoint parse error.
                return None;
            }
            // separator field
            let mut sep_idx = parts.len() - 4;
            // In Linux <= 3.9 mounting a cifs with spaces in a share
            // name (like "//srv/My Docs") _may_ end up having a space
            // in the last field of mountinfo (like "unc=//serv/My Docs").
            // Since kernel 3.10-rc1, cifs option "unc=" is ignored,
            // so spaces should not appear.
            //
            // Check for a separator, and work around the spaces bug
            for i in (0..sep_idx).rev() {
                if parts[i] == "-" {
                    sep_idx = i;
                    break;
                }
                if sep_idx == 5 {
                    // mountpoint parse error
                    return None;
                }
            }

            let mut mount_info = MountInfo {
                id: str::parse::<u32>(parts[0]).ok()?,
                parent: str::parse::<u32>(parts[1]).ok()?,
                major: 0,
                minor: 0,
                root: parts[3].to_string(),
                mountpoint: parts[4].to_string(),
                options: parts[5].to_string(),
                optional: parts[6..sep_idx].join(" "),
                fs_type: parts[sep_idx + 1].to_string(),
                source: parts[sep_idx + 2].to_string(),
                vfs_options: parts[sep_idx + 3].to_string(),
            };
            let major_minor = parts[2].splitn(3, ':').collect::<Vec<&str>>();
            if major_minor.len() != 2 {
                // mountpoint parse error.
                return None;
            }
            mount_info.major = str::parse::<u32>(major_minor[0]).ok()?;
            mount_info.minor = str::parse::<u32>(major_minor[1]).ok()?;
            if let Some(f) = &f {
                if f(mount_info.clone()) {
                    // skip this mountpoint. This mountpoint is not the container's mountpoint
                    return None;
                }
            }
            Some(mount_info)
        })
        .collect::<Vec<MountInfo>>();
    Ok(mount_points)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trim_flawed_dir() {
        let mut tcases: Vec<(&str, String)> = Vec::new();
        tcases.push(("/", "/".to_string()));
        tcases.push(("/foo", "/".to_string()));
        tcases.push(("/.foo-_bar/foo", "/.foo-_bar/".to_string()));
        tcases.push(("/.foo-_bar/foo/", "/.foo-_bar/foo/".to_string()));
        tcases.push(("/.foo-_bar/foo/bar", "/.foo-_bar/foo/".to_string()));
        tcases.push(("/.foo-_bar/foo/bar/", "/.foo-_bar/foo/bar/".to_string()));
        for (case, expected) in tcases {
            let res = trim_flawed_dir(case);
            assert_eq!(res, expected);
        }
    }

    #[test]
    fn test_longest_common_prefix() {
        let mut tcases: Vec<(Vec<String>, String)> = Vec::new();
        tcases.push((vec![], "".to_string()));
        tcases.push((vec!["foo".to_string()], "foo".to_string()));
        tcases.push((vec!["foo".to_string(), "bar".to_string()], "".to_string()));
        tcases.push((
            vec!["foo".to_string(), "foo".to_string()],
            "foo".to_string(),
        ));
        tcases.push((
            vec!["foo".to_string(), "foobar".to_string()],
            "foo".to_string(),
        ));
        tcases.push((
            vec!["foo".to_string(), "".to_string(), "foobar".to_string()],
            "".to_string(),
        ));
        for (case, expected) in tcases {
            let res = longest_common_prefix(&case);
            assert_eq!(res, expected);
        }
    }

    #[test]
    fn test_compact_lowerdir_option() {
        let mut tcases: Vec<(Vec<String>, Option<String>, Vec<String>)> = Vec::new();
        tcases.push((
            vec!["workdir=a".to_string()],
            None,
            vec!["workdir=a".to_string()],
        ));
        tcases.push((
            vec!["workdir=a".to_string(), "lowerdir=b".to_string()],
            None,
            vec!["workdir=a".to_string(), "lowerdir=b".to_string()],
        ));
        tcases.push((
            vec!["lowerdir=/snapshots/1/fs:/snapshots/10/fs".to_string()],
            Some("/snapshots/".to_string()),
            vec!["lowerdir=1/fs:10/fs".to_string()],
        ));
        tcases.push((
            vec![
                "workdir=a".to_string(),
                "lowerdir=/snapshots/1/fs:/snapshots/10/fs".to_string(),
            ],
            Some("/snapshots/".to_string()),
            vec!["workdir=a".to_string(), "lowerdir=1/fs:10/fs".to_string()],
        ));
        tcases.push((
            vec!["lowerdir=/snapshots/1/fs:/snapshots/10/fs:/snapshots/2/fs".to_string()],
            Some("/snapshots/".to_string()),
            vec!["lowerdir=1/fs:10/fs:2/fs".to_string()],
        ));
        tcases.push((
            vec![
                "workdir=a".to_string(),
                "lowerdir=/snapshots/1/fs:/snapshots/10/fs:/snapshots/2/fs".to_string(),
            ],
            Some("/snapshots/".to_string()),
            vec![
                "workdir=a".to_string(),
                "lowerdir=1/fs:10/fs:2/fs".to_string(),
            ],
        ));
        tcases.push((
            vec!["lowerdir=/snapshots/1/fs:/other_snapshots/1/fs".to_string()],
            None,
            vec!["lowerdir=/snapshots/1/fs:/other_snapshots/1/fs".to_string()],
        ));
        tcases.push((
            vec![
                "workdir=a".to_string(),
                "lowerdir=/snapshots/1/fs:/other_snapshots/1/fs".to_string(),
            ],
            None,
            vec![
                "workdir=a".to_string(),
                "lowerdir=/snapshots/1/fs:/other_snapshots/1/fs".to_string(),
            ],
        ));
        for (case, expected_chdir, expected_options) in tcases {
            let (chdir, options) = LowerdirCompactor::new(&case).compact();
            assert_eq!(chdir, expected_chdir);
            assert_eq!(options, expected_options);
        }
    }

    #[cfg(feature = "async")]
    #[test]
    fn test_mount_rootfs_umount_recursive() {
        let target = tempfile::tempdir().expect("create target dir error");
        let lower1 = tempfile::tempdir().expect("create lower1 dir error");
        let lower2 = tempfile::tempdir().expect("create lower2 dir error");
        let upperdir = tempfile::tempdir().expect("create upperdir dir error");
        let workdir = tempfile::tempdir().expect("create workdir dir error");
        let options = vec![
            "lowerdir=".to_string()
                + lower1.path().to_str().expect("lower1 path to str error")
                + ":"
                + lower2.path().to_str().expect("lower2 path to str error"),
            "upperdir=".to_string()
                + upperdir
                    .path()
                    .to_str()
                    .expect("upperdir path to str error"),
            "workdir=".to_string() + workdir.path().to_str().expect("workdir path to str error"),
        ];
        // mount target.
        let result = mount_rootfs(Some("overlay"), Some("overlay"), &options, &target);
        assert!(result.is_ok());
        let mut mountinfo = get_mounts(Some(prefix_filter(
            target
                .path()
                .to_str()
                .expect("target path to str error")
                .to_string(),
        )))
        .expect("get_mounts error");
        // make sure the target has been mounted.
        assert_ne!(0, mountinfo.len());
        // umount target.
        let result = umount_recursive(target.path().to_str(), 0);
        assert!(result.is_ok());
        mountinfo = get_mounts(Some(prefix_filter(
            target
                .path()
                .to_str()
                .expect("target path to str error")
                .to_string(),
        )))
        .expect("get_mounts error");
        // make sure the target has been unmounted.
        assert_eq!(0, mountinfo.len());
    }

    #[cfg(feature = "async")]
    #[test]
    fn test_setup_loop_dev() {
        let path = tempfile::NamedTempFile::new().expect("cannot create tempfile");
        let backing_file = path.path().to_str();
        let params = LoopParams {
            readonly: false,
            auto_clear: true,
            direct: true,
        };
        let result = setup_loop(backing_file, params);
        assert!(result.is_ok());
    }
}
