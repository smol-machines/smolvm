//! vsock support for the helper daemon.
//!
//! This module provides vsock server functionality for Linux guests.

use std::io::{Read, Write};
use std::os::fd::OwnedFd;

/// vsock listener.
pub struct VsockListener {
    #[allow(dead_code)] // Accessed via AsRawFd trait
    fd: OwnedFd,
}

/// vsock stream (connection).
pub struct VsockStream {
    #[allow(dead_code)] // Accessed via AsRawFd trait
    fd: OwnedFd,
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::mem;

    // vsock constants
    const AF_VSOCK: libc::c_int = 40;
    const VMADDR_CID_ANY: u32 = u32::MAX;

    #[repr(C)]
    struct sockaddr_vm {
        svm_family: libc::sa_family_t,
        svm_reserved1: u16,
        svm_port: u32,
        svm_cid: u32,
        svm_zero: [u8; 4],
    }

    impl VsockListener {
        /// Create a new vsock listener on the given port.
        pub fn bind(port: u32) -> std::io::Result<Self> {
            unsafe {
                // Create socket
                let fd = libc::socket(AF_VSOCK, libc::SOCK_STREAM, 0);
                if fd < 0 {
                    return Err(std::io::Error::last_os_error());
                }

                let fd = OwnedFd::from_raw_fd(fd);

                // Bind to port
                let addr = sockaddr_vm {
                    svm_family: AF_VSOCK as u16,
                    svm_reserved1: 0,
                    svm_port: port,
                    svm_cid: VMADDR_CID_ANY,
                    svm_zero: [0; 4],
                };

                if libc::bind(
                    fd.as_raw_fd(),
                    &addr as *const sockaddr_vm as *const libc::sockaddr,
                    mem::size_of::<sockaddr_vm>() as libc::socklen_t,
                ) < 0
                {
                    return Err(std::io::Error::last_os_error());
                }

                // Listen
                if libc::listen(fd.as_raw_fd(), 1) < 0 {
                    return Err(std::io::Error::last_os_error());
                }

                Ok(Self { fd })
            }
        }

        /// Accept a new connection.
        pub fn accept(&self) -> std::io::Result<VsockStream> {
            unsafe {
                let fd = libc::accept(
                    self.fd.as_raw_fd(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                );
                if fd < 0 {
                    return Err(std::io::Error::last_os_error());
                }

                Ok(VsockStream {
                    fd: OwnedFd::from_raw_fd(fd),
                })
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod stub {
    use super::*;

    impl VsockListener {
        pub fn bind(_port: u32) -> std::io::Result<Self> {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "vsock only supported on Linux",
            ))
        }

        pub fn accept(&self) -> std::io::Result<VsockStream> {
            unreachable!()
        }
    }
}

#[cfg(target_os = "linux")]
impl Read for VsockStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        unsafe {
            let n = libc::read(self.fd.as_raw_fd(), buf.as_mut_ptr() as *mut _, buf.len());
            if n < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        }
    }
}

#[cfg(target_os = "linux")]
impl Write for VsockStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        unsafe {
            let n = libc::write(self.fd.as_raw_fd(), buf.as_ptr() as *const _, buf.len());
            if n < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
impl Read for VsockStream {
    fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
        unreachable!("vsock only supported on Linux")
    }
}

#[cfg(not(target_os = "linux"))]
impl Write for VsockStream {
    fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
        unreachable!("vsock only supported on Linux")
    }

    fn flush(&mut self) -> std::io::Result<()> {
        unreachable!("vsock only supported on Linux")
    }
}

/// Listen on a vsock port.
pub fn listen(port: u32) -> std::io::Result<VsockListener> {
    VsockListener::bind(port)
}
