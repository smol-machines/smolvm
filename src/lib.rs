//! smolvm - OCI-native microVM runtime
//!
//! smolvm is a library and CLI for running microVMs with strong isolation
//! and OCI container compatibility.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────┐
//! │  smolvm CLI / Library                           │
//! ├─────────────────────────────────────────────────┤
//! │  VM abstraction (VmBackend, VmHandle)           │
//! ├─────────────────────────────────────────────────┤
//! │  libkrun (Hypervisor.framework / KVM)           │
//! ├─────────────────────────────────────────────────┤
//! │  libkrunfw (embedded Linux kernel)              │
//! └─────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```no_run
//! use smolvm::{VmConfig, RootfsSource, default_backend};
//!
//! // Create a VM configuration
//! let config = VmConfig::builder(RootfsSource::path("/path/to/rootfs"))
//!     .memory(1024)  // 1 GB
//!     .cpus(2)
//!     .command(vec!["/bin/sh".into()])
//!     .build();
//!
//! // Get the default backend for this platform
//! let backend = default_backend().unwrap();
//!
//! // Create and run the VM
//! let mut vm = backend.create(config).unwrap();
//! let exit = vm.wait().unwrap();
//!
//! println!("VM exited with: {}", exit);
//! ```
//!
//! # Features
//!
//! ## Phase 0 (Current)
//! - VM creation and lifecycle management
//! - Rootfs from path
//! - Host directory mounts via virtiofs
//! - Network egress via NAT
//!
//! ## Phase 1 (Planned)
//! - vsock control channel
//! - Persistent overlay disks
//! - `exec` into running VMs
//! - Clean shutdown protocol
//!
//! # Platform Support
//!
//! | Platform | Backend | Status |
//! |----------|---------|--------|
//! | macOS (Apple Silicon) | libkrun + Hypervisor.framework | ✅ |
//! | macOS (Intel) | libkrun + Hypervisor.framework | ✅ |
//! | Linux (arm64) | libkrun + KVM | ✅ |
//! | Linux (x86_64) | libkrun + KVM | ✅ |

#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod agent;
pub mod config;
pub mod error;
pub mod mount;
pub mod network;
pub mod platform;
pub mod process;
pub mod rootfs;
pub mod storage;
pub mod util;
pub mod vm;

// Re-export main types for convenience
pub use agent::{AgentClient, AgentManager};
pub use config::{RecordState, SmolvmConfig, VmRecord};
pub use error::{Error, Result};
pub use process::ChildProcess;
pub use vm::config::{HostMount, NetworkPolicy, Resources, RootfsSource, Timeouts, VmConfig, VmId};
pub use vm::state::{ExitReason, VmState};
pub use vm::{default_backend, VmBackend, VmHandle};

/// Library version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
