//! Incremental checkpoint storage without a VM runtime dependency.
//!
//! Callers supply stable files or streams; this crate chunks, verifies, stores,
//! materializes, and exports them. It does not pause or resume virtual machines.
//! See [`store::Writer`] for capture and [`store::materialize`] for restoration.

#![deny(missing_docs)]

pub mod store;

/// Manifest types shared with SmolVM's portable artifact format.
pub use smolvm_pack::format;
pub use store::{
    export, logical_size, materialize, materialize_with_base, promote_base, prune, publish,
    read_manifest, StoredFile, WriteStats, Writer,
};
