//! Language-neutral embedded runtime support for SDK bindings.

mod control;
mod handle;
mod paths;
mod runtime;

pub use control::MachineSpec;
pub use paths::{configure_paths, configured_paths, EmbeddedPaths};
pub use runtime::{runtime, EmbeddedRuntime};
