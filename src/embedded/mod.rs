//! Language-neutral embedded runtime support for SDK bindings.

mod control;
mod handle;
mod runtime;

pub use control::MachineSpec;
pub use runtime::{runtime, EmbeddedRuntime};
