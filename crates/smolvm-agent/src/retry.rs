//! Retry utilities for transient failure recovery.
//!
//! This module re-exports retry utilities from smolvm-protocol for use
//! in the agent. The shared implementation ensures consistent retry
//! behavior across host and guest.

// Re-export everything from the protocol's retry module
pub use smolvm_protocol::retry::*;
