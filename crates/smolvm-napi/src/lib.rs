//! smolvm-napi — NAPI-RS bindings for the smolvm microVM runtime.
//!
//! This crate provides native Node.js bindings via NAPI-RS, allowing users
//! to create, manage, and interact with microVMs directly from Node.js
//! without requiring the `smolvm serve` daemon.
//!
//! # Architecture
//!
//! ```text
//! TypeScript API layer (ergonomic, API-compatible with smolvm-node)
//!   └── @smolvm/native .node binary (this crate)
//!         └── smolvm library (Rust)
//!               └── libkrun (dynamic linking) → Hypervisor.framework / KVM
//! ```

pub mod error;
pub mod sandbox;
pub mod types;
