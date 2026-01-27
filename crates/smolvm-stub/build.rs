//! Build script for smolvm-stub.
//!
//! The stub uses dlopen to load libkrun dynamically at runtime after
//! assets are extracted, so no compile-time linking is required.

fn main() {
    // No compile-time linking required - libkrun is loaded via dlopen
    // after assets are extracted to the cache directory.
}
