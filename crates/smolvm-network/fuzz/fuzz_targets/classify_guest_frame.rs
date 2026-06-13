#![no_main]
//! Fuzz the host-side parser of guest-driven ethernet frames.
//!
//! A malicious guest sends arbitrary bytes over virtio-net; the host runs each
//! through `classify_guest_frame`. It must never panic / abort on any input.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    smolvm_network::stack::fuzz_classify_guest_frame(data);
});
