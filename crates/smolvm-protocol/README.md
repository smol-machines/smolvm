# smolvm-protocol

Typed messages and framing for communication between the **smolvm host and its
Linux guest agent**. Use this crate when implementing protocol integrations,
inspecting messages, or working on the host/guest boundary.

This is a protocol library, **not a VM launcher or the smolvm SDK**. To run
machines, start with the [smolvm runtime](https://github.com/smol-machines/smolvm#readme).

## Add to your project

```sh
cargo add smolvm-protocol
```

## Encode and decode a frame

The helpers accept Serde-compatible values. This small round trip demonstrates
framing; the string is not an executable guest-agent request.

```rust
use smolvm_protocol::{decode_message, encode_message};

fn main() {
    let frame = encode_message(&"hello").expect("encode JSON");
    let value: String = decode_message(&frame).expect("decode frame");
    assert_eq!(value, "hello");
}
```

A frame consists of a four-byte big-endian JSON payload length followed by that
payload. The receiver must assemble a complete frame from its transport before
decoding it; a socket read is not necessarily a whole message.
The decoder rejects payload lengths above `MAX_FRAME_SIZE`.

## What is included

- Host/guest request and response types for execution, files, and image operations.
- Serde serialization and length-prefixed JSON framing.
- Shared image-reference, secret-reference, and guest-environment helpers.

Serialization does not establish authentication, authorization, or a secure
transport. Integrators must enforce those boundaries themselves. Check the
message definitions and protocol compatibility when updating either endpoint;
the crate version is not a promise that every host and guest release interoperates.

## Links

[API documentation](https://docs.rs/smolvm-protocol) · [crates.io](https://crates.io/crates/smolvm-protocol) · [Source](https://github.com/smol-machines/smolvm/tree/main/crates/smolvm-protocol)

Part of [Smol Machines](https://github.com/smol-machines/smolvm). Licensed under Apache-2.0.
