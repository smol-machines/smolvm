# smolvm-registry

An **OCI Distribution client for smolvm machine artifacts**. Publish and retrieve
`.smolmachine` payloads using OCI manifests and a content-addressed blob cache.

Use this library to integrate machine-artifact distribution into a service or
tool. It is not a general-purpose container image builder, and downloading an
artifact does not launch a VM.

## Add to your project

```sh
cargo add smolvm-registry
```

## Create a registry client

```rust
use smolvm_registry::RegistryClient;

fn main() {
    let client = RegistryClient::new(
        "https://registry.smolmachines.com".to_owned(),
    );
    assert_eq!(client.base_url(), "https://registry.smolmachines.com");
}
```

Constructing a client makes no registry request. Use the asynchronous `pull`
and `push` APIs with a Tokio runtime for transfers; consult the API docs for
their arguments and authentication options.

## What it handles

- `RegistryClient`: registry HTTP operations and authentication configuration.
- `pull` / `PullResult`: fetch a machine artifact and report its local path,
  digest, size, and cache status.
- `push` / `PushResult`: upload an existing machine artifact.
- `BlobCache`: locally cached content-addressed blobs.
- OCI manifest and descriptor types for the smolmachine artifact media types.

The payload is a machine artifact, not an ordinary OCI container root filesystem.
A registry must accept the relevant artifact media types and your credentials
must authorize the requested repository operations.

## Choosing the right layer

Use [smolvm-pack](https://crates.io/crates/smolvm-pack) to inspect or construct
local artifacts; use this crate to distribute them. Use the
[smolvm runtime](https://github.com/smol-machines/smolvm#readme) to run machines.

Content digests establish content identity, not publisher trust. Keep registry
credentials out of source code and logs, and execute only trusted artifacts.

## Links

[API documentation](https://docs.rs/smolvm-registry) · [crates.io](https://crates.io/crates/smolvm-registry) · [Source](https://github.com/smol-machines/smolvm/tree/main/crates/smolvm-registry)

Part of [Smol Machines](https://github.com/smol-machines/smolvm). Licensed under Apache-2.0.
