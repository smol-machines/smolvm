# smolvm-pack

Read and build **smolvm portable machine artifacts**. This library contains the
`.smolmachine` format, manifest and footer handling, asset collection, packing,
and extraction used by the smolvm runtime.

Use it for artifact inspection or packaging integrations. It does **not** boot
VMs or download a complete runtime merely by adding it as a dependency.

## Add to your project

```sh
cargo add smolvm-pack
```

## Inspect a machine manifest

```rust,no_run
use smolvm_pack::read_manifest_from_sidecar;

fn main() -> smolvm_pack::Result<()> {
    let path = std::env::args().nth(1)
        .expect("usage: inspect <file.smolmachine>");
    let manifest = read_manifest_from_sidecar(path)?;
    println!("{manifest:#?}");
    Ok(())
}
```

This reads an existing sidecar; it does not execute the guest. Reading a manifest
alone is not a full integrity or authenticity check.

## Packaging model

The normal sidecar workflow distributes a host-specific launcher alongside a
`.smolmachine` payload. Keep both files together. The crate also contains
embedded-artifact support; see `Packer` and `PackMode` in the API documentation.

For an end-user workflow, install the
[smolvm runtime](https://github.com/smol-machines/smolvm#readme), then use:

```sh
smolvm pack create --image python:3.12-alpine -o ./my-python
./my-python run -- python3 -c "print('hello from a microVM')"
```

Building runnable artifacts requires the appropriate runtime assets. Executing
them still requires a supported host, architecture, and hypervisor. Packaging
does not emulate a different CPU architecture.

## API entry points

- `Packer`: collect assets and construct an artifact.
- `PackManifest`, `PackFooter`: metadata and format structures.
- `read_manifest_from_sidecar`: inspect an existing sidecar.
- `verify_sidecar_checksum`: verify the sidecar checksum.
- `extract`: extraction and runtime asset handling.

A checksum detects corruption; it is not proof of publisher identity. Treat
machine artifacts as executable software and use trusted sources.

## Links

[API documentation](https://docs.rs/smolvm-pack) · [crates.io](https://crates.io/crates/smolvm-pack) · [Source](https://github.com/smol-machines/smolvm/tree/main/crates/smolvm-pack)

Part of [Smol Machines](https://github.com/smol-machines/smolvm). Licensed under Apache-2.0.
