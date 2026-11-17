# smolfile

Parse **Smolfiles: declarative TOML configurations for smolvm workloads**.
Use this library to build configuration editors, deployment tooling, or other
Rust integrations without launching a VM.

The Cargo package is named `smolfile`; its source directory in the smolvm
repository is `crates/smolvm-smolfile`.

## Add to your project

```sh
cargo add smolfile
```

## Parse a workload

```rust
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let workload = smolfile::parse(r#"
image = "python:3.12-alpine"
cpus = 2
memory = 1024
net = false
entrypoint = ["python3"]
cmd = ["-m", "http.server", "8080"]

[dev]
ports = ["8080:8080"]
"#)?;
    assert_eq!(workload.image.as_deref(), Some("python:3.12-alpine"));
    assert_eq!(workload.cpus, Some(2));
    assert_eq!(workload.memory, Some(1024));
    Ok(())
}
```

Use `smolfile::load(std::path::Path::new("Smolfile"))` to read from disk.
The conventional filename is `Smolfile`, with no extension.

## What you can describe

- Image, command, environment, and working directory.
- CPU, memory, disk, and networking settings.
- Development mounts, ports, and initialization commands under `[dev]`.
- Packaging overrides under `[artifact]`.
- Network policy, health checks, restart policy, and secret references.

Memory is expressed in MiB and storage sizes in GiB. Omitted optional fields
remain optional in the parsed representation; the consuming runtime supplies
defaults and applies CLI/profile precedence.

## Parsing is not execution

This crate parses configuration; it does not pull images, provision machines,
enforce network policy, run health checks, or resolve secret values. Those are
responsibilities of the consuming runtime. Successful parsing is not a guarantee
that a configuration is supported on the chosen host.

Secret configuration contains references such as `from_env` and `from_file`,
not a secret store. A consumer must validate and authorize references before
resolving them, especially when configuration comes from an untrusted source.

To execute workloads, install the
[smolvm runtime](https://github.com/smol-machines/smolvm#readme) and pass your file
with `smolvm machine run -s Smolfile`.

## Links

[API documentation](https://docs.rs/smolfile) · [crates.io](https://crates.io/crates/smolfile) · [Source](https://github.com/smol-machines/smolvm/tree/main/crates/smolvm-smolfile)

Part of [Smol Machines](https://github.com/smol-machines/smolvm). Licensed under Apache-2.0.
