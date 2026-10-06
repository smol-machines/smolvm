# Packing a machine into a portable artifact

Turn an image or a provisioned machine into a file you can copy to another host and run with no
install step and no runtime downloads.

`SKILL.md` is the procedure, [pack layer ownership](../pack-layer-ownership.md) explains why a pack
built by smolvm older than 1.8.1 loses its files' owners, and `references/traps.md` carries the
rest.

## Two files by default, or one if you ask

```bash
smolvm pack create --image python:3.12-alpine --output ./python312
./python312 run -- python3 --version
```

That writes **two** files, and both must travel together:

| File | What |
|---|---|
| `python312` | the stub: a platform-specific binary with the VM runtime embedded |
| `python312.smolmachine` | the payload: rootfs, OCI layers and storage, cross-platform |

The CLI says so when it finishes (`Note: Keep the .smolmachine file alongside the binary`), and the
stub on its own prints smolvm's usage and exits. **`--single-file` writes one executable with no
sidecar**, which is what to use when "one file" is the requirement; its own help warns it may have
issues with macOS notarization.

## The artifact's own subcommands

```bash
./my-app run  -- python3 -c "print('hello')"   # ephemeral, cleaned up after exit
./my-app start                                 # persistent daemon mode
./my-app exec -- pip install x                 # exec into the daemon
./my-app stop
```

`run` and `start` take `--ssh-agent` from v1.18.1, which forwards the host's SSH agent into the
artifact's VM so a workload can use keys that never enter it; it needs `SSH_AUTH_SOCK` set on the
host.

A bare `--` is rejected: the stub takes a subcommand first, and the tip it prints does not mention
`run`. `smolvm pack run` takes `--sidecar <PATH>`, not a positional path.

## Assert a value, not a boot

**A pack that lost its rootfs still boots, still prints a guest kernel and still exits zero.** Write
a marker into the source machine, then read it back out of the artifact. That is what
`scripts/verify-pack.sh` does and why `scripts/pack-machine.sh` refuses to export a source that
does not carry its marker.

## Packing from a machine

`pack create --from-vm` exports a stopped machine. On v1.16.1 a **branched** machine packs and the
artifact carries both the state it inherited and the state written after the branch; that was
refused by design on v1.14.6. A branch must be stopped first. On macOS before v1.20.0, taking a
checkpoint of a machine needed it to have been started `--branchable`, and the error when it was
not names neither the flag nor the precondition. From v1.20.0 a checkpoint file does not need it;
a stored checkpoint, `--store`, still does.

Both pack paths boot a helper VM first. `pack create --image` pulls the image in one fixed at
8192 MiB, which `--mem` does not change: `--mem` is the artifact's. `pack create --from-vm` boots
an export helper, fixed at 8192 MiB through v1.16.1, when a host that could not seat it failed
with a bare `agent did not become ready within 30 seconds`. From v1.16.2 it asks for 4096 MiB,
less on a Linux host with less available, `SMOLVM_EXPORT_HELPER_MEMORY_MIB` sets it, and its
failure names both. From v1.16.1 the helper reuses the machine's cached image layers instead of
pulling the image again, and an export finished in 1.2 s here.
