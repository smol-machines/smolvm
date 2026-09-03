Pack Layer Ownership
====================

A pack built by smolvm **older than 1.8.1** cannot carry the file ownership its
image recorded. Re-pack it with 1.8.1 or later — there is no other fix.

## Are you affected?

Both of these must hold:

- the pack was built by smolvm older than 1.8.1 — check the `Version:` line of
  `smolvm pack inspect <ref>`; and
- something in the image is owned by a uid other than 0: a database data
  directory, a service account's home, a cache owned by an unprivileged user.

How badly depends on how smolvm itself runs:

| how smolvm runs | what the machine sees |
| --- | --- |
| unprivileged (a laptop, `smolvm machine run`) | every file owned by the current user |
| **as root** (smolfleet nodes, the Kubernetes shim) | **every non-zero owner becomes the overflow uid, 65534/nobody** |

The root case is [#1095], and it is the one that breaks services: a daemon that
drops to its own account can no longer read its own data directory. Nothing fails
at extraction time — it surfaces later, at runtime, as a permission error that
does not mention packing.

## Why

Since 1.8.1, layer tars are staged on the host and unpacked *inside* the machine,
where the agent is root and reproduces every owner exactly. A pack built before
that carries an agent which only recognises layer *directories*, so smolvm has to
fall back to unpacking on the host.

Host-side unpacking cannot reproduce the owners:

- **Unprivileged**, `chown` fails with `EPERM`, so every entry lands owned by
  whoever ran smolvm.
- **As root**, `chown` succeeds and the archive's owners do reach the disk — but a
  machine reaches the shared store through an idmapped mount that maps exactly one
  id: on-disk `0` becomes that machine's own uid. Every other owner has no mapping
  and surfaces as the overflow uid.

That one-id mapping is deliberate. It is what gives each machine a private uid
without chowning a shared copy per machine ([#456]). Widening it to carry
arbitrary owners would dissolve the isolation it exists to provide, so the two
requirements genuinely conflict — which is why correctness for current packs is
bought by unpacking in the guest instead.

## The fix

Re-pack with smolvm 1.8.1 or later:

```bash
smolvm pack inspect ghcr.io/you/app:v1      # check the Version: line
smolvm pack create --image ghcr.io/you/app:v1 -o app
smolvm pack push --file app.smolmachine ghcr.io/you/app:v2
```

smolvm prints a warning on every extraction of an affected pack, naming which of
the two failures the current run will hit.

[#1095]: https://github.com/smol-machines/smolvm/issues/1095
[#456]: https://github.com/smol-machines/smolvm/issues/456
