# Cross-OS `.smolmachine` validation (macOS → Linux arm64)

**Status:** verified 2026-06-02 on GCP `c4a-highmem-96-metal` (Google Axion, arm64 bare metal).

## What this proves (and what it doesn't)

A `.smolmachine` packed on **macOS arm64** (Apple Silicon, libkrun-on-Darwin) was
transferred to a **remote Linux arm64 bare-metal host**, rehydrated, **booted
under Linux KVM with a from-source libkrun/libkrunfw**, and executed the packed
image.

- ✅ **Cross-OS, same-arch** (`darwin/arm64` pack → `linux/arm64` run): proven.
  The guest is `linux/arm64` either way; only the *host* runtime changes
  (libkrun-on-Darwin/HVF vs libkrun-on-Linux/KVM). The seam that matters — an
  artifact assembled against a macOS filesystem, reconstructed against ext4 on
  bare-metal KVM — holds with no macOS-ism leaking into the packed layers.
- ❌ **Cross-architecture** (one artifact on both arm64 and x86_64) is **false by
  design.** A `.smolmachine` packs native OCI layers + agent rootfs for ONE CPU
  arch. The arch-aware scheduler ([smolfleet]) enforces this: an arm64 artifact
  is *refused* on an x86 node, not run on it.

So "cross-platform compatibility" = **OS-portable, arch-specific**.

## Result

```
$ # exec inside the macOS-packed image, now on Linux arm64 bare metal
Python 3.12.13
aarch64
PRETTY_NAME="Alpine Linux v3.23"
exit: 0
```

The artifact was `python:3.12-alpine` packed on a Mac — a plain rootfs has no
`python3`, so finding 3.12.13 proves the packed image state was rehydrated.

## Why bare metal

Linux libkrun needs `/dev/kvm`. Regular cloud VMs (GCP T2A/Tau, AWS Nitro) do
**not** expose nested virtualization, so smolvm workers must be **bare metal**:
GCP `c4a-*-metal` (Axion arm64) or AWS Graviton `*.metal`. On bare metal `/dev/kvm`
is native — there's no nesting to be unsupported. Confirmed on the host:
`uname -m` = `aarch64`, 96 cores, `/dev/kvm` present.

## Reproduction

Provision an arm64 Linux bare-metal host (see `smolfleet/deploy/terraform/gcp`
`arm_worker_*` or `.../aws`). Then, on the host:

1. **Build the arm64 libkrun/libkrunfw libs** from the patched submodules:
   `scripts/build-libkrun-linux.sh` → `lib/linux-aarch64/`. (Already committed;
   rebuild only on a libkrun/libkrunfw bump.)
2. **Build the smolvm host binary:** `cargo build --release --bin smolvm`.
   (Needs `AGENTS.md` present — it's `include_str!`'d by `main.rs`.)
3. **Build + install the agent-rootfs:**
   `scripts/build-agent-rootfs.sh --arch aarch64` → copy `target/agent-rootfs`
   to the smolvm data dir (`<HOME>/.local/share/smolvm/agent-rootfs`). The node
   needs its OWN agent-rootfs; a `.smolmachine`'s image layers run *on top of* it.
4. **Run the runtime:**
   `SMOLVM_LIB_DIR=<repo>/lib/linux-aarch64 smolvm serve start --listen 0.0.0.0:8080`
   (KVM access needs root or `kvm` group membership).
5. **Rehydrate a Mac-built artifact:** copy the `.smolmachine` over, then
   `POST /api/v1/machines {"name":..., "from":"/path/to.smolmachine", ...}` →
   `POST .../start` → `POST .../exec`.

## Gotchas hit (and fixed in the tooling)

Discovered building on the real host; folded back into the scripts where applicable:

- **`make -C libkrunfw` fails `No rule to make target 'w'`** — `-C` auto-enables
  `-w` (print-directory), which lands in `MAKEFLAGS` as a bare `w` and the
  kernel's `$(MAKE) $(MAKEFLAGS)` recipe treats it as a target. Fix: build from
  *inside* the dir, not with `-C`. (Fixed in `build-libkrun-linux.sh`.)
- **libkrunfw needs `python3-pyelftools`** (for `bin2cbundle.py`).
- **libkrun GPU feature needs** `libepoxy-dev` + `libvirglrenderer-dev` +
  `libdrm-dev` + `libgbm-dev` (build) and `libvirglrenderer1` + `libepoxy0`
  (runtime).
- **`error: linker 'cc' not found`** — install `build-essential` (cloud-init may
  still hold the apt lock on first boot; wait for `lock-frontend`).
- **smolvm needs the agent-rootfs installed** even for `from`/`.smolmachine`
  machines (step 3) — the artifact supplies image layers, not the guest init.

## Versions built

- `libkrunfw.so.5.4.0` (linux/aarch64, kernel 6.12.87)
- `libkrun.so.1.17.3` (linux/aarch64, BLK+NET+GPU)
- `smolvm` 0.8.1 (linux/aarch64 host binary)

[smolfleet]: ../smolfleet
