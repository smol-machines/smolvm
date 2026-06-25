# Native display helper

Last verified: 2026-06-25

This fork adds an opt-in native graphical console to SmolVM 1.2.4 without
changing the lifecycle of machines started by the stock CLI.

```text
smolvm machine start --name NAME --display
smolvm machine display --name NAME --json
```

Display must be selected before the VMM enters `krun_start_enter`; it cannot be
attached to an already-running libkrun context. A machine already running
without display must be stopped before it is restarted with `--display`.

## Persistent Debian/Weston profile

The repository includes a restart-safe graphical fixture at
`examples/weston-desktop/weston.smolfile`:

```bash
smolvm machine create --name debian-gui \
  -s examples/weston-desktop/weston.smolfile
smolvm machine start --name debian-gui --display
```

The first start installs Weston, Xwayland, DBus, fonts, icons, and udev into the
machine's persistent OCI overlay. The stored entrypoint then launches Weston as
the machine workload. Later stop/start cycles do not require package
installation or a manual compositor command:

```bash
smolvm machine stop --name debian-gui
smolvm machine start --name debian-gui --display
```

`--display` remains a per-launch requirement because the framebuffer and input
devices must be configured before libkrun starts. The Smolfile persists the
guest workload; it does not make the host display bridge attachable at runtime.
Weston writes its persistent diagnostic log to `/var/log/weston.log`.

## Transport contract

- The VMM process owns the framebuffer and input bridge for exactly one VM
  launch.
- libkrun provides a bounded, damage-aware framebuffer callback and virtual
  keyboard plus absolute-pointer devices.
- `rustvncserver` exposes the framebuffer as password-protected RFB on an
  ephemeral `127.0.0.1` port.
- A per-launch eight-character credential is returned only over
  `<machine>/display-runtime/endpoint.sock`.
- The runtime directory is mode `0700`, the Unix socket is mode `0600`, and the
  server verifies that the connecting process has the same effective UID.
- `machine ls --json` publishes only `display_ready: true|false`; it never
  publishes the port or credential.
- Endpoint JSON is limited to 4096 bytes and accepts only the `vnc` protocol,
  `127.0.0.1`, a nonzero port, and a nonempty password. Debug and parse errors
  redact the password.

The frame callback has three reusable buffers and a two-frame worker queue. A
slow client drops and recycles stale frames instead of blocking the virtio-gpu
thread. Input readiness is level-triggered on macOS so a batched Linux input
event and its `SYN_REPORT` remain visible until both are consumed. Disconnecting
the RFB client releases all tracked keys and pointer buttons.

## Guest input and seat discovery

The input path spans the host VMM, minimal guest rootfs, and graphical OCI
workload:

1. libkrun exposes a virtual keyboard and absolute pointer alongside the KMS
   scanout.
2. The guest agent polls for their sysfs `event*` entries and creates the
   corresponding `/dev/input/event*` character devices before switching to the
   persistent root.
3. After `pivot_root`, the agent classifies the devices from their kernel name
   and EV_KEY/EV_REL/EV_ABS capabilities, then writes the minimal libinput udev
   records under `/run/udev/data/c<major>:<minor>`.
4. Graphical OCI workloads receive `/dev/input`, the seatd socket, and a
   read-only bind mount of `/run/udev`. They also receive
   `LIBSEAT_BACKEND=seatd` and `SEATD_SOCK=/run/seatd.sock`.

This synthetic runtime metadata replaces the `systemd-udevd input_id` step that
does not run in the minimal agent rootfs. It is created only for GPU-enabled
guests and is harmless when no input devices are present. A desktop image may
contain the `udev` userspace package for libudev consumers, but it does not need
to start a second udev daemon or inject records manually.

## Native build requirements

The helper requires both the host libkrun input feature and the guest kernel
driver:

```text
make -C libkrun BLK=1 NET=1 GPU=1 INPUT=1
CONFIG_VIRTIO_INPUT=y
```

The pinned macOS GPU build also requires the `virglrenderer` formula from the
maintained libkrun Homebrew tap:

```bash
brew tap libkrun/krun
brew trust --formula libkrun/krun/virglrenderer
brew install libkrun/krun/virglrenderer
```

The resulting library must report all four required features:

```text
net=1
block=1
gpu=1
input=1
```

`libkrunfw` still builds its Linux kernel in a Linux VM on macOS. Rebuild the
pinned firmware after enabling `CONFIG_VIRTIO_INPUT`, then bundle that
`libkrunfw.5.dylib` with the custom libkrun.

The bundled agent rootfs is a third required input. It must contain the current
Linux `smolvm-agent` binary, which creates the event nodes and udev metadata,
and the `seatd` package used by graphical workloads:

```bash
cargo make build-agent
cargo make agent-rootfs
```

For a direct development run, point the helper at the matching rootfs:

```bash
DYLD_LIBRARY_PATH=./lib \
SMOLVM_AGENT_ROOTFS=./target/agent-rootfs \
./target/release/smolvm machine start --name debian-gui --display
```

Packaged display helpers use `scripts/smolvm-display-wrapper.sh`, which selects
the `agent-rootfs` beside the helper through `SMOLVM_AGENT_ROOTFS`. Rebuild and
ship libkrun, libkrunfw, the host helper, and the agent rootfs as one validated
set. A new framebuffer helper paired with an older rootfs can display frames
while silently lacking keyboard/pointer discovery.

## Current source boundary

The fast-loop source checkout resolves `rustvncserver` from the sibling
`../rustvncserver` fork. That fork adds explicit-address and prebound-listener
entry points so the helper can bind loopback port zero without a
close-and-rebind race. Before distributing source, publish the reviewed fork or
vendor an exact revision and replace the sibling path dependency. Do not ship a
source package that depends on an undeclared adjacent checkout.

## Client and fullscreen boundary

The SmolVM helper owns the loopback RFB endpoint, framebuffer updates, and input
event injection. It does not own application layout, pane composition, window
fullscreen, or display reconnection UX.

Local Machines waits for `display_ready`, retrieves the credential-bearing
endpoint through `machine display --json`, and embeds the RFB surface beside
its shell and log panes. Its Display fullscreen control switches to an
app-local immersive layout: inventory, toolbar, and docked auxiliary panes are
hidden while the same RFB surface stays attached, and active Logs/Shell can be
shown in an overlay. Native macOS app fullscreen remains a separate standard
window operation. Neither mode changes the guest KMS mode, creates another
display session, or stops the VM. Stopping the VM closes the endpoint, after
which a client must wait for the next `--display` launch and connect to its new
per-launch credential.

## Machine JSON inventory

`machine list --json` and `machine status --json` share the same per-machine
object. Display clients can consume these non-secret lifecycle fields without
probing private runtime files:

- `display_ready`: true only for a running machine with a live endpoint.
- `forkable`: true only while the fork control socket reports a usable running
  or frozen base.
- `fork_base_state`: `"running"`, `"frozen"`, or null.
- `golden`: the persisted parent name for a clone, or null.
- `dependent_clones`: names of clones that currently depend on the machine.

These fork fields describe warm-fork inventory; they do not imply display
availability, and they never expose the display port or credential.

## Acceptance checks

1. `krun_has_feature` reports GPU and INPUT support.
2. A display-aware guest sees `/dev/dri/card0`, virtual input event devices,
   matching `/run/udev/data` records, and a live seatd socket.
3. A graphical OCI workload sees `/dev/input`, read-only `/run/udev`, and can
   initialize libinput without manual udev record injection.
4. `machine ls --json` reports `display_ready: true` only while the rendezvous
   server is live.
5. `machine display --name NAME --json` returns a loopback endpoint to the same
   user and does not start or repair a VM.
6. A client receives changing non-black frames and can inject one key and one
   pointer event.
7. The Debian/Weston fixture returns to its desktop after stop/start when the
   next start includes `--display`.
8. Immersive Display mode hides app chrome and docked panes while preserving
   the same RFB session; native app fullscreen remains independently usable.
9. Stopping the VM removes the endpoint and terminates the RFB listener.

The guest still needs a DRM/KMS graphical workload or compositor. Enabling the
host bridge alone does not turn a headless root filesystem into a desktop.
