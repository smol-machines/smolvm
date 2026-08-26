# A Linux desktop in a machine

Runs a real DRM Wayland compositor (Hyprland) inside a smolvm machine and
serves it over VNC from the **host**, so the guest needs no capture tool and no
compositor-specific screencopy protocol.

```sh
SMOLVM_DISPLAY=1280x800 SMOLVM_VNC=127.0.0.1:5900 \
  smolvm machine run --net --gpu --cpus 4 --mem 6144 \
    -v "$PWD:/in" --image archlinux:latest -- bash /in/run.sh
```

Then point any VNC client at `127.0.0.1:5900`.

## The two environment variables

`SMOLVM_DISPLAY=WIDTHxHEIGHT` adds a virtio-gpu scanout. Without it `--gpu`
gives the guest GPU *rendering* only: `/dev/dri/card0` is a render node with no
connector, and every DRM compositor refuses to start with "not a KMS device".

`SMOLVM_VNC=[host:]port` serves the resulting framebuffer over RFB. A bare port
binds loopback only. The session is interactive: smolvm attaches a virtio
keyboard and an absolute pointer, and client key/pointer events are injected
into the guest. This needs a libkrun built with the input feature; without it
the session degrades to view-only.

For the guest's compositor to *see* the devices, two container-guest gaps
must be bridged before it starts (both handled by `omarchy.sh`):

- `/dev` is not devtmpfs, so the evdev nodes the kernel registers never
  appear — `mknod` them from `/sys/class/input/event*/dev`.
- libinput only adopts devices classified in the udev database, and
  `systemd-udevd` cannot populate it without a full systemd runtime. libudev
  reads `/run/udev/data` directly, so write `c<major>:<minor>` entries by
  hand with `E:ID_INPUT=1` plus a type (`E:ID_INPUT_KEYBOARD=1` /
  `E:ID_INPUT_MOUSE=1`).

Both are opt-in. A connector changes guest topology, and existing GPU workloads
(CUDA remoting, headless Vulkan) neither need nor want one.

## The one thing the guest must do

Run `seatd` with **`SEATD_VTBOUND=0`**:

```sh
SEATD_VTBOUND=0 seatd -g wheel &
```

seatd defaults to a *VT-bound* seat, which needs `/dev/tty0`. A workload
container has no VT, so a VT-bound seat cannot open a session — and because
seatd itself starts fine either way, the failure surfaces much later and in the
client, as libseat's misleading "Failed to open a session". This costs an hour
if you have not seen it before.

## Verifying it actually renders

A listening socket proves a server and an RFB banner proves a handshake;
neither proves a frame was ever presented. `rfb_probe.py` speaks the protocol,
pulls two full framebuffer updates a few seconds apart, and reports whether the
pixels are non-uniform (something was drawn) and whether they changed (it is
live):

```sh
python3 rfb_probe.py 127.0.0.1 5900
```

## Omarchy

`omarchy.sh` runs the real thing: omarchy's package set (126 of its 148 base
packages resolve from the official Arch repos; the rest are AUR or
Omarchy-published and are packaging work, not a smolvm limitation), omarchy's
actual Hyprland Lua config, and its theme — verified live over VNC with a
two-captures-differ check.

```sh
SMOLVM_DISPLAY=1280x800 SMOLVM_VNC=127.0.0.1:5900 \
  smolvm machine run --net --gpu --cpus 4 --mem 6144 \
    -v "$PWD:/in" --image archlinux:latest -- bash /in/omarchy.sh
```

Four things the script handles that cost real debugging time:

- omarchy's `hyprland.lua` loads `/usr/share/omarchy/default/hypr/bootstrap.lua`
  — the **system** path. With the repo only under `~/.local/share`, the Lua
  config errors and Hyprland silently drops into emergency mode: desktop up,
  but no binds and no autostart.
- `foot.ini` (and other app configs) include the **state** theme link
  `~/.local/state/omarchy/current/theme/…`, which the installer normally
  creates — without it foot exits at startup.
- omarchy's shell (bar, notifications, wallpaper) is a single Quickshell app
  launched through systemd user units; a workload container has no systemd
  user session (and no `/etc/machine-id`, which D-Bus requires), so the script
  runs `dbus-uuidgen --ensure`, starts a session bus, and spawns
  `quickshell -p "$OMARCHY_PATH/shell"` directly. Under the Lua config,
  `hyprctl dispatch exec` parses its argument as Lua — spawn clients as plain
  processes.
- virtio-gpu has no explicit-sync or hardware-cursor support yet:
  `AQ_NO_ATOMIC=1` plus runtime `hyprctl keyword render:explicit_sync 0` and
  `cursor:no_hardware_cursors true`.
