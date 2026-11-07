# GUI forwarding

Two machine flags put guest GUI apps on the host desktop. Both ride vsock, like
`--cuda`, so forwarding itself needs no networking.

## Wayland: `--waypipe`

`--waypipe` bridges a guest [waypipe](https://gitlab.freedesktop.org/mstoeckl/waypipe)
vsock port to a host Unix socket in the machine's data directory. The guest
agent runs one `waypipe server` daemon inside the workload container and
exports `WAYLAND_DISPLAY`, and on a Linux host smolvm starts the matching
`waypipe client` next to your compositor. Run the app; both ends are wired up.

```bash
smolvm machine create --name gui --net --waypipe --image ubuntu:26.04
smolvm machine start --name gui
smolvm machine exec --name gui -- weston-terminal
```

The host client starts when `$WAYLAND_DISPLAY` is set and `waypipe` is on the
host `PATH`, and it exits with the machine. Without either, smolvm skips it and
you can run one yourself:

```bash
waypipe -s "$(smolvm machine data-dir --name gui)/waypipe.sock" client &
```

The optional value picks the binary the guest daemon runs:

- `--waypipe` or `--waypipe=host` (default): share the host binary, so both ends
  are the same build and the image needs no waypipe. The host glibc must suit
  the guest image.
- `--waypipe=container`: use the image's own `waypipe`. The daemon starts on the
  first command after it is installed, with no restart.
- `--waypipe=/path/to/waypipe`: share that host binary.

waypipe must support `--vsock` (0.9 or later) on the host and, for `container`,
in the guest. `--waypipe` needs `--image`: the daemon runs in the workload
container, and a bare machine has none, so it is refused up front. When the
daemon cannot start, `machine exec` prints the reason on stderr and an
interactive session prints it first.

## X11: `--x11`

`--x11` resolves the host `$DISPLAY` at launch and bridges a guest vsock port
(guest to host CID 2, port 7002) to that X server's Unix socket. The agent
exports `DISPLAY=:10` in the guest.

```bash
smolvm machine create --name xgui --net --x11 --image ubuntu:26.04
smolvm machine start --name xgui        # with $DISPLAY set
xhost +local:                           # allow the bridged connections
smolvm machine exec --name xgui -- sh -c 'apt-get install -y x11-apps && xeyes'
```

The bridge is a byte pipe and cannot pass file descriptors, so MIT-SHM and DRI3
fall back to wire transport: correct, but slower. Prefer `--waypipe` for
per-window integration and GPU buffers.
