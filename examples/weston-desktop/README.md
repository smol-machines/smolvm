# Persistent Debian/Weston desktop

This example creates a Debian graphical machine whose desktop command and
installed packages persist across normal `machine stop` / `machine start`
cycles. It uses smolvm's native display transport, virtual keyboard and
absolute pointer, and the guest agent's seatd/libinput plumbing.

## Create and start

From the repository root:

```bash
smolvm machine create --name debian-gui \
  -s examples/weston-desktop/weston.smolfile
smolvm machine start --name debian-gui --display
```

The first start installs Weston and Xwayland into the persistent image overlay.
Later starts skip package installation and launch the desktop immediately.

Read the loopback-only display endpoint with:

```bash
smolvm machine display --name debian-gui --json
```

Local Machines performs that endpoint exchange automatically when its Display
pane opens.

## Restart proof

```bash
smolvm machine stop --name debian-gui
smolvm machine start --name debian-gui --display
```

The `--display` flag is required on each start because it requests the host
framebuffer and keyboard/pointer bridge. No package installation, udev record
injection, or manual Weston command is required after creation.

## Diagnostics

If the compositor exits, inspect its log from the persistent machine:

```bash
smolvm machine exec --name debian-gui -- tail -n 200 /var/log/weston.log
```

The reference profile uses Pixman intentionally. smolvm's native scanout path
provides a 2D virtio-gpu display; 3D rendering can be enabled separately when a
guest image and host libkrun build both advertise a compatible virgl path.
