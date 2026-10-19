# Browser display

A machine started with `--gpu` can expose a display. The host serves it on
one port: open it in a browser, or point a VNC client at it. Keyboard and
pointer input reach the guest.

```sh
smolvm machine create --name desktop --gpu --net --image archlinux:latest
SMOLVM_DISPLAY=1280x800 SMOLVM_VNC=5900 smolvm machine start --name desktop
```

Open `http://127.0.0.1:5900/`.

`SMOLVM_DISPLAY=WIDTHxHEIGHT` adds a virtio-gpu scanout, so the guest gets a
KMS connector on `/dev/dri/card0`. It has no effect without `--gpu`. There is
no `/dev/fb0`; the guest needs something that drives KMS, such as a Wayland
compositor or `modetest`.

`SMOLVM_VNC=[host:]port` serves the display from the host; the guest runs no
VNC server. A bare port binds `127.0.0.1`; a bare host uses port 5900. The
port answers native RFB, serves the browser client at `/`, and carries RFB over
a WebSocket at `/websockify`. Both variables are read when the machine starts,
from the environment of the process that starts it.

The libkrun must export `krun_add_display` and `krun_set_display_backend`.
Without `krun_add_input_device` the session is view-only.

The server has no authentication: anything that can reach the port can view
and control the desktop. Keep it on loopback.

With `ffmpeg` on the host, the browser client receives H.264 instead of raw
pixels; see [hardware-video.md](hardware-video.md). For a full desktop, see
[examples/desktop](../examples/desktop/README.md).
