# Low-latency video streaming

SmolVM can encode its browser display as H.264 instead of sending raw
framebuffer pixels. It uses a host hardware encoder when available and a
bounded software encoder on CPU-only Linux hosts. Keyboard and pointer input
continue over RFB, and native VNC clients are unchanged.

The path is on by default whenever an `ffmpeg` binary is on the host's PATH, and
falls back to Raw RFB if the selected encoder is missing; set `SMOLVM_VIDEO=off` to
disable it. It requires an FFmpeg build exposing the selected encoder:

```console
SMOLVM_DISPLAY=1920x1080 \
SMOLVM_VNC=5900 \
SMOLVM_VIDEO=auto \
smolvm machine start --name desktop
```

Open `http://127.0.0.1:5900/`. The embedded client uses WebCodecs when it is
available and falls back to Raw RFB if the browser, FFmpeg, or selected encoder
is unavailable.

`auto` selects VideoToolbox on macOS, NVENC on an NVIDIA Linux host, VAAPI on
an Intel/AMD Linux host, or bounded software x264 when a Linux host exposes no
hardware video device. An implementation can be selected explicitly with
`SMOLVM_VIDEO=videotoolbox`, `nvenc`, `vaapi`, or `x264`. Explicit hardware
modes never fall back to software. Every implementation uses the same H.264
browser protocol.

Optional tuning:

- `SMOLVM_VIDEO_FPS` controls the maximum capture rate (default `60`).
- `SMOLVM_VIDEO_BITRATE_MBIT` controls the target bitrate (default `20`).
- `SMOLVM_VIDEO_THREADS` bounds software x264 worker threads (default `2`,
  maximum `32`). It is ignored by hardware encoders.
- `SMOLVM_VAAPI_DEVICE` selects the VAAPI render node (default
  `/dev/dri/renderD128`).
- `SMOLVM_FFMPEG` selects the FFmpeg executable (default `ffmpeg` from `PATH`).

The encoder runs as a per-VM, unprivileged helper prepared before the VMM's
Landlock/seccomp boundary. SmolVM does not link or bundle FFmpeg or codec
libraries, and enabling video does not broaden the VMM syscall allowlist.
Software mode requires an FFmpeg build with `libx264` enabled.
