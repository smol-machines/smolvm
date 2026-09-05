#!/bin/bash
# Omarchy on an aarch64 machine (Apple-silicon macOS hosts, arm Linux hosts),
# adapted from omarchy.sh with everything the arm port needs. Idempotent:
# rerunning skips completed steps and just (re)starts the session.
#
# Create and start the machine from the host:
#   smolvm machine create -n omarchy -I menci/archlinuxarm:latest \
#     --cpus 6 --mem 8192 --storage 20 --net --gpu -p 5901:5901 \
#     -v "$PWD:/in"
#   SMOLVM_DISPLAY=1024x768 SMOLVM_VNC=127.0.0.1:5900 SMOLVM_VIDEO=0 \
#     smolvm machine start --name omarchy
#   (SMOLVM_VIDEO=0 keeps the browser client on Raw RFB. On a local/loopback
#   link H.264 has no bandwidth to save and only adds encode+decode latency;
#   leave video enabled for cloud/remote viewers, where it is essential.)
#   smolvm machine exec --name omarchy -- bash /in/omarchy-aarch64.sh
#
# Two ways to view it, both interactive:
#   - Fast path (recommended): wayvnc runs inside the guest on port 5901 with
#     native damage tracking and a client-side cursor. Point a VNC client (or
#     websockify+noVNC for a browser) at 127.0.0.1:5901.
#   - Console path: the host-side scanout VNC on SMOLVM_VNC (5900). With the
#     GPU stack below, the compositor's frames reach it through the blob
#     scanout, so it shows the accelerated desktop directly.
#
# GPU acceleration on macOS hosts: the bundled virglrenderer is Venus (Vulkan)
# only, so the guest gets GL through Zink. Stock Mesa cannot do that here (its
# Venus dies on the host's 16 KiB pages, and Zink from 26.2 requires an
# extension the renderer cannot offer), so the recipe installs a matched Mesa
# 26.0.8 build. It looks for SMOLVM_MESA_ZINK_TARBALL (a path or URL), then the
# tarball beside this script in /in, then SMOLVM_MESA_ZINK_URL.
# build-mesa-zink-aarch64.sh reproduces the tarball. Without it the desktop
# still works, on llvmpipe.
#
# Deltas from the x86 recipe, each learned the hard way:
#   - Base is Arch Linux ARM (no snapshot archive; pacman keyring needs init).
#   - ~30 omarchy packages are x86-only. Everything session-critical
#     (hyprland, quickshell, foot) exists on aarch64; chromium too.
#   - Omarchy's icon fonts are x86-only: install the official nerd fonts.
#   - Omarchy launches apps via uwsm-app (needs a systemd user session) and
#     terminals via xdg-terminal-exec (no arm package): shim both, or every
#     keybind silently does nothing.
#   - `hyprctl keyword` is REJECTED by the Lua config parser: runtime options
#     land in the user override ~/.config/hypr/looknfeel.lua via hl.config().
#   - Without the GPU stack (llvmpipe): blur/shadows/animations off is the
#     difference between a slideshow and a usable session. With it they stay on.
set -o pipefail
export LANG=C
# The GPU driver injection puts /opt/smolvm-vulkan on LD_LIBRARY_PATH for the
# session; its bundled libexpat/libzstd predate the distro's and shadow them,
# which breaks pacman's hooks, python and tar --zstd in confusing ways.
unset LD_LIBRARY_PATH
log() { echo "[omarchy-aarch64] $*"; }

# ---------------------------------------------------------------- packages --
# A run interrupted mid-transaction (machine restarted) leaves pacman's lock
# behind and every later install fails to lock the database.
[ -f /var/lib/pacman/db.lck ] && ! pgrep -x pacman >/dev/null && rm -f /var/lib/pacman/db.lck
if [ ! -d /usr/share/omarchy ]; then
  pacman-key --init >/dev/null 2>&1
  pacman-key --populate archlinuxarm >/dev/null 2>&1
  sed -i 's/^#ParallelDownloads.*/ParallelDownloads = 8/' /etc/pacman.conf
  ok=0
  for _ in 1 2 3; do
    pacman -Syu --noconfirm --needed --disable-download-timeout git sudo \
      >/tmp/pac0.log 2>&1 && { ok=1; break; }
    sleep 15
  done
  [ "$ok" = 1 ] || { tail -5 /tmp/pac0.log; exit 1; }

  git clone -q --depth 1 https://github.com/basecamp/omarchy /tmp/om || exit 1
  mapfile -t PKGS < <(grep -vE "^\s*#|^\s*$" /tmp/om/install/omarchy-base.packages)
  OK=()
  for p in "${PKGS[@]}"; do pacman -Si "$p" >/dev/null 2>&1 && OK+=("$p"); done
  log "installing ${#OK[@]}/${#PKGS[@]} base packages available on aarch64"
  ok=0
  for _ in 1 2 3; do
    # Mirrors rotate package versions under a stale database, so refresh
    # before every attempt or the install fails on 404s.
    pacman -Syy --noconfirm >/dev/null 2>&1
    pacman -S --noconfirm --needed --disable-download-timeout "${OK[@]}" \
      foot grim wayvnc waybar swaybg ttf-nerd-fonts-symbols ttf-jetbrains-mono-nerd \
      noto-fonts waybar mako swayosd hypridle hyprlock alacritty wofi \
      >/tmp/pac.log 2>&1 && { ok=1; break; }
    sleep 20
  done
  # Omarchy's launcher (walker) has no aarch64 package; wofi stands in.
  command -v walker >/dev/null 2>&1 || printf '#!/bin/sh\nexec wofi --show drun "$@"\n' > /usr/local/bin/walker
  chmod +x /usr/local/bin/walker
  # Omarchy starts its shell through systemd-cat; there is no journal here,
  # so a shim drops the logging options and runs the command directly.
  printf '#!/bin/sh\nwhile [ $# -gt 0 ]; do case $1 in --) shift; break;; -*) shift; [ $# -gt 0 ] && case $1 in -*) ;; *) shift;; esac;; *) break;; esac; done\nexec "$@"\n' > /usr/local/bin/systemd-cat
  chmod +x /usr/local/bin/systemd-cat
  [ "$ok" = 1 ] || { tail -10 /tmp/pac.log; exit 1; }

  # seatd owns the seat group; if its package did not land the groups are
  # missing and useradd fails, taking the whole session with it.
  for g in wheel video input seat render; do getent group "$g" >/dev/null || groupadd "$g"; done
  id omar >/dev/null 2>&1 || useradd -m -G wheel,video,input,seat,render omar \
    || { log "useradd omar failed"; exit 1; }
  printf '%%wheel ALL=(ALL) NOPASSWD: ALL\n' > /etc/sudoers.d/wheel
  chmod 440 /etc/sudoers.d/wheel

  # Omarchy's layout, as its installer creates it: system copy (hyprland.lua
  # dofile()s the SYSTEM bootstrap path), user copy, config tree, and the
  # STATE theme link that foot.ini includes.
  cp -r /tmp/om /usr/share/omarchy
  install -d -o omar -g omar /home/omar/.local/share
  cp -r /tmp/om /home/omar/.local/share/omarchy
  install -d -o omar -g omar /home/omar/.config
  cp -r /tmp/om/config/* /home/omar/.config/ 2>/dev/null
  THEME=/home/omar/.local/share/omarchy/themes/tokyo-night
  install -d -o omar -g omar /home/omar/.local/state/omarchy/current
  ln -sfn "$THEME" /home/omar/.local/state/omarchy/current/theme
  BG=$(ls "$THEME"/backgrounds/* 2>/dev/null | head -1)
  [ -n "$BG" ] && ln -sfn "$BG" /home/omar/.local/state/omarchy/current/background
  install -d /home/omar/.config/omarchy
  ln -sfn "$THEME" /home/omar/.config/omarchy/current

  # Options this environment needs, in the user-override file omarchy loads
  # after its defaults (the Lua parser rejects `hyprctl keyword`).
  cat >> /home/omar/.config/hypr/looknfeel.lua <<'LUA'

-- Software rendering: effects multiply the pixels redrawn per frame. The
-- pointer goes on the cursor plane, which the host hands to viewers directly.
hl.config({
  cursor = { no_hardware_cursors = false },
  animations = { enabled = false },
  decoration = {
    blur = { enabled = false },
    shadow = { enabled = false },
  },
})
LUA
  chown -R omar:omar /home/omar/.config /home/omar/.local
  # A blinking cursor gives the compositor a periodic present, so the last
  # character of a paused line reaches the display within a blink instead of
  # waiting for the next keystroke.
  install -d -o omar -g omar /home/omar/.config/foot
  printf "[cursor]\nblink=yes\nblink-rate=200\n" >> /home/omar/.config/foot/foot.ini
  chown -R omar:omar /home/omar/.config/foot
  # The virtual krun-display reports a tiny physical size, so Hyprland
  # auto-picks scale 2.0; the absolute VNC pointer then lands every click at
  # half position and nothing focuses. Pin scale 1 so pointer coordinates
  # match the 1280x800 framebuffer 1:1 (GDK integer scale follows).
  sed -i "s/local omarchy_monitor_scale = .auto./local omarchy_monitor_scale = 1/" /home/omar/.config/hypr/monitors.lua
  sed -i "s/local omarchy_gdk_scale = 2/local omarchy_gdk_scale = 1/" /home/omar/.config/hypr/monitors.lua

  # Omarchy's keybinds launch apps through uwsm-app (systemd user session)
  # and terminals through xdg-terminal-exec (not packaged on aarch64).
  cat > /usr/local/bin/uwsm-app <<'EOF'
#!/bin/bash
# No systemd user session in this machine: launch apps directly.
[ "$1" = "--" ] && shift
exec "$@"
EOF
  cat > /usr/local/bin/xdg-terminal-exec <<'EOF'
#!/bin/bash
# Not packaged for aarch64: map the spec launcher onto foot.
dir=""
case "$1" in --dir=*) dir="${1#--dir=}"; shift;; esac
[ "$1" = "--" ] && shift
if [ -n "$dir" ] && [ -d "$dir" ]; then exec foot -D "$dir" "$@"; fi
exec foot "$@"
EOF
  # quickshell's bar shells out to this on every tick; it is x86-only, and
  # without the shim the bar dies at startup.
  printf '#!/bin/sh\nexit 0\n' > /usr/local/bin/omarchy-audio-output-sink
  chmod +x /usr/local/bin/uwsm-app /usr/local/bin/xdg-terminal-exec \
    /usr/local/bin/omarchy-audio-output-sink

  # Chromium: Wayland, software rendering, and software WebGL. The Arch ARM
  # chromium is a bare ELF with no flags-file launcher, so a PATH wrapper is
  # the only way to apply flags to every launch. --enable-unsafe-swiftshader
  # matters: modern Chromium blocks software WebGL in windowed mode without
  # it (headless allows it), so CAD/3D sites silently render nothing.
  cat > /usr/local/bin/chromium <<'CHROMIUMWRAP'
#!/bin/bash
# Chromium treats any unclean exit (e.g. the machine being stopped) as a crash
# and shows a "Restore pages?" bubble on the next launch, top-right, over the
# toolbar. --disable-session-crashed-bubble no longer suppresses it in current
# builds, so mark the profile cleanly exited before every launch instead.
P="$HOME/.config/chromium/Default/Preferences"
[ -f "$P" ] && sed -i 's/"exit_type":"[^"]*"/"exit_type":"Normal"/;s/"exited_cleanly":false/"exited_cleanly":true/' "$P" 2>/dev/null
exec /usr/bin/chromium --ozone-platform=wayland --disable-gpu --enable-unsafe-swiftshader --no-first-run --disable-session-crashed-bubble --disable-infobars "$@"
CHROMIUMWRAP
  chmod +x /usr/local/bin/chromium
  log "setup complete"
fi

# --------------------------------------------------------------------- gpu --
MESA_ZINK_TARBALL_NAME=mesa-26.0.8-zink-venus16k-aarch64.tar.zst
MESA_ZINK_SHA256=09d95de59c135f78c99cc56c2f096e628a04bfec3bc0e7d73946530617dbb823
if [ ! -f /usr/lib/libgallium-26.0.8.so ]; then
  src="${SMOLVM_MESA_ZINK_TARBALL:-}"
  [ -z "$src" ] && [ -f "/in/$MESA_ZINK_TARBALL_NAME" ] && src="/in/$MESA_ZINK_TARBALL_NAME"
  [ -z "$src" ] && [ -n "${SMOLVM_MESA_ZINK_URL:-}" ] && src="$SMOLVM_MESA_ZINK_URL"
  if [ -n "$src" ]; then
    case "$src" in
      http://*|https://*) curl -fsSL "$src" -o "/tmp/$MESA_ZINK_TARBALL_NAME" && src="/tmp/$MESA_ZINK_TARBALL_NAME" ;;
    esac
    if echo "$MESA_ZINK_SHA256  $src" | sha256sum -c --status; then
      tar --zstd -xf "$src" -C / || { log "extracting $src failed"; exit 1; }
      ldconfig
      # Effects are cheap on the GPU; keep the cursor in the frame, the host
      # scanout has no cursor plane.
      cat >> /home/omar/.config/hypr/looknfeel.lua <<'LUA'
hl.config({
  animations = { enabled = true },
  decoration = { blur = { enabled = true }, shadow = { enabled = true } },
})
LUA
      chown omar:omar /home/omar/.config/hypr/looknfeel.lua
      log "installed the Mesa Zink stack: GL on the GPU"
    else
      log "WARNING: $src does not match the pinned sha256; staying on llvmpipe"
    fi
  else
    log "no Mesa Zink tarball (SMOLVM_MESA_ZINK_TARBALL / /in / SMOLVM_MESA_ZINK_URL): llvmpipe"
  fi
fi
# Zink over a Venus-only virtio-gpu: the loader fallback, and the GLES version
# Mesa withholds because the host has no transform feedback (compositors do
# not use it).
GPU_ENV=""
[ -f /usr/lib/libgallium-26.0.8.so ] && GPU_ENV="MESA_VIRTIO_ZINK=1 MESA_LOADER_DRIVER_OVERRIDE=zink MESA_GLES_VERSION_OVERRIDE=3.2 MESA_GLSL_VERSION_OVERRIDE=320"

# ----------------------------------------------------------------- session --
pkill -f Hyprland 2>/dev/null; pkill -f quickshell 2>/dev/null
# The Omarchy notification overlay is a full-screen wlr-layer surface at overlay
# level (above every window). Its input mask (the toast column) can grab pointer
# events across the top of the screen even with no visible toast, which silently
# makes window chrome -- a browser's tabs, back button and address bar --
# unclickable. Make the overlay click-through so toasts still display but never
# intercept clicks. Runs as root here: the system copy under /usr/share (which
# Omarchy's launcher actually runs) is root-owned; the user copy is patched too.
for _nf in /usr/share/omarchy/shell/plugins/notifications/Service.qml \
           /home/omar/.local/share/omarchy/shell/plugins/notifications/Service.qml; do
  [ -f "$_nf" ] && sed -i 's|mask: Region { item: popupColumn }|mask: Region {} // cloud-desktop: never grab pointer, keep window chrome clickable|' "$_nf"
done
pkill -x wayvnc 2>/dev/null; pkill -x seatd 2>/dev/null; sleep 1

RT=/run/user/1000; mkdir -p "$RT"; chown omar:omar "$RT"; chmod 700 "$RT"
chmod 666 /dev/dri/* 2>/dev/null
dbus-uuidgen --ensure 2>/dev/null || true

# Chromium passes fonts and tiles between processes through POSIX shared
# memory; at the 64M container-default /dev/shm its font service hits ENOSPC
# and CHECK-crashes the renderer whenever a video plays.
mount -o remount,size=2G /dev/shm 2>/dev/null || true

# Container-guest input fixes: /dev is not devtmpfs, and libinput needs the
# udev db entries systemd-udevd would normally write.
mkdir -p /dev/input /run/udev/data
for e in /sys/class/input/event*; do
  [ -e "$e" ] || continue
  n=$(basename "$e")
  maj=$(cut -d: -f1 "$e/dev"); min=$(cut -d: -f2 "$e/dev")
  [ -e "/dev/input/$n" ] || mknod "/dev/input/$n" c "$maj" "$min"
  case "$(cat "$e/device/name" 2>/dev/null)" in
    *keyboard*) type=ID_INPUT_KEYBOARD ;;
    *)          type=ID_INPUT_MOUSE ;;
  esac
  printf 'E:ID_INPUT=1\nE:%s=1\nG:seat\nQ:seat\n' "$type" \
    > "/run/udev/data/c$(cat "$e/dev")"
done

# D-Bus before the compositor: apps launched from Hyprland keybinds inherit
# HYPRLAND's environment, so the bus must exist (at the standard path) before
# Hyprland starts, or every client sees a broken/missing address.
mkdir -p /run/dbus
[ -S /run/dbus/system_bus_socket ] || dbus-daemon --system --fork 2>/dev/null || true
sudo -u omar env XDG_RUNTIME_DIR=$RT dbus-daemon --session \
  --address=unix:path=$RT/bus --fork 2>/dev/null || true

SEATD_VTBOUND=0 seatd -g wheel >/tmp/seatd.log 2>&1 &
sleep 2

sudo -u omar env HOME=/home/omar XDG_RUNTIME_DIR=$RT XDG_SESSION_TYPE=wayland \
  LIBSEAT_BACKEND=seatd DBUS_SESSION_BUS_ADDRESS=unix:path=$RT/bus OMARCHY_PATH=/usr/share/omarchy PATH=/usr/share/omarchy/bin:/usr/local/bin:/usr/bin:/usr/sbin \
  $GPU_ENV \
  bash -s <<'INNER'
set -o pipefail
setsid Hyprland >/tmp/hypr.log 2>&1 &
for i in $(seq 1 40); do ls "$XDG_RUNTIME_DIR"/wayland-* >/dev/null 2>&1 && break; sleep 1; done
S=$(ls "$XDG_RUNTIME_DIR"/wayland-* 2>/dev/null | grep -v '\.lock$' | head -1)
[ -z "$S" ] && { echo "compositor failed"; tail -20 /tmp/hypr.log; exit 1; }
export WAYLAND_DISPLAY=$(basename "$S")
export HYPRLAND_INSTANCE_SIGNATURE=$(ls -t "$XDG_RUNTIME_DIR"/hypr 2>/dev/null | head -1)
# llvmpipe warmup: IPC can take a while to answer on software rendering.
for i in $(seq 1 20); do timeout 10 hyprctl -j monitors >/dev/null 2>&1 && break; sleep 5; done
echo "omarchy hyprland up on $WAYLAND_DISPLAY"

export OMARCHY_PATH=$HOME/.local/share/omarchy
# Omarchy's autostart (omarchy-launch-shell, from hypr/autostart.lua) already
# starts the quickshell shell when Hyprland comes up. Starting a second one
# here spawns a DUPLICATE whose full-screen omarchy-notifications overlay -- a
# wlr-layer surface at overlay level, above every window -- grabs pointer
# events across the top strip of the screen, which silently makes window chrome
# (a browser's tabs, back button and address bar) unclickable. So wait briefly
# for the autostart instance and only start our own if none came up.
for _ in $(seq 1 10); do pgrep -x quickshell >/dev/null 2>&1 && break; sleep 1; done
if ! pgrep -x quickshell >/dev/null 2>&1; then
  (setsid env DBUS_SESSION_BUS_ADDRESS=$DBUS_SESSION_BUS_ADDRESS \
    QS_DISABLE_FILE_WATCHER=1 QS_NO_RELOAD_POPUP=1 \
    quickshell -n -p "$OMARCHY_PATH/shell" >/tmp/qs.log 2>&1 &)
fi

# In-guest VNC: wayvnc attaches to Hyprland via screencopy with native damage
# tracking, tight encodings, and a client-side cursor — far cheaper than
# streaming the raw scanout.
(setsid env WAYLAND_DISPLAY=$WAYLAND_DISPLAY XDG_RUNTIME_DIR=$XDG_RUNTIME_DIR \
  wayvnc 0.0.0.0 5901 >/tmp/wayvnc.log 2>&1 &)
BGIMG=$(readlink -f "$HOME/.local/state/omarchy/current/background" 2>/dev/null)
[ -f "$BGIMG" ] || BGIMG=$(ls "$HOME/.config/omarchy/current/backgrounds/"* 2>/dev/null | head -1)
[ -f "$BGIMG" ] && (setsid swaybg -i "$BGIMG" -m fill >/tmp/swaybg.log 2>&1 &)

# The Omarchy quickshell bar (and its notifications / OSD) render blank on this
# GPU stack: Qt Quick surfaces are not composited here, though shm clients
# (foot, swaybg, waybar) are. So hide the quickshell bar via its bar-off toggle
# and use Waybar -- GTK/shm -- as the top bar: workspaces, focused-window
# title, clock, and CPU/RAM load. Config is only written when absent so user
# edits survive a rerun.
mkdir -p "$HOME/.config/waybar" "$HOME/.local/state/omarchy/toggles"
touch "$HOME/.local/state/omarchy/toggles/bar-off"
if [ ! -f "$HOME/.config/waybar/config.jsonc" ]; then
  cat > "$HOME/.config/waybar/config.jsonc" <<'WBCFG'
{
  // Waybar replaces the Omarchy quickshell bar here: on this GPU stack Qt Quick
  // surfaces (quickshell's bar, notifications, OSD) are not composited, while
  // GTK/shm clients like Waybar render fine.
  "layer": "top", "position": "top", "height": 28, "spacing": 4,
  "modules-left": ["hyprland/workspaces", "hyprland/window"],
  "modules-center": ["clock"],
  "modules-right": ["cpu", "memory", "pulseaudio", "network", "tray"],
  "hyprland/workspaces": { "format": "{id}", "on-click": "activate" },
  "hyprland/window": { "max-length": 60 },
  "clock": { "format": "{:%a %d %b  %H:%M}", "tooltip-format": "<tt>{calendar}</tt>" },
  "cpu": { "format": "CPU {usage}%" },
  "memory": { "format": "RAM {}%" },
  "network": { "format-wifi": "{essid}", "format-ethernet": "net", "format-disconnected": "" },
  "pulseaudio": { "format": "VOL {volume}%", "format-muted": "muted" },
  "tray": { "spacing": 8 }
}
WBCFG
fi
if [ ! -f "$HOME/.config/waybar/style.css" ]; then
  cat > "$HOME/.config/waybar/style.css" <<'WBCSS'
* { font-family: "JetBrainsMono Nerd Font", monospace; font-size: 13px; min-height: 0; }
window#waybar { background: #1a1b26; color: #a9b1d6; }
#workspaces button { color: #a9b1d6; padding: 0 8px; background: transparent; }
#workspaces button.active { background: #7aa2f7; color: #1a1b26; }
#workspaces button:hover { background: #292e42; }
#window { color: #a9b1d6; }
#clock, #cpu, #memory, #network, #pulseaudio, #tray { padding: 0 10px; }
#clock { font-weight: bold; }
WBCSS
fi
pkill -x waybar 2>/dev/null
(setsid env WAYLAND_DISPLAY=$WAYLAND_DISPLAY XDG_RUNTIME_DIR=$XDG_RUNTIME_DIR HYPRLAND_INSTANCE_SIGNATURE=$HYPRLAND_INSTANCE_SIGNATURE waybar >/tmp/waybar.log 2>&1 &)


sleep 8
timeout 10 hyprctl monitors | head -4
grim /tmp/a.png; sleep 3; grim /tmp/b.png
[ "$(sha256sum </tmp/a.png)" != "$(sha256sum </tmp/b.png)" ] \
  && echo "LIVE: frames differ" || echo "frames static"
echo "SESSION_UP — connect a VNC client to host port 5901 (wayvnc)"
INNER
