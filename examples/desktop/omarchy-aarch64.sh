#!/bin/bash
# Omarchy on an aarch64 machine (Apple-silicon macOS hosts, arm Linux hosts),
# adapted from omarchy.sh with everything the arm port needs. Idempotent:
# rerunning skips completed steps and just (re)starts the session.
#
# Create and start the machine from the host:
#   smolvm machine create -n omarchy -I menci/archlinuxarm:latest \
#     --cpus 6 --mem 8192 --storage 20 --net --gpu -p 5901:5901 \
#     -v "$PWD:/in"
#   SMOLVM_DISPLAY=1024x768 SMOLVM_VNC=127.0.0.1:5900 \
#     smolvm machine start --name omarchy
#   smolvm machine exec --name omarchy -- bash /in/omarchy-aarch64.sh
#
# Two ways to view it, both interactive:
#   - Fast path (recommended): wayvnc runs inside the guest on port 5901 with
#     native damage tracking and a client-side cursor. Point a VNC client (or
#     websockify+noVNC for a browser) at 127.0.0.1:5901.
#   - Console path: the host-side scanout VNC on SMOLVM_VNC (5900). On macOS
#     smolvm defaults KRUN_GPU_BACKEND=2d automatically — the bundled
#     virglrenderer there has no GL support, so classic 2D resources need
#     rutabaga's CPU component. Set the variable yourself to override.
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
#   - Software rendering (llvmpipe): blur/shadows/animations off is the
#     difference between a slideshow and a usable session.
set -o pipefail
export LANG=C
log() { echo "[omarchy-aarch64] $*"; }

# ---------------------------------------------------------------- packages --
if [ ! -d /usr/share/omarchy ]; then
  pacman-key --init >/dev/null 2>&1
  pacman-key --populate archlinuxarm >/dev/null 2>&1
  sed -i 's/^#ParallelDownloads.*/ParallelDownloads = 8/' /etc/pacman.conf
  for attempt in 1 2 3; do
    pacman -Syu --noconfirm --needed --disable-download-timeout git sudo \
      >/tmp/pac0.log 2>&1 && break
    sleep 15
  done || { tail -5 /tmp/pac0.log; exit 1; }

  git clone -q --depth 1 https://github.com/basecamp/omarchy /tmp/om || exit 1
  mapfile -t PKGS < <(grep -vE "^\s*#|^\s*$" /tmp/om/install/omarchy-base.packages)
  OK=()
  for p in "${PKGS[@]}"; do pacman -Si "$p" >/dev/null 2>&1 && OK+=("$p"); done
  log "installing ${#OK[@]}/${#PKGS[@]} base packages available on aarch64"
  for attempt in 1 2 3; do
    pacman -S --noconfirm --needed --disable-download-timeout "${OK[@]}" \
      foot grim wayvnc ttf-nerd-fonts-symbols ttf-jetbrains-mono-nerd \
      noto-fonts >/tmp/pac.log 2>&1 && break
    sleep 20
  done || { tail -10 /tmp/pac.log; exit 1; }

  id omar >/dev/null 2>&1 || useradd -m -G wheel,video,input,seat,render omar
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

-- Software rendering: effects multiply the pixels redrawn per frame, and
-- the host scanout path has no composited cursor plane.
hl.config({
  cursor = { no_hardware_cursors = true },
  animations = { enabled = false },
  decoration = {
    blur = { enabled = false },
    shadow = { enabled = false },
  },
})
LUA
  chown -R omar:omar /home/omar/.config /home/omar/.local

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
  chmod +x /usr/local/bin/uwsm-app /usr/local/bin/xdg-terminal-exec

  # Chromium: Wayland, software rendering, and software WebGL. The Arch ARM
  # chromium is a bare ELF with no flags-file launcher, so a PATH wrapper is
  # the only way to apply flags to every launch. --enable-unsafe-swiftshader
  # matters: modern Chromium blocks software WebGL in windowed mode without
  # it (headless allows it), so CAD/3D sites silently render nothing.
  cat > /usr/local/bin/chromium <<'CHROMIUMWRAP'
#!/bin/bash
exec /usr/bin/chromium --ozone-platform=wayland --disable-gpu --enable-unsafe-swiftshader "$@"
CHROMIUMWRAP
  chmod +x /usr/local/bin/chromium
  log "setup complete"
fi

# ----------------------------------------------------------------- session --
pkill -f Hyprland 2>/dev/null; pkill -f quickshell 2>/dev/null
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
  LIBSEAT_BACKEND=seatd AQ_NO_ATOMIC=1 DBUS_SESSION_BUS_ADDRESS=unix:path=$RT/bus PATH=/usr/local/bin:/usr/bin:/usr/sbin \
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
(setsid env DBUS_SESSION_BUS_ADDRESS=$DBUS_SESSION_BUS_ADDRESS \
  QS_DISABLE_FILE_WATCHER=1 QS_NO_RELOAD_POPUP=1 \
  quickshell -n -p "$OMARCHY_PATH/shell" >/tmp/qs.log 2>&1 &)

# In-guest VNC: wayvnc attaches to Hyprland via screencopy with native damage
# tracking, tight encodings, and a client-side cursor — far cheaper than
# streaming the raw scanout.
(setsid env WAYLAND_DISPLAY=$WAYLAND_DISPLAY XDG_RUNTIME_DIR=$XDG_RUNTIME_DIR \
  wayvnc 0.0.0.0 5901 >/tmp/wayvnc.log 2>&1 &)

sleep 8
timeout 10 hyprctl monitors | head -4
grim /tmp/a.png; sleep 3; grim /tmp/b.png
[ "$(sha256sum </tmp/a.png)" != "$(sha256sum </tmp/b.png)" ] \
  && echo "LIVE: frames differ" || echo "frames static"
echo "SESSION_UP — connect a VNC client to host port 5901 (wayvnc)"
INNER
