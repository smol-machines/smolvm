#!/bin/bash
# Omarchy (DHH's Arch + Hyprland setup) inside a smolvm machine, end to end:
# package set -> real omarchy Hyprland session on the DRM backend -> live
# pixels served by the host's VNC server (SMOLVM_VNC).
#
# Launch from the host with:
#   SMOLVM_DISPLAY=1280x800 SMOLVM_VNC=127.0.0.1:5900 \
#     smolvm machine run --net --gpu --cpus 4 --mem 6144 \
#       -v "$PWD:/in" --image archlinux:latest -- bash /in/omarchy.sh
set -o pipefail
export LANG=C

# Pin a coherent snapshot: rolling mirrors routinely serve a mesa that needs a
# libdrm symbol the same mirror has not published yet. Parallel downloads and
# no per-file timeout ride out archive.archlinux.org's throttling.
echo 'Server=https://archive.archlinux.org/repos/2026/08/20/$repo/os/$arch' > /etc/pacman.d/mirrorlist
sed -i 's/^#ParallelDownloads.*/ParallelDownloads = 8/' /etc/pacman.conf

pacman -Sy --noconfirm --needed --disable-download-timeout git sudo >/dev/null 2>&1 || exit 1
git clone -q --depth 1 https://github.com/basecamp/omarchy /tmp/om || exit 1

# Install every omarchy base package the official repos carry (the rest are
# AUR/omarchy-published and orthogonal to running the session).
mapfile -t PKGS < <(grep -vE "^\s*#|^\s*$" /tmp/om/install/omarchy-base.packages)
OK=()
for p in "${PKGS[@]}"; do pacman -Si "$p" >/dev/null 2>&1 && OK+=("$p"); done
for attempt in 1 2 3; do
  pacman -S --noconfirm --needed --disable-download-timeout "${OK[@]}" foot grim >/tmp/pac.log 2>&1 && break
  sleep 20
done

id omar >/dev/null 2>&1 || useradd -m -G wheel,video,input,seat,render omar
printf '%%wheel ALL=(ALL) NOPASSWD: ALL\n' > /etc/sudoers.d/wheel && chmod 440 /etc/sudoers.d/wheel
RT=/run/user/1000; mkdir -p "$RT"; chown omar:omar "$RT"; chmod 700 "$RT"
chmod 666 /dev/dri/* 2>/dev/null

# Chromium passes fonts and tiles between processes through POSIX shared
# memory; at the 64M container-default /dev/shm its font service hits ENOSPC
# and CHECK-crashes the renderer whenever a video plays.
mount -o remount,size=2G /dev/shm 2>/dev/null || true

# D-Bus refuses to start without a machine id, and the session components
# need a session bus — a container guest has neither out of the box.
dbus-uuidgen --ensure 2>/dev/null || true

# Chromium wrapper: Wayland, software rendering, and software WebGL —
# --enable-unsafe-swiftshader matters: modern Chromium blocks software WebGL
# in windowed mode without it, so CAD/3D sites silently render nothing.
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

# Input devices need two container-guest fixes. First: /dev is not devtmpfs,
# so the evdev nodes the kernel registered (visible in /sys/class/input)
# never appear in /dev — create them, the same way k3d guests need /dev/kmsg.
mkdir -p /dev/input
for e in /sys/class/input/event*; do
  [ -e "$e" ] || continue
  n=$(basename "$e")
  maj=$(cut -d: -f1 "$e/dev"); min=$(cut -d: -f2 "$e/dev")
  [ -e "/dev/input/$n" ] || mknod "/dev/input/$n" c "$maj" "$min"
done

# Second: libinput only adopts devices classified in the udev database, and
# systemd-udevd cannot populate it without a full systemd runtime. libudev
# reads /run/udev/data directly and needs no daemon, so write the entries by
# hand (the file's existence also marks the device "initialized").
mkdir -p /run/udev/data
for e in /sys/class/input/event*; do
  [ -e "$e" ] || continue
  devnum=$(cat "$e/dev")
  case "$(cat "$e/device/name" 2>/dev/null)" in
    *keyboard*) type=ID_INPUT_KEYBOARD ;;
    *)          type=ID_INPUT_MOUSE ;;
  esac
  printf 'E:ID_INPUT=1\nE:%s=1\nG:seat\nQ:seat\n' "$type" > "/run/udev/data/c$devnum"
done

# A VT-bound seat cannot open a session in a container with no /dev/tty0.
SEATD_VTBOUND=0 seatd -g wheel >/tmp/seatd.log 2>&1 &
sleep 2

# Omarchy's layout, as its installer creates it:
#   - the repo at /usr/share/omarchy (hyprland.lua dofile()s
#     /usr/share/omarchy/default/hypr/bootstrap.lua — the SYSTEM path; with it
#     missing the lua config errors and Hyprland trips emergency mode)
#   - config tree copied to ~/.config
#   - the STATE theme link ~/.local/state/omarchy/current/theme, which
#     foot.ini and friends include (distinct from ~/.config/omarchy/current)
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
chown -R omar:omar /home/omar/.config /home/omar/.local

sudo -u omar env HOME=/home/omar XDG_RUNTIME_DIR=$RT XDG_SESSION_TYPE=wayland \
  LIBSEAT_BACKEND=seatd AQ_NO_ATOMIC=1 bash -s <<'INNER'
set -o pipefail
Hyprland >/tmp/hypr.log 2>&1 &
for i in $(seq 1 40); do ls "$XDG_RUNTIME_DIR"/wayland-* >/dev/null 2>&1 && break; sleep 1; done
S=$(ls "$XDG_RUNTIME_DIR"/wayland-* 2>/dev/null | grep -v '\.lock$' | head -1)
[ -z "$S" ] && { echo "compositor failed"; tail -20 /tmp/hypr.log; exit 1; }
export WAYLAND_DISPLAY=$(basename "$S")
export HYPRLAND_INSTANCE_SIGNATURE=$(ls -t "$XDG_RUNTIME_DIR"/hypr 2>/dev/null | head -1)
echo "omarchy hyprland up on $WAYLAND_DISPLAY"

# virtio-gpu has no explicit-sync or hardware-cursor support yet; the lua
# config owns the file-level settings, so apply these at runtime.
timeout 10 hyprctl keyword render:explicit_sync 0 >/dev/null 2>&1
timeout 10 hyprctl keyword cursor:no_hardware_cursors true >/dev/null 2>&1

# Omarchy's shell (bar, notifications, wallpaper) is one Quickshell app,
# normally launched by omarchy-launch-shell through systemd user units — which
# a container guest does not run. Spawn it directly. (Under the lua config
# `hyprctl dispatch exec` parses its argument as lua — spawn clients as plain
# processes instead.)
# dbus-launch plain output single-quotes the address; export $(...) keeps
# the quotes in the variable and every D-Bus client then fails to parse
# it. --sh-syntax emits eval-able assignments instead.
eval "$(dbus-launch --sh-syntax 2>/dev/null)"
export DBUS_SESSION_BUS_ADDRESS DBUS_SESSION_BUS_PID
export OMARCHY_PATH=$HOME/.local/share/omarchy
(setsid env DBUS_SESSION_BUS_ADDRESS=$DBUS_SESSION_BUS_ADDRESS \
  QS_DISABLE_FILE_WATCHER=1 QS_NO_RELOAD_POPUP=1 \
  quickshell -n -p "$OMARCHY_PATH/shell" >/dev/null 2>&1 &)
(setsid foot -e watch -n1 date >/dev/null 2>&1 &)

sleep 12
timeout 10 hyprctl monitors | head -4
# Liveness: two captures a few seconds apart must differ (the clock ticks).
grim /tmp/a.png; sleep 3; grim /tmp/b.png
[ "$(sha256sum </tmp/a.png)" != "$(sha256sum </tmp/b.png)" ] && echo "LIVE: frames differ" || echo "static"
INNER

cp /tmp/*.png /in/ 2>/dev/null
echo "desktop is up; connect a VNC client to the host's SMOLVM_VNC address"
sleep 600
