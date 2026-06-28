#!/usr/bin/env bash
# Full-VM e2e for the shared content-addressed pack store + per-VM idmapped
# bind mount. Drives the *serve API* (the cloud/node path that the shared store
# targets) as root so the per-VM uid drop (#456) is active and the idmap mount
# fires. Validates: (1) shared store extracts ONCE into _shared/<checksum>,
# root-owned 0700; (2) a second machine from the same .smolmachine REUSES it
# (no second decode); (3) each machine leaves an empty `pack` mountpoint + a
# `.pack-shared` pointer; (4) both guests BOOT and exec reads files (proving the
# idmap mount presented the root-owned pack as the VM's dropped uid); (5) the
# on-disk shared copy stays root:root (isolation preserved).
#
# Run as root on a Linux/KVM box:  sudo SMOLVM=... SMOLVM_LIB_DIR=... ./idmap_e2e_boot.sh /path/to/x.smolmachine
set -u

SMOLVM="${SMOLVM:?set SMOLVM to the smolvm binary}"
SIDECAR="${1:?usage: idmap_e2e_boot.sh <file.smolmachine>}"
DATA_DIR="${SMOLVM_DATA_DIR:-/tmp/idmap-e2e-data}"
SOCK="/tmp/idmap-e2e.sock"
CURL=(curl -s --unix-socket "$SOCK")
URL="http://localhost"
PASS=0; FAIL=0
ok()   { echo "  PASS: $*"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL: $*"; FAIL=$((FAIL+1)); }

# Fresh, world-traversable data root so the dropped VM uid can reach its dirs.
rm -rf "$DATA_DIR"; mkdir -p "$DATA_DIR"; chmod 755 "$DATA_DIR"
export SMOLVM_DATA_DIR="$DATA_DIR"

# Seed the node-constant guest agent-rootfs (the serve API gates `start` on it
# via "verify rootfs"). It's install-state, not part of the per-image pack the
# shared store optimizes, so we copy a known-good tree in rather than re-install.
AGENT_ROOTFS_SRC="${AGENT_ROOTFS_SRC:-$HOME/.local/share/smolvm/agent-rootfs}"
if [ -d "$AGENT_ROOTFS_SRC" ]; then
  mkdir -p "$DATA_DIR/.local/share/smolvm"
  cp -a "$AGENT_ROOTFS_SRC" "$DATA_DIR/.local/share/smolvm/agent-rootfs"
  chmod -R a+rX "$DATA_DIR/.local/share/smolvm"
else
  echo "[!] no agent-rootfs at $AGENT_ROOTFS_SRC — boot steps will fail (set AGENT_ROOTFS_SRC)"
fi

echo "[*] euid=$(id -u) (expect 0 for uid-drop), data=$DATA_DIR, sidecar=$SIDECAR"

rm -f "$SOCK"
"$SMOLVM" serve start -l "unix://$SOCK" >"$DATA_DIR/serve.log" 2>&1 &
SERVE_PID=$!
cleanup() {
  "${CURL[@]}" -X DELETE "$URL/api/v1/machines/e2e-a" >/dev/null 2>&1 || true
  "${CURL[@]}" -X DELETE "$URL/api/v1/machines/e2e-b" >/dev/null 2>&1 || true
  kill "$SERVE_PID" 2>/dev/null || true; wait "$SERVE_PID" 2>/dev/null || true
}
trap cleanup EXIT

for i in $(seq 1 50); do "${CURL[@]}" "$URL/health" >/dev/null 2>&1 && break; sleep 0.2; done
"${CURL[@]}" "$URL/health" | grep -q '"status":"ok"' && ok "serve up" || { bad "serve did not start"; cat "$DATA_DIR/serve.log"; exit 1; }

create() {
  "${CURL[@]}" -o /dev/null -w "%{http_code}" -X POST "$URL/api/v1/machines" \
    -H 'Content-Type: application/json' -d "{\"name\":\"$1\",\"from\":\"$SIDECAR\",\"cpus\":1,\"mem\":512}"
}

# --- Create machine A: first extraction populates the shared store ----------
echo "[*] creating e2e-a"
[ "$(create e2e-a)" = "200" ] && ok "create e2e-a 200" || bad "create e2e-a !=200"

# Layout: SMOLVM_DATA_DIR becomes $HOME, so the store is $HOME/.cache/smolvm/vms.
VMS_ROOT="$(find "$DATA_DIR" -type d -path '*/smolvm/vms' | head -1)"
SHARED_ROOT="$VMS_ROOT/_shared"
[ -d "$SHARED_ROOT" ] && ok "shared root exists: $SHARED_ROOT" || bad "no shared root (vms=$VMS_ROOT)"
CKDIR="$(find "$SHARED_ROOT" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | head -1)"
[ -n "$CKDIR" ] && ok "shared checksum dir: $(basename "$CKDIR")" || bad "no shared checksum dir"
# Root-owned + 0700 (isolation): a sibling dropped-uid cannot read it directly.
own="$(stat -c '%U:%G %a' "$CKDIR" 2>/dev/null)"
[ "$own" = "root:root 700" ] && ok "shared dir is root:root 0700" || bad "shared dir perms = $own (want root:root 700)"
# Per-machine: empty `pack` mountpoint + a pointer to the shared dir.
PACK_A="$(find "$VMS_ROOT" -mindepth 2 -maxdepth 2 -name pack -type d 2>/dev/null | grep -v _shared | head -1)"
PTR_A="$(dirname "$PACK_A")/.pack-shared"
[ -f "$PTR_A" ] && ok "pointer written: $PTR_A -> $(cat "$PTR_A")" || bad "no .pack-shared pointer"
[ -z "$(ls -A "$PACK_A" 2>/dev/null)" ] && ok "pack mountpoint is empty (pre-boot)" || bad "pack mountpoint not empty"

# --- Create machine B from the SAME sidecar: must REUSE, not re-extract ------
echo "[*] creating e2e-b (same sidecar)"
[ "$(create e2e-b)" = "200" ] && ok "create e2e-b 200" || bad "create e2e-b !=200"
NDIRS="$(find "$SHARED_ROOT" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')"
[ "$NDIRS" = "1" ] && ok "still ONE shared dir after 2 creates (reuse, no re-decode)" || bad "shared dirs=$NDIRS (expected 1)"

# --- Boot both: idmap mount presents the root-owned pack as each VM's uid ----
boot_and_exec() {
  local n="$1"
  local st; st="$("${CURL[@]}" -X POST "$URL/api/v1/machines/$n/start")"
  echo "$st" | grep -q '"state":"running"' && ok "$n booted (state=running)" || { bad "$n did not boot"; echo "$st"; }
  local ex; ex="$("${CURL[@]}" -X POST "$URL/api/v1/machines/$n/exec" -H 'Content-Type: application/json' -d '{"command":["cat","/etc/os-release"]}')"
  echo "$ex" | grep -qi 'alpine\|linux' && ok "$n exec read rootfs through idmap mount" || { bad "$n exec failed"; echo "$ex" | head -c 400; }
}
boot_and_exec e2e-a
boot_and_exec e2e-b

# --- Isolation: shared copy still root-owned after both VMs booted -----------
own2="$(stat -c '%U:%G %a' "$CKDIR" 2>/dev/null)"
[ "$own2" = "root:root 700" ] && ok "shared copy still root:root 0700 post-boot" || bad "shared perms changed: $own2"

# --- The two VMMs dropped to DIFFERENT uids (per-VM isolation #456) ----------
uids="$(ps -eo uid,args | grep '[_]boot-vm' | awk '{print $1}' | sort -u)"
nuid="$(echo "$uids" | grep -c .)"
echo "[*] live _boot-vm uids: $(echo $uids | tr '\n' ' ')"
[ "$nuid" -ge 2 ] && ok "VMMs run under >=2 distinct dropped uids" || echo "  INFO: distinct boot-vm uids=$nuid (VMs may share or have exited)"

echo ""
echo "==== idmap e2e: $PASS passed, $FAIL failed ===="
[ "$FAIL" = "0" ]
