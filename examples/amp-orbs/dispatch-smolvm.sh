#!/usr/bin/env bash
# Amp self-hosted orb provider backed by smolvm: every orb is a smol machine.
#
#   export AMP_ORB_PROVIDER_TOKEN=<token from Custom Orb Provider settings>
#   amp orb provider ./dispatch-smolvm.sh
#
# Pause saves the machine's RAM and disk, so an orb wakes with its processes
# still running. Amp's orb image is linux/amd64, so run this on an x86_64
# Linux host with KVM.
set -euo pipefail

SMOLVM="${SMOLVM:-smolvm}"
CPUS="${ORB_CPUS:-4}"
MEMORY_MIB="${ORB_MEMORY_MIB:-8192}"
STORAGE_GIB="${ORB_STORAGE_GIB:-40}"
name="orb-${ORB_ID:?ORB_ID is required}"

state() {
  "$SMOLVM" machine status --name "$name" --json 2>/dev/null |
    grep -o '"state": *"[a-z]*"' | grep -o '[a-z]*"$' | tr -d '"' || true
}

bootstrap() {
  # The token is read from this process's environment, so it never appears on
  # a command line.
  local env=(--secret-env "ORB_TOKEN=ORB_TOKEN")
  if [ -n "${AMP_URL:-}" ]; then env+=(-e "AMP_URL=$AMP_URL"); fi
  "$SMOLVM" machine exec --name "$name" -u user -d "${env[@]}" -- amp orb bootstrap
}

case "${ORB_OPERATION:?ORB_OPERATION is required}" in
  spawn)
    : "${ORB_TOKEN:?ORB_TOKEN is required}"
    case "$(state)" in
      running) ;;
      paused) "$SMOLVM" machine resume --name "$name" ;;
      stopped | created) "$SMOLVM" machine start --name "$name" ;;
      *)
        "$SMOLVM" machine create --name "$name" --image "$ORB_IMAGE" --net \
          --cpus "$CPUS" --mem "$MEMORY_MIB" --storage "$STORAGE_GIB"
        "$SMOLVM" machine start --name "$name"
        ;;
    esac
    bootstrap
    ;;
  pause)
    if [ "$(state)" = running ]; then
      "$SMOLVM" machine pause --name "$name"
    fi
    ;;
  delete)
    if [ -n "$(state)" ]; then
      "$SMOLVM" machine delete --name "$name" -f
    fi
    ;;
  *)
    echo "unknown ORB_OPERATION: $ORB_OPERATION" >&2
    exit 1
    ;;
esac
