#!/usr/bin/env bash
# Wait for dockerd inside the machine, starting it when nothing else does.
#
# usage: start-dockerd.sh [<name>]
#
# Run this on EVERY start, not only the first. With assets/docker.smolfile
# (v1.28.1 and later) the docker:dind workload starts dockerd on its disk
# volumes, and this only waits for it. With assets/docker-bind-mounts.smolfile
# nothing starts it, and `init` runs once, so on any start after the first
# /var/lib/docker is back on the rootfs overlay: this re-applies the bind mounts
# and starts dockerd, the upstream example's "Start dockerd" recipe.

set -uo pipefail

NAME="${1:-smolskill-docker}"
SMOLVM="${SMOLVM:-$(command -v smolvm 2>/dev/null)}"
if [ -z "$SMOLVM" ]; then
    printf 'smolvm not found; set SMOLVM to its path\n' >&2
    exit 2
fi

# shellcheck disable=SC2016  # $(seq ...) runs in the guest shell, not here
"$SMOLVM" machine exec --name "$NAME" -- sh -c '
  # 10 s for the image'\''s own dockerd to appear before deciding nothing starts it.
  for i in $(seq 1 10); do pgrep -x dockerd >/dev/null && break; sleep 1; done
  if ! pgrep -x dockerd >/dev/null; then
    echo "starting dockerd on the bind mounts"
    mkdir -p /storage/docker /var/lib/docker /storage/containerd /var/lib/containerd
    mountpoint -q /var/lib/docker     || mount --bind /storage/docker /var/lib/docker
    mountpoint -q /var/lib/containerd || mount --bind /storage/containerd /var/lib/containerd
    rm -f /var/run/docker.pid
    dockerd --storage-driver=overlay2 >/tmp/dockerd.log 2>&1 &
  fi
  # 60 s: dockerd answered docker info within a few seconds on both hosts here;
  # the margin covers a first start that has to create its storage layout.
  for i in $(seq 1 60); do docker info >/dev/null 2>&1 && break; sleep 1; done
  docker info 2>/dev/null | grep -E "Server Version|Storage Driver|Docker Root Dir"
' 2>&1 | sed 's/^/  /'

# `docker info` succeeding is not the check that matters; see verify-docker.sh.
server="$("$SMOLVM" machine exec --name "$NAME" -- docker info --format '{{.ServerVersion}}' 2>&1 | tr -d '\r')"
printf 'server_version=%s\n' "$server"
case "$server" in
    [0-9]*) printf 'result=dockerd_up\n' ;;
    *)
        printf 'result=dockerd_down\n'
        printf 'daemon log:\n'
        "$SMOLVM" machine exec --name "$NAME" -- tail -20 /tmp/dockerd.log 2>&1 | sed 's/^/  /'
        exit 1
        ;;
esac
