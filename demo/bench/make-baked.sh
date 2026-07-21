#!/bin/bash
# Build the baked machine ($BAKED) once: a packed smolvm VM with the python
# venv and HF model cache copied onto its own block storage, so the golden
# never mounts them over virtiofs or re-downloads. Needs VENV + HF populated
# (see config.sh / QUICKSTART.md). ~10 min; produces a ~8 GB .smolmachine.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/config.sh"

[ -d "$VENV" ] || { echo "MISSING venv at $VENV (set VENV=...)"; exit 1; }
[ -d "$HF/hub" ] || { echo "MISSING HF cache at $HF/hub (pre-download the model; set HF=...)"; exit 1; }
[ -x "$SMOLVM" ] || { echo "MISSING smolvm at $SMOLVM"; exit 1; }

echo "== provisioning bake VM (copying venv + HF cache onto guest disk) =="
"$SMOLVM" machine rm --name bake --force >/dev/null 2>&1
"$SMOLVM" machine create --name bake --net --storage 30 --overlay 10 \
  -v "$VENV:/mnt/venv_src:ro" -v "$HF:/mnt/hf_src:ro" \
  --image ubuntu:22.04 -- sh -c '
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq && apt-get install -y -qq python3 python3-dev gcc ca-certificates
    mkdir -p /home/ubuntu /opt/hfcache
    cp -a /mnt/venv_src /home/ubuntu/ptwork
    cp -a /mnt/hf_src/hub /opt/hfcache/hub
    sync
    touch /done' >/dev/null 2>&1
"$SMOLVM" machine start --name bake >/dev/null 2>&1 &
# wait for the copy to finish (the machine exits after `touch /done`; poll VM)
for i in $(seq 1 120); do
  "$SMOLVM" machine list 2>/dev/null | grep -q "^bake" || break
  sleep 5
done
"$SMOLVM" machine stop --name bake >/dev/null 2>&1; sleep 2

echo "== packing -> $BAKED =="
out="${BAKED%.smolmachine}"
SMOLVM_FILE_TRANSFER_MAX_BYTES=64G "$SMOLVM" pack create --from-vm bake -o "$out"
"$SMOLVM" machine rm --name bake --force >/dev/null 2>&1
[ -f "$BAKED" ] && echo "OK: $BAKED ($(du -h "$BAKED" | cut -f1))" || echo "FAILED: $BAKED not produced"
