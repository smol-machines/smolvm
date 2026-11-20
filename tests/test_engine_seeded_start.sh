#!/usr/bin/env bash
# A cached image starts without host fetching even when its VM has no network.
source "$(dirname "$0")/common.sh"
init_smolvm
WORK=$(mktemp -d /tmp/sms-XXXXXX)
WORK=$(cd "$WORK" && pwd -P)
ROOT="$WORK/engine"
SOCKET="$WORK/docker.sock"
export SMOLVM_DATA_DIR="$WORK/data" SMOLVM_CONFIG="$WORK/config.toml" DOCKER_HOST="unix://$SOCKET"
unset DOCKER_CONTEXT BUILDX_BUILDER
cleanup() {
    docker rm -f "${ID:-smol-seeded-unused}" >/dev/null 2>&1 || true
    "$SMOLVM" engine unregister --socket "$SOCKET" --root "$ROOT" >/dev/null 2>&1 || true
    # Leave the socket directory present until idle supervisors remove their sockets.
    rm -rf "$ROOT"
    for _ in $(seq 1 100); do
        if ! compgen -G "$WORK/w-*.sock" >/dev/null; then break; fi
        sleep 0.2
    done
    rm -rf "$WORK"
}
trap cleanup EXIT
"$SMOLVM" engine register --socket "$SOCKET" --root "$ROOT"
docker pull -q alpine >/dev/null
ID=$(docker create --network none alpine sh -c 'test ! -e /sys/class/net/eth0 && echo seeded')
check_image_on_disk() {
    python3 - "$ID" <<'PY'
import json, os, pathlib, sqlite3, sys
root = pathlib.Path(os.environ['SMOLVM_DATA_DIR'])
data = root / ('Library/Application Support' if sys.platform == 'darwin' else '.local/share')
with sqlite3.connect(f'file:{data}/smolvm/server/smolvm.db?mode=ro', uri=True) as db:
    row = db.execute('SELECT data FROM vms WHERE name = ?', ('docker-' + sys.argv[1][:12],)).fetchone()
record = json.loads(row[0])
assert record['init_completed'], 'seeded disk was not recorded as containing the image'
assert not record['network'], 'seeding enabled guest networking'
assert '@sha256:' in record['image'] and not record['image'].startswith('local:'), record['image']
assert not record.get('image_origin'), 'start fetched and staged the seeded image again'
PY
}
check_image_on_disk
[[ $(docker start -a "$ID") == seeded ]]
check_image_on_disk
[[ $(docker start -a "$ID") == seeded ]]
check_image_on_disk
echo 'PASS: seeded image survives first start and restart without host restaging or guest networking'
