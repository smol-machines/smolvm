#!/usr/bin/env bash
# Verify targeted requests remain correct without consulting unrelated inventory.
source "$(dirname "$0")/common.sh"
init_smolvm
WORK=$(mktemp -d "${TMPDIR:-/tmp}/smol-inventory-XXXXXX")
WORK=$(cd "$WORK" && pwd -P)
ROOT="$WORK/engine"
SOCKET="$WORK/docker.sock"
export DOCKER_HOST="unix://$SOCKET"
unset DOCKER_CONTEXT BUILDX_BUILDER
NAME="smol-inventory-$$"
cleanup() {
    local status=$?
    if [[ -d "$ROOT/volumes-saved" ]]; then mv "$ROOT/volumes-saved" "$ROOT/volumes"; fi
    docker rm -f "${ID:-$NAME}" "$NAME" "$NAME-renamed" "$NAME-reused" >/dev/null 2>&1 || true
    "$SMOLVM" engine unregister --socket "$SOCKET" --root "$ROOT" >/dev/null 2>&1 || true
    if [[ $status != 0 ]]; then cat "$ROOT/adapter.log" "$ROOT"/containers/*/supervisor.log 2>/dev/null || true; fi
    rm -rf "$WORK"
}
trap cleanup EXIT
"$SMOLVM" engine register --socket "$SOCKET" --root "$ROOT"
docker pull -q alpine >/dev/null
ID=$(docker create --name "$NAME" alpine true)
# Warm the owning supervisor, whose initial recovery legitimately reads inventory.
[[ $(docker inspect --format '{{.Id}}' "$ID") == "$ID" ]]
mv "$ROOT/volumes" "$ROOT/volumes-saved"
# A missing inventory directory makes an accidental refresh fail deterministically.
[[ $(curl -fsS --unix-socket "$SOCKET" http://d/_ping) == OK ]]
curl -fsS --unix-socket "$SOCKET" http://d/v1.44/version >/dev/null
curl -fsSI --unix-socket "$SOCKET" http://d/v1.44/_ping >/dev/null
[[ $(docker inspect --format '{{.Id}}' "$ID") == "$ID" ]]
[[ $(docker inspect --format '{{.Id}}' "$NAME") == "$ID" ]]
[[ $(docker inspect --format '{{.Id}}' "${ID:0:12}") == "$ID" ]]
# Collection operations still consult live shared state.
if docker volume ls >/dev/null 2>&1; then echo 'volume listing ignored missing inventory' >&2; exit 1; fi
mv "$ROOT/volumes-saved" "$ROOT/volumes"
docker rename "$NAME" "$NAME-renamed"
if docker inspect "$NAME" >/dev/null 2>&1; then echo 'old name still resolves' >&2; exit 1; fi
[[ $(docker inspect --format '{{.Id}}' "$NAME-renamed") == "$ID" ]]
NEW=$(docker create --name "$NAME" alpine true)
[[ $(docker inspect --format '{{.Id}}' "$NAME") == "$NEW" ]]
docker rm "$NAME" "$NAME-renamed" >/dev/null
if docker inspect "$ID" >/dev/null 2>&1; then echo 'removed ID still resolves' >&2; exit 1; fi
# A name can itself look like a full ID; direct lookup must retain name fallback.
docker create --name "$ID" alpine true >"$WORK/hex-id"
HEX=$(cat "$WORK/hex-id")
[[ $(docker inspect --format '{{.Id}}' "$ID") == "$HEX" ]]
docker rename "$ID" "$NAME-reused"
docker rm "$NAME-reused" >/dev/null
# All per-start readiness rendezvous are transient.
if compgen -G "$WORK/w-*.ready" >/dev/null; then echo 'readiness socket leaked' >&2; exit 1; fi
# Removing temporary engine state must not strand idle supervisors trying to lock it.
"$SMOLVM" engine unregister --socket "$SOCKET" --root "$ROOT"
rm -rf "$ROOT"
for _ in $(seq 1 100); do
    if ! compgen -G "$WORK/w-*.sock" >/dev/null; then break; fi
    sleep 0.2
done
if compgen -G "$WORK/w-*.sock" >/dev/null; then echo 'supervisor survived removal of its engine state' >&2; exit 1; fi
echo 'PASS: inventory-independent probes and reads, fresh rename/remove/name reuse, and supervisor readiness cleanup'
