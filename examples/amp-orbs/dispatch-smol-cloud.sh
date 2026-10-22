#!/usr/bin/env bash
# Amp self-hosted orb provider backed by smol cloud: every orb is a smol cloud
# machine, found again by its `amp-orb` label.
#
#   export SMOL_API_KEY=<smol cloud API key>
#   export AMP_ORB_PROVIDER_TOKEN=<token from Amp's Custom Orb Provider settings>
#   amp orb provider ./dispatch-smol-cloud.sh
#
# Pause saves the machine's RAM and disk, so an orb wakes with its processes
# still running; a paused orb is not billed for CPU or memory. Orbs are created
# branchable, so an orb can also be branched.
# Needs curl and jq.
set -euo pipefail

API="${SMOL_CLOUD_URL:-https://api.smolmachines.com}"
: "${SMOL_API_KEY:?SMOL_API_KEY is required}"
: "${ORB_ID:?ORB_ID is required}"
CPUS="${ORB_CPUS:-4}"
MEMORY_MB="${ORB_MEMORY_MB:-8192}"
DISK_GB="${ORB_DISK_GB:-40}"

# api METHOD PATH [BODY] [ALSO_OK]: prints the response body. A status of 400
# or more fails unless it is listed in ALSO_OK (e.g. "404 409"), for calls whose
# repeat answers that way.
api() {
  local method=$1 path=$2 body=${3:-} also_ok=${4:-}
  local args=(-sS -X "$method" -H "Authorization: Bearer $SMOL_API_KEY" -w '\n%{http_code}')
  if [ -n "$body" ]; then args+=(-H 'Content-Type: application/json' --data "$body"); fi
  local out code
  out=$(curl "${args[@]}" "$API$path")
  code=${out##*$'\n'}
  out=${out%$'\n'*}
  if [ "$code" -ge 400 ] && [[ " $also_ok " != *" $code "* ]]; then
    echo "$method $path: HTTP $code: $out" >&2
    return 1
  fi
  printf '%s' "$out"
}

# Prints "<id> <state>" of this orb's machine, or nothing.
find_orb() {
  api GET "/v1/machines?label=$(jq -rn --arg l "amp-orb=$ORB_ID" '$l | @uri')" |
    jq -r 'if type == "array" then .[0] // empty | "\(.id) \(.state)" else empty end'
}

state_of() { api GET "/v1/machines/$1" | jq -r '.state // empty'; }

# Wait until the machine settles in one of the given states.
wait_for() {
  local id=$1 deadline=$((SECONDS + 240)) state
  shift
  while :; do
    state=$(state_of "$id")
    for want in "$@"; do [ "$state" = "$want" ] && return 0; done
    case "$state" in
      error | deleted | "") echo "orb $id is $state" >&2; return 1 ;;
    esac
    if [ "$SECONDS" -ge "$deadline" ]; then
      echo "orb $id is still $state" >&2
      return 1
    fi
    sleep 2
  done
}

bootstrap() {
  local env
  env=$(jq -n --arg token "$ORB_TOKEN" --arg url "${AMP_URL:-}" \
    '{ORB_TOKEN: $token} + (if $url == "" then {} else {AMP_URL: $url} end)')
  api POST "/v1/machines/$1/exec" "$(jq -n --argjson env "$env" \
    '{command: ["amp", "orb", "bootstrap"], user: "user", background: true, env: $env}')" >/dev/null
}

case "${ORB_OPERATION:?ORB_OPERATION is required}" in
  spawn)
    : "${ORB_TOKEN:?ORB_TOKEN is required}"
    read -r id state < <(find_orb) || true
    case "${state:-}" in
      started) ;;
      paused) api POST "/v1/machines/$id/resume" >/dev/null ;;
      pausing) wait_for "$id" paused && api POST "/v1/machines/$id/resume" >/dev/null ;;
      stopped) api POST "/v1/machines/$id/start" "" 409 >/dev/null ;;
      creating) ;;
      *)
        id=$(api POST /v1/machines "$(jq -n \
          --arg image "$ORB_IMAGE" --arg orb "$ORB_ID" \
          --argjson cpus "$CPUS" --argjson mem "$MEMORY_MB" --argjson disk "$DISK_GB" \
          '{name: ("orb-" + $orb), labels: {"amp-orb": $orb},
            source: {type: "image", reference: $image, arch: "amd64"},
            resources: {cpus: $cpus, memoryMb: $mem, diskGb: $disk},
            network: {mode: "open"}, forkable: true}')" | jq -r .id)
        api POST "/v1/machines/$id/start" "" 409 >/dev/null
        ;;
    esac
    wait_for "$id" started
    bootstrap "$id"
    ;;
  pause)
    read -r id state < <(find_orb) || true
    if [ "${state:-}" = started ]; then api POST "/v1/machines/$id/pause" >/dev/null; fi
    ;;
  delete)
    read -r id state < <(find_orb) || true
    if [ -n "${id:-}" ]; then api DELETE "/v1/machines/$id" "" 404 >/dev/null; fi
    ;;
  *)
    echo "unknown ORB_OPERATION: $ORB_OPERATION" >&2
    exit 1
    ;;
esac
