#!/usr/bin/env bash
# Run after building smolvm on Linux KVM or Apple Silicon macOS with an agent rootfs.
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
for tool in curl nc od dd grep; do
  command -v "$tool" >/dev/null || { echo "Missing host tool: $tool" >&2; exit 1; }
done
if [[ $(uname -s) == Linux && ! -e /dev/kvm ]]; then
  echo 'This test requires /dev/kvm' >&2
  exit 1
fi

host_home=$HOME
if [[ $(uname -s) == Darwin ]]; then
  rootfs=${SMOLVM_AGENT_ROOTFS:-"$host_home/Library/Application Support/smolvm/agent-rootfs"}
else
  rootfs=${SMOLVM_AGENT_ROOTFS:-"$host_home/.local/share/smolvm/agent-rootfs"}
fi
[[ -d $rootfs ]] || { echo "Missing agent rootfs: $rootfs" >&2; exit 1; }
binary=${SMOLVM_E2E_BIN:-"$repo/target/debug/smolvm"}
[[ -x $binary ]] || { echo "Missing smolvm binary: $binary" >&2; exit 1; }

tmp=$(mktemp -d /tmp/smolvm-med-XXXXXXXX)
server_pid= broker_pid= direct_pid=
cleanup() {
  if [[ -n $server_pid ]]; then
    for name in child source; do
      curl -sS --max-time 3 -X POST "$base/$name/stop" >/dev/null 2>&1 || true
      curl -sS --max-time 3 -X DELETE "$base/$name" >/dev/null 2>&1 || true
    done
  fi
  for pid in "$direct_pid" "$broker_pid" "$server_pid"; do
    if [[ -n $pid ]]; then kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi
  done
  case $tmp in /tmp/smolvm-med-*) rm -rf "$tmp" ;; esac
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" >&2
  if [[ -s $tmp/server.log ]]; then tail -n 30 "$tmp/server.log" >&2; fi
  exit 1
}
pick_port() {
  local port
  while :; do
    port=$((20000 + RANDOM % 35000))
    [[ $port != "$api_port" && $port != "$broker_port" && $port != "$direct_port" && $port != "$rollout_port" ]] || continue
    if ! nc -z 127.0.0.1 "$port" >/dev/null 2>&1; then printf '%s' "$port"; return; fi
  done
}
api_port= broker_port= direct_port= rollout_port=
api_port=$(pick_port)
broker_port=$(pick_port)
direct_port=$(pick_port)
rollout_port=$(pick_port)
base="http://127.0.0.1:$api_port/api/v1/machines"
api() {
  local method=$1 path=$2
  local args=(-sS --max-time 60 -o "$tmp/response.json" -w '%{http_code}' -X "$method" -H 'Content-Type: application/json')
  if (( $# == 3 )); then args+=(--data-binary "$3"); fi
  status=$(curl "${args[@]}" "$base$path") || fail "$method $path could not reach API"
  body=$(<"$tmp/response.json")
}
expect() {
  local wanted=$1 method=$2 path=$3
  if (( $# == 4 )); then api "$method" "$path" "$4"; else api "$method" "$path"; fi
  [[ $status == "$wanted" ]] || fail "$method $path returned $status, wanted $wanted: $body"
}
guest() {
  expect 200 POST "/$1/exec" "{\"command\":[\"sh\",\"-c\",\"$2\"]}"
}
hex_at() { od -An -tx1 -j "$2" -N "$3" "$1" | tr -d ' \n'; }
event() {
  local transport=$1 action=$2 reason=${3:-}
  local row
  while IFS= read -r row; do
    [[ $row == *"\"transport\":\"$transport\""* && $row == *"\"action\":\"$action\""* ]] || continue
    [[ -z $reason || $row == *"\"reason\":\"$reason\""* ]] || continue
    return 0
  done < <(grep -oE '\{[^{}]*\}' <<<"$body")
  return 1
}

if [[ $(uname -s) == Darwin ]]; then
  cp "$binary" "$tmp/smolvm-signed"
  codesign --force --sign - --entitlements "$repo/smolvm.entitlements" "$tmp/smolvm-signed" >/dev/null
  binary="$tmp/smolvm-signed"
  export HOME="$tmp" SMOLVM_LIB_DIR="$repo/lib" DYLD_LIBRARY_PATH="$repo/lib"
fi
export XDG_CACHE_HOME="$tmp/cache" XDG_DATA_HOME="$tmp/data" XDG_CONFIG_HOME="$tmp/config"
export SMOLVM_AGENT_ROOTFS="$rootfs" SMOLVM_EGRESS_FLOOR=metadata
export SMOLVM_GUEST_ROLLOUT_HOST_PORT="$rollout_port"
"$binary" serve start -l "127.0.0.1:$api_port" >"$tmp/server.log" 2>&1 &
server_pid=$!
ready=false
for ((i=0; i<100; i++)); do
  if curl -sS --max-time 1 -f "http://127.0.0.1:$api_port/health" >/dev/null 2>&1; then ready=true; break; fi
  kill -0 "$server_pid" 2>/dev/null || fail 'API server exited before readiness'
  sleep 0.1
done
[[ $ready == true ]] || fail 'API server did not become ready'

token=$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')
(
  for index in 1 2; do
    printf '\002broker-ok\n' | nc -l 127.0.0.1 "$broker_port" >"$tmp/prelude.$index"
  done
) &
broker_pid=$!

expect 400 POST '' '{"name":"invalid-rule","egressRules":[{"transport":"tcp","cidr":"bad-cidr","action":"allow"}]}'
expect 400 POST '' '{"name":"tsi-rule","networkBackend":"tsi","egressRules":[{"transport":"tcp","action":"deny"}]}'
expect 200 POST '' "{\"name\":\"source\",\"network\":true,\"allowedCidrs\":[\"1.1.1.1/32\"],\"egressRules\":[
  {\"transport\":\"tcp\",\"cidr\":\"1.1.1.1/32\",\"ports\":{\"start\":80,\"end\":80},\"action\":\"deny\"},
  {\"transport\":\"tcp\",\"cidr\":\"1.1.1.1/32\",\"ports\":{\"start\":443,\"end\":443},\"action\":\"redirect\"},
  {\"transport\":\"tcp\",\"cidr\":\"1.1.1.1/32\",\"ports\":{\"start\":8443,\"end\":8443},\"action\":\"allow\"},
  {\"transport\":\"tcp\",\"cidr\":\"100.96.0.1/32\",\"ports\":{\"start\":$direct_port,\"end\":$direct_port},\"action\":\"allow\"},
  {\"transport\":\"udp\",\"cidr\":\"1.1.1.1/32\",\"ports\":{\"start\":124,\"end\":124},\"action\":\"allow\"}] }"
expect 400 POST '/source/start'
expect 200 POST '/source/start?branchable=true' "{\"egressInterceptor\":{\"address\":\"127.0.0.1:$broker_port\",\"token\":\"$token\",\"mediated\":true}}"

guest source 'printf hello | nc -w 2 1.1.1.1 443'
[[ $body == *'"exitCode":0'* && $body == *'"stdout":"broker-ok\n"'* ]] || fail "source redirect failed: $body"
expect 200 POST '/source/branches' '{"name":"child"}'
guest child 'printf hello | nc -w 2 1.1.1.1 443'
[[ $body == *'"exitCode":0'* && $body == *'"stdout":"broker-ok\n"'* ]] || fail "child redirect failed: $body"
wait "$broker_pid" || fail 'broker failed'
broker_pid=

for index in 1 2; do
  file="$tmp/prelude.$index"
  [[ $(dd if="$file" bs=1 count=8 2>/dev/null) == SMOLMEG2 ]] || fail "broker prelude $index has wrong magic"
  [[ $(hex_at "$file" 8 32) == "$token" ]] || fail "broker prelude $index has wrong token"
  [[ $(hex_at "$file" 72 1) == 04 && $(hex_at "$file" 73 2) == 01bb ]] || fail "broker prelude $index has wrong family or port"
  [[ $(hex_at "$file" 75 4) == 01010101 && $(hex_at "$file" 79 2) == 0005 ]] || fail "broker prelude $index has wrong destination or payload length"
  [[ $(dd if="$file" bs=1 skip=81 count=5 2>/dev/null) == hello ]] || fail "broker prelude $index has wrong first payload"
done
source_id=$(hex_at "$tmp/prelude.1" 40 16)
child_id=$(hex_at "$tmp/prelude.2" 40 16)
[[ $source_id != "$child_id" && $(hex_at "$tmp/prelude.1" 56 16) == 00000000000000000000000000000000 && $(hex_at "$tmp/prelude.2" 56 16) == "$source_id" ]] || fail 'branch identity or lineage is wrong'

guest source 'printf deny | nc -w 1 1.1.1.1 80'
printf 'direct-ok\n' | nc -l 127.0.0.1 "$direct_port" >"$tmp/direct.request" &
direct_pid=$!
guest source "printf direct | nc -w 2 100.96.0.1 $direct_port"
[[ $body == *'"exitCode":0'* && $body == *'"stdout":"direct-ok\n"'* ]] || fail "direct relay failed: $body"
wait "$direct_pid" || fail 'direct listener failed'
direct_pid=
[[ $(<"$tmp/direct.request") == direct ]] || fail 'direct listener received wrong payload'

guest source 'printf udp | nc -u -w 1 1.1.1.1 123'
guest source 'printf udp | nc -u -w 1 1.1.1.1 124'
expect 200 POST '/source/exec' '{"command":["ping","-c","1","-W","1","1.1.1.1"]}'
expect 200 GET '/source/mediation-events'
event tcp redirect broker_decision || fail "missing redirect audit: $body"
event tcp deny || fail "missing TCP denial audit: $body"
event udp deny || fail "missing UDP denial audit: $body"
event icmp deny || fail "missing ICMP denial audit: $body"
event tcp allow static_rule || fail "missing static allow audit: $body"
event udp allow local_policy || fail "missing UDP allow audit: $body"
[[ $body == *"\"machineId\":\"$source_id\""* && $body == *'"destination":"to 1.1.1.1:80"'* ]] || fail "missing identity or denied destination in audit: $body"

expect 200 POST '/child/stop'
expect 200 DELETE '/child'
guest source 'printf hello | nc -w 2 1.1.1.1 443'
expect 200 GET '/source/mediation-events'
event tcp deny broker_unavailable || fail "broker outage did not fail closed: $body"
expect 200 POST '/source/stop'
expect 400 POST '/source/start'
echo 'PASS: mediated egress VM end to end'
