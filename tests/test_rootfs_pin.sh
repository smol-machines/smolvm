#!/usr/bin/env bash
# A machine's live state boots the agent rootfs it was captured with, not the
# one the host has installed since.
#
# A pause or checkpoint freezes processes that keep the agent rootfs they
# booted with mapped; a restore under a rootfs with other bytes at the same
# paths left the agent answering its ping while every program it started died
# with SIGSEGV (a v1.32.4 pause resumed by a build with the Alpine 3.24 rootfs:
# `resume` printed "resumed", every `exec` exited 139). This test swaps the
# installed rootfs between a pause and its resume (a copy with one changed
# file, which is what an upgrade looks like to the guest) and checks that the
# resume boots the pinned copy and the guest still runs programs, that a
# checkpoint restored under the swapped rootfs does the same, and that a cold
# start moves the machine onto the installed rootfs.
#
# Needs a built smolvm with its agent rootfs (target/release/smolvm and
# target/agent-rootfs, or SMOLVM and SMOLVM_AGENT_ROOTFS), and KVM or
# Hypervisor.framework.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SMOLVM="${SMOLVM:-$ROOT/target/release/smolvm}"
ROOTFS_A="${SMOLVM_AGENT_ROOTFS:-$ROOT/target/agent-rootfs}"
export SMOLVM_LIB_DIR="${SMOLVM_LIB_DIR:-$ROOT/lib/$(uname -s | tr A-Z a-z)-$(uname -m)}"
export LD_LIBRARY_PATH="${LD_LIBRARY_PATH:-$SMOLVM_LIB_DIR}"

WORK="$(mktemp -d /tmp/smolvm-pin-XXXX)"
STATE="$WORK/state"
NAME="pin-$$"
export XDG_CACHE_HOME="$WORK/cache"
cleanup() {
    SMOLVM_AGENT_ROOTFS="$ROOTFS_A" "$SMOLVM" --state-dir "$STATE" machine delete --name "$NAME" -f >/dev/null 2>&1 || true
    SMOLVM_AGENT_ROOTFS="$ROOTFS_A" "$SMOLVM" --state-dir "$STATE" machine delete --name "$NAME-restored" -f >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT

pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1" >&2; exit 1; }

sm() { "$SMOLVM" --state-dir "$STATE" "$@"; }
# the digest the engine recorded for the machine's current boot
recorded_digest() {
    sm machine ls --json 2>/dev/null | python3 -c '
import json, sys
for m in json.load(sys.stdin):
    if m.get("name") == sys.argv[1]:
        print(m.get("agent_rootfs_digest") or m.get("agentRootfsDigest") or "")
' "$1"
}

echo "== rootfs B: a copy of A with one changed file (what an upgrade looks like)"
ROOTFS_B="$WORK/rootfs-b"
cp -a "$ROOTFS_A" "$ROOTFS_B"
rm -f "$ROOTFS_B"/.smolvm-ready.* 2>/dev/null || true
echo "upgraded" > "$ROOTFS_B/etc/smolvm-rootfs-test-marker"

echo "== boot on A, start a counter, pause"
export SMOLVM_AGENT_ROOTFS="$ROOTFS_A"
sm machine create --name "$NAME" --cpus 1 --mem 1024 >/dev/null
sm machine start --name "$NAME" >/dev/null
sm machine exec --name "$NAME" -- sh -c 'echo state > /workspace/m; (while :; do date +%s > /workspace/t; sleep 1; done) >/dev/null 2>&1 &'
digest_a="$(recorded_digest "$NAME")"
[ -n "$digest_a" ] || fail "no agent rootfs digest recorded at boot"
pass "boot recorded agent rootfs digest $digest_a"
sm machine checkpoint --name "$NAME" -o "$WORK/live.checkpoint" >/dev/null
sm machine pause --name "$NAME" >/dev/null

echo "== swap the installed rootfs to B, resume"
export SMOLVM_AGENT_ROOTFS="$ROOTFS_B"
sm machine resume --name "$NAME" >/dev/null
out="$(sm machine exec --name "$NAME" -- cat /workspace/m)" || fail "exec after resume failed (exit $?)"
[ "$out" = "state" ] || fail "exec after resume returned '$out'"
t1="$(sm machine exec --name "$NAME" -- cat /workspace/t)"; sleep 2
t2="$(sm machine exec --name "$NAME" -- cat /workspace/t)"
[ "$t2" != "$t1" ] || fail "counter did not advance after resume ($t1 -> $t2)"
pass "resume under a swapped rootfs still runs programs and the counter continues"
[ "$(recorded_digest "$NAME")" = "$digest_a" ] || fail "resume changed the recorded digest to $(recorded_digest "$NAME")"
pass "the resume booted the pinned rootfs A"
# --state-dir keeps the cache under the state dir
ls "$STATE/.cache/smolvm/agent-rootfs-store/${digest_a#sha256:}/sbin/init" >/dev/null || fail "store has no copy of rootfs A"
pass "the carried copy of A was installed in the rootfs store"

echo "== a checkpoint from A restored under B"
sm machine create --name "$NAME-restored" --from "$WORK/live.checkpoint" >/dev/null
sm machine start --name "$NAME-restored" >/dev/null
out="$(sm machine exec --name "$NAME-restored" -- cat /workspace/m)" || fail "exec in restored machine failed (exit $?)"
[ "$out" = "state" ] || fail "restored exec returned '$out'"
[ "$(recorded_digest "$NAME-restored")" = "$digest_a" ] || fail "restored machine runs on $(recorded_digest "$NAME-restored"), not A"
pass "a checkpoint restored under a swapped rootfs boots the rootfs it was captured with"

echo "== a cold start moves onto the installed rootfs B"
sm machine stop --name "$NAME" >/dev/null
sm machine start --name "$NAME" >/dev/null
digest_b="$(recorded_digest "$NAME")"
[ "$digest_b" != "$digest_a" ] || fail "cold start kept digest A"
sm machine exec --name "$NAME" -- true || fail "exec after cold start failed"
pass "a cold start records the installed rootfs $digest_b"

echo "== a pause on B carries B, and resumes under B after A is gone"
sm machine pause --name "$NAME" >/dev/null
rm -rf "$ROOTFS_B/etc/smolvm-rootfs-test-marker"
echo "upgraded again" > "$ROOTFS_B/etc/smolvm-rootfs-test-marker"
sm machine resume --name "$NAME" >/dev/null
sm machine exec --name "$NAME" -- true || fail "exec after second resume failed"
[ "$(recorded_digest "$NAME")" = "$digest_b" ] || fail "second resume runs on $(recorded_digest "$NAME"), not B"
pass "a second swap resumes on the pinned copy of B"

echo "== a golden started on B stays branchable after the installed rootfs moves to C (a fleet roll)"
ROOTFS_C="$WORK/rootfs-c"
cp -a "$ROOTFS_B" "$ROOTFS_C"
echo "rolled" > "$ROOTFS_C/etc/smolvm-rootfs-test-marker"
sm machine stop --name "$NAME" >/dev/null
sm machine start --name "$NAME" --branchable >/dev/null
sm machine exec --name "$NAME" -- sh -c 'echo golden > /workspace/g'
digest_g="$(recorded_digest "$NAME")"
export SMOLVM_AGENT_ROOTFS="$ROOTFS_C"
# a single --name branch waits for no branch point, which a bare machine never announces
clone="$NAME-br"
sm machine branch --from "$NAME" --name "$clone" >/dev/null
out="$(sm machine exec --name "$clone" -- cat /workspace/g)" || fail "exec in branch failed (exit $?)"
[ "$out" = "golden" ] || fail "branch exec returned '$out'"
[ "$(recorded_digest "$clone")" = "$digest_g" ] || fail "branch runs on $(recorded_digest "$clone"), not its golden's $digest_g"
pass "a branch taken after a roll boots its golden's rootfs and runs programs"
sm machine delete --name "$clone" -f >/dev/null

echo "all rootfs pin checks passed"
