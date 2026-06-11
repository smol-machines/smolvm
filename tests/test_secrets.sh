#!/bin/bash
#
# End-to-end tests for host-side secret references.
#
# smolvm stores no secret material itself: a `[secrets]` entry references a
# value that already lives on the host (here, a host environment variable). The
# security INVARIANT is that the referenced PLAINTEXT is resolved on the host at
# launch time and reaches the guest workload's environment, but NEVER persists
# in the machine's DB record or a portable `.smolmachine` pack — only the opaque
# ref does. These tests boot real VMs and verify both halves end to end (the
# unit tests cover the resolution logic; only an e2e run can prove the plaintext
# actually crosses to the guest and actually stays out of the persisted
# artifacts).
#
# Usage:
#   ./tests/test_secrets.sh

source "$(dirname "$0")/common.sh"
init_smolvm

log_info "Pre-flight cleanup: killing orphan processes..."
kill_orphan_smolvm_processes

echo ""
echo "=========================================="
echo "  smolvm Secret Reference E2E Tests"
echo "=========================================="
echo ""

SECRET_TMPDIR=$(mktemp -d)
# Unique name + value per run so the value is an unambiguous needle to grep for
# in the DB / pack, and parallel runs never collide.
SECRET_NAME="E2ESECRET_$$"
SECRET_VALUE="plaintext-needle-$$-do-not-leak"
# The host env var the ref points at. smolvm is launched as a child of this
# shell, so exporting it puts the value in smolvm's own environment, where the
# `from_env` ref resolves it at launch time. The value is never persisted.
export "$SECRET_NAME=$SECRET_VALUE"

cleanup_vm() {
    local name="$1"
    $SMOLVM machine stop --name "$name" 2>/dev/null || true
    $SMOLVM machine delete --name "$name" -f 2>/dev/null || true
}

cleanup_secrets_test() {
    rm -rf "$SECRET_TMPDIR"
    cleanup_machine
}
trap 'cleanup_secrets_test' EXIT

# Write a Smolfile that references the stored secret as a guest env var of the
# same name. `extra` is appended verbatim (e.g. an `init = [...]` line).
write_smolfile() {
    local path="$1"
    local extra="${2:-}"
    cat > "$path" <<EOF
cpus = 1
memory = 512
$extra

[secrets]
$SECRET_NAME = { from_env = "$SECRET_NAME" }
EOF
}

# =============================================================================
# 1. Plaintext reaches the guest env at exec time.
# =============================================================================
test_secret_reaches_guest_exec() {
    local vm="secret-exec-$$"
    cleanup_vm "$vm"
    write_smolfile "$SECRET_TMPDIR/Smolfile.exec"
    $SMOLVM machine create --name "$vm" --smolfile "$SECRET_TMPDIR/Smolfile.exec" 2>&1 || return 1
    $SMOLVM machine start --name "$vm" 2>&1 || { cleanup_vm "$vm"; return 1; }
    # `env` (busybox) prints the whole environment — robust across rootfs builds.
    local output
    output=$($SMOLVM machine exec --name "$vm" -- env 2>&1)
    cleanup_vm "$vm"
    [[ "$output" == *"$SECRET_NAME=$SECRET_VALUE"* ]]
}

# =============================================================================
# 2. Plaintext reaches the guest at init time too.
# =============================================================================
test_secret_reaches_guest_init() {
    local vm="secret-init-$$"
    cleanup_vm "$vm"
    write_smolfile "$SECRET_TMPDIR/Smolfile.init" \
        "init = [\"printenv $SECRET_NAME > /tmp/secret-out.txt\"]"
    $SMOLVM machine create --name "$vm" --smolfile "$SECRET_TMPDIR/Smolfile.init" 2>&1 || return 1
    $SMOLVM machine start --name "$vm" 2>&1 || { cleanup_vm "$vm"; return 1; }
    local output
    output=$($SMOLVM machine exec --name "$vm" -- cat /tmp/secret-out.txt 2>&1)
    cleanup_vm "$vm"
    [[ "$output" == *"$SECRET_VALUE"* ]]
}

# =============================================================================
# 3. INVARIANT: the plaintext never lands in the persisted DB record.
# =============================================================================
test_plaintext_not_in_db() {
    local vm="secret-nodb-$$"
    cleanup_vm "$vm"
    write_smolfile "$SECRET_TMPDIR/Smolfile.nodb"
    $SMOLVM machine create --name "$vm" --smolfile "$SECRET_TMPDIR/Smolfile.nodb" 2>&1 || return 1
    # Start too, so any persist-on-run path also executes.
    $SMOLVM machine start --name "$vm" 2>&1 || { cleanup_vm "$vm"; return 1; }
    # The ref NAME may legitimately appear in the record; the VALUE must not.
    local db leaked=0
    db=$(find "$HOME" -name 'smolvm.db' -path '*smolvm/server/*' 2>/dev/null | head -1)
    if [[ -n "$db" ]] && strings "$db" 2>/dev/null | grep -qF "$SECRET_VALUE"; then
        leaked=1
        log_info "LEAK: plaintext secret found in DB at $db"
    fi
    cleanup_vm "$vm"
    [[ "$leaked" -eq 0 ]]
}

# =============================================================================
# 4. INVARIANT: the plaintext never lands in a portable .smolmachine pack.
# =============================================================================
test_plaintext_not_in_pack() {
    local vm="secret-nopack-$$"
    cleanup_vm "$vm"
    write_smolfile "$SECRET_TMPDIR/Smolfile.nopack"
    $SMOLVM machine create --name "$vm" --smolfile "$SECRET_TMPDIR/Smolfile.nopack" 2>&1 || return 1
    $SMOLVM machine start --name "$vm" 2>&1 || { cleanup_vm "$vm"; return 1; }
    $SMOLVM machine stop --name "$vm" 2>&1 || true
    local pack="$SECRET_TMPDIR/out.smolmachine"
    $SMOLVM pack create --from-vm "$vm" -o "$pack" 2>&1 || { cleanup_vm "$vm"; return 1; }
    local leaked=0
    if strings "$pack" 2>/dev/null | grep -qF "$SECRET_VALUE"; then
        leaked=1
        log_info "LEAK: plaintext secret found in pack $pack"
    fi
    cleanup_vm "$vm"
    [[ -f "$pack" ]] && [[ "$leaked" -eq 0 ]]
}

# =============================================================================
# 5. The secret re-resolves on restart (refs persist, plaintext does not).
# =============================================================================
test_secret_reresolves_after_restart() {
    local vm="secret-restart-$$"
    cleanup_vm "$vm"
    write_smolfile "$SECRET_TMPDIR/Smolfile.restart"
    $SMOLVM machine create --name "$vm" --smolfile "$SECRET_TMPDIR/Smolfile.restart" 2>&1 || return 1
    $SMOLVM machine start --name "$vm" 2>&1 || { cleanup_vm "$vm"; return 1; }
    $SMOLVM machine stop --name "$vm" 2>&1 || true
    $SMOLVM machine start --name "$vm" 2>&1 || { cleanup_vm "$vm"; return 1; }
    local output
    output=$($SMOLVM machine exec --name "$vm" -- env 2>&1)
    cleanup_vm "$vm"
    [[ "$output" == *"$SECRET_NAME=$SECRET_VALUE"* ]]
}

# =============================================================================
# Run
# =============================================================================
log_info "Test secret exported as host env var '$SECRET_NAME' (from_env source)"

run_test "Secret plaintext reaches guest via exec" test_secret_reaches_guest_exec || true
run_test "Secret plaintext reaches guest via init" test_secret_reaches_guest_init || true
run_test "INVARIANT: plaintext never in DB record" test_plaintext_not_in_db || true
run_test "INVARIANT: plaintext never in .smolmachine pack" test_plaintext_not_in_pack || true
run_test "Secret re-resolves after restart" test_secret_reresolves_after_restart || true

print_summary "Secret Reference E2E Tests"
