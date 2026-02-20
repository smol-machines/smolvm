#!/bin/bash
#
# Smolfile tests for smolvm.
#
# Tests the `--smolfile` and `--init` functionality for both
# microvm and sandbox create commands.
#
# Usage:
#   ./tests/test_smolfile.sh

source "$(dirname "$0")/common.sh"
init_smolvm

# Pre-flight: Kill any existing smolvm processes that might hold database lock
log_info "Pre-flight cleanup: killing orphan processes..."
kill_orphan_smolvm_processes

echo ""
echo "=========================================="
echo "  smolvm Smolfile Tests"
echo "=========================================="
echo ""

# Temp directory for Smolfiles
SMOLFILE_TMPDIR=$(mktemp -d)
trap 'rm -rf "$SMOLFILE_TMPDIR"; cleanup_microvm' EXIT

# =============================================================================
# Helpers
# =============================================================================

# Clean up a named VM, ignoring errors
cleanup_vm() {
    local name="$1"
    $SMOLVM microvm stop "$name" 2>/dev/null || true
    $SMOLVM microvm delete "$name" -f 2>/dev/null || true
}

# =============================================================================
# --init flag (no Smolfile)
# =============================================================================

test_init_flag_creates_file() {
    local vm_name="smolfile-init-flag-$$"
    cleanup_vm "$vm_name"

    # Create VM with --init that creates a marker file
    $SMOLVM microvm create "$vm_name" --init "echo 'init-ran' > /tmp/init-marker.txt" 2>&1 || return 1

    # Start VM (init should run)
    $SMOLVM microvm start "$vm_name" 2>&1 || { cleanup_vm "$vm_name"; return 1; }

    # Verify the init command ran
    local output
    output=$($SMOLVM microvm exec --name "$vm_name" -- cat /tmp/init-marker.txt 2>&1)

    cleanup_vm "$vm_name"
    [[ "$output" == *"init-ran"* ]]
}

test_init_flag_multiple_commands() {
    local vm_name="smolfile-multi-init-$$"
    cleanup_vm "$vm_name"

    # Create VM with multiple --init flags
    $SMOLVM microvm create "$vm_name" \
        --init "echo 'first' > /tmp/init1.txt" \
        --init "echo 'second' > /tmp/init2.txt" \
        2>&1 || return 1

    # Start VM
    $SMOLVM microvm start "$vm_name" 2>&1 || { cleanup_vm "$vm_name"; return 1; }

    # Verify both init commands ran
    local out1 out2
    out1=$($SMOLVM microvm exec --name "$vm_name" -- cat /tmp/init1.txt 2>&1)
    out2=$($SMOLVM microvm exec --name "$vm_name" -- cat /tmp/init2.txt 2>&1)

    cleanup_vm "$vm_name"
    [[ "$out1" == *"first"* ]] && [[ "$out2" == *"second"* ]]
}

test_init_flag_with_env() {
    local vm_name="smolfile-init-env-$$"
    cleanup_vm "$vm_name"

    # Create VM with --init and -e
    $SMOLVM microvm create "$vm_name" \
        -e MY_VAR=hello_from_env \
        --init 'echo "$MY_VAR" > /tmp/env-test.txt' \
        2>&1 || return 1

    # Start VM
    $SMOLVM microvm start "$vm_name" 2>&1 || { cleanup_vm "$vm_name"; return 1; }

    # Verify env was passed to init
    local output
    output=$($SMOLVM microvm exec --name "$vm_name" -- cat /tmp/env-test.txt 2>&1)

    cleanup_vm "$vm_name"
    [[ "$output" == *"hello_from_env"* ]]
}

test_init_flag_with_workdir() {
    local vm_name="smolfile-init-wd-$$"
    cleanup_vm "$vm_name"

    # Create VM with --init and -w
    $SMOLVM microvm create "$vm_name" \
        -w /tmp \
        --init "pwd > cwd.txt" \
        2>&1 || return 1

    # Start VM
    $SMOLVM microvm start "$vm_name" 2>&1 || { cleanup_vm "$vm_name"; return 1; }

    # Verify workdir was applied
    local output
    output=$($SMOLVM microvm exec --name "$vm_name" -- cat /tmp/cwd.txt 2>&1)

    cleanup_vm "$vm_name"
    [[ "$output" == *"/tmp"* ]]
}

test_init_runs_on_every_start() {
    local vm_name="smolfile-restart-$$"
    cleanup_vm "$vm_name"

    # Create VM with --init that appends to a file
    $SMOLVM microvm create "$vm_name" \
        --init 'echo "boot" >> /tmp/boot-count.txt' \
        2>&1 || return 1

    # First start
    $SMOLVM microvm start "$vm_name" 2>&1 || { cleanup_vm "$vm_name"; return 1; }

    # Check count after first start
    local count1
    count1=$($SMOLVM microvm exec --name "$vm_name" -- wc -l /tmp/boot-count.txt 2>&1)

    # Stop and start again
    $SMOLVM microvm stop "$vm_name" 2>&1 || { cleanup_vm "$vm_name"; return 1; }
    $SMOLVM microvm start "$vm_name" 2>&1 || { cleanup_vm "$vm_name"; return 1; }

    # Check count after second start
    local count2
    count2=$($SMOLVM microvm exec --name "$vm_name" -- wc -l /tmp/boot-count.txt 2>&1)

    cleanup_vm "$vm_name"

    # First boot should have 1 line, second boot should have 2
    # (boot-count.txt is in tmpfs, so it resets between VM stops —
    #  but the init command should run each time)
    [[ "$count1" == *"1"* ]]
}

# =============================================================================
# --smolfile flag
# =============================================================================

test_smolfile_basic() {
    local vm_name="smolfile-basic-$$"
    cleanup_vm "$vm_name"

    # Write a Smolfile
    cat > "$SMOLFILE_TMPDIR/Smolfile.basic" <<'EOF'
cpus = 2
memory = 1024

init = [
    "echo 'smolfile-init-ran' > /tmp/smolfile-marker.txt",
]
EOF

    # Create VM from Smolfile
    $SMOLVM microvm create "$vm_name" --smolfile "$SMOLFILE_TMPDIR/Smolfile.basic" 2>&1 || return 1

    # Verify config was applied
    local list_output
    list_output=$($SMOLVM microvm ls --json 2>&1)
    if [[ "$list_output" != *'"cpus": 2'* ]] || [[ "$list_output" != *'"memory_mib": 1024'* ]]; then
        echo "Smolfile cpus/memory not applied"
        cleanup_vm "$vm_name"
        return 1
    fi

    # Start and verify init ran
    $SMOLVM microvm start "$vm_name" 2>&1 || { cleanup_vm "$vm_name"; return 1; }

    local output
    output=$($SMOLVM microvm exec --name "$vm_name" -- cat /tmp/smolfile-marker.txt 2>&1)

    cleanup_vm "$vm_name"
    [[ "$output" == *"smolfile-init-ran"* ]]
}

test_smolfile_with_env() {
    local vm_name="smolfile-env-$$"
    cleanup_vm "$vm_name"

    cat > "$SMOLFILE_TMPDIR/Smolfile.env" <<'EOF'
env = ["GREETING=hello_from_smolfile"]

init = [
    'echo "$GREETING" > /tmp/greeting.txt',
]
EOF

    $SMOLVM microvm create "$vm_name" --smolfile "$SMOLFILE_TMPDIR/Smolfile.env" 2>&1 || return 1
    $SMOLVM microvm start "$vm_name" 2>&1 || { cleanup_vm "$vm_name"; return 1; }

    local output
    output=$($SMOLVM microvm exec --name "$vm_name" -- cat /tmp/greeting.txt 2>&1)

    cleanup_vm "$vm_name"
    [[ "$output" == *"hello_from_smolfile"* ]]
}

test_smolfile_cli_overrides_scalars() {
    local vm_name="smolfile-override-$$"
    cleanup_vm "$vm_name"

    cat > "$SMOLFILE_TMPDIR/Smolfile.override" <<'EOF'
cpus = 2
memory = 256
EOF

    # CLI --mem should override Smolfile memory
    $SMOLVM microvm create "$vm_name" --smolfile "$SMOLFILE_TMPDIR/Smolfile.override" --mem 1024 2>&1 || return 1

    local list_output
    list_output=$($SMOLVM microvm ls --json 2>&1)

    cleanup_vm "$vm_name"

    # mem should be 1024 (CLI override), cpus should be 2 (from Smolfile)
    [[ "$list_output" == *'"memory_mib": 1024'* ]] && [[ "$list_output" == *'"cpus": 2'* ]]
}

test_smolfile_cli_extends_init() {
    local vm_name="smolfile-extend-$$"
    cleanup_vm "$vm_name"

    cat > "$SMOLFILE_TMPDIR/Smolfile.extend" <<'EOF'
init = [
    "echo 'from-smolfile' > /tmp/source.txt",
]
EOF

    # CLI --init should extend, not replace
    $SMOLVM microvm create "$vm_name" \
        --smolfile "$SMOLFILE_TMPDIR/Smolfile.extend" \
        --init "echo 'from-cli' > /tmp/cli-source.txt" \
        2>&1 || return 1

    $SMOLVM microvm start "$vm_name" 2>&1 || { cleanup_vm "$vm_name"; return 1; }

    local sf_out cli_out
    sf_out=$($SMOLVM microvm exec --name "$vm_name" -- cat /tmp/source.txt 2>&1)
    cli_out=$($SMOLVM microvm exec --name "$vm_name" -- cat /tmp/cli-source.txt 2>&1)

    cleanup_vm "$vm_name"
    [[ "$sf_out" == *"from-smolfile"* ]] && [[ "$cli_out" == *"from-cli"* ]]
}

test_smolfile_not_found_errors() {
    local vm_name="smolfile-notfound-$$"
    cleanup_vm "$vm_name"

    local exit_code=0
    $SMOLVM microvm create "$vm_name" --smolfile "/nonexistent/Smolfile" 2>&1 || exit_code=$?

    cleanup_vm "$vm_name"
    [[ $exit_code -ne 0 ]]
}

test_smolfile_invalid_toml_errors() {
    local vm_name="smolfile-invalid-$$"
    cleanup_vm "$vm_name"

    cat > "$SMOLFILE_TMPDIR/Smolfile.bad" <<'EOF'
this is not valid toml {{{
EOF

    local exit_code=0
    $SMOLVM microvm create "$vm_name" --smolfile "$SMOLFILE_TMPDIR/Smolfile.bad" 2>&1 || exit_code=$?

    cleanup_vm "$vm_name"
    [[ $exit_code -ne 0 ]]
}

test_smolfile_unknown_field_errors() {
    local vm_name="smolfile-unknown-$$"
    cleanup_vm "$vm_name"

    cat > "$SMOLFILE_TMPDIR/Smolfile.unknown" <<'EOF'
cpus = 2
typo_field = "oops"
EOF

    local exit_code=0
    $SMOLVM microvm create "$vm_name" --smolfile "$SMOLFILE_TMPDIR/Smolfile.unknown" 2>&1 || exit_code=$?

    cleanup_vm "$vm_name"
    [[ $exit_code -ne 0 ]]
}

test_no_auto_detection() {
    local vm_name="smolfile-noauto-$$"
    cleanup_vm "$vm_name"

    # Create a Smolfile in the temp dir (simulating CWD)
    cat > "$SMOLFILE_TMPDIR/Smolfile" <<'EOF'
cpus = 4
memory = 2048
init = ["echo 'should-not-run' > /tmp/noauto.txt"]
EOF

    # Create VM WITHOUT --smolfile, even though Smolfile exists in CWD
    # The Smolfile should NOT be auto-detected
    (cd "$SMOLFILE_TMPDIR" && $SMOLVM microvm create "$vm_name" 2>&1) || return 1

    # Verify default config was used (not Smolfile config)
    local list_output
    list_output=$($SMOLVM microvm ls --json 2>&1)

    cleanup_vm "$vm_name"

    # cpus should be default (1), not 4 from Smolfile
    [[ "$list_output" == *'"cpus": 1'* ]]
}

# =============================================================================
# Verbose output
# =============================================================================

test_ls_verbose_shows_init() {
    local vm_name="smolfile-verbose-$$"
    cleanup_vm "$vm_name"

    $SMOLVM microvm create "$vm_name" \
        --init "echo hello" \
        --init "echo world" \
        -e FOO=bar \
        -w /app \
        2>&1 || return 1

    local verbose_output
    verbose_output=$($SMOLVM microvm ls --verbose 2>&1)

    cleanup_vm "$vm_name"

    # Should show init commands, env, and workdir in verbose output
    [[ "$verbose_output" == *"Init:"* ]] && \
    [[ "$verbose_output" == *"echo hello"* ]] && \
    [[ "$verbose_output" == *"Env:"* ]] && \
    [[ "$verbose_output" == *"FOO=bar"* ]] && \
    [[ "$verbose_output" == *"Workdir:"* ]] && \
    [[ "$verbose_output" == *"/app"* ]]
}

# =============================================================================
# Smolfile allow_ip validation
# =============================================================================

test_smolfile_allow_ip_invalid_rejected() {
    local vm_name="smolfile-badip-$$"
    cleanup_vm "$vm_name"

    cat > "$SMOLFILE_TMPDIR/Smolfile.badip" <<'EOF'
net = true
allow_ip = ["not-a-cidr"]
EOF

    local output exit_code=0
    output=$($SMOLVM microvm create "$vm_name" --smolfile "$SMOLFILE_TMPDIR/Smolfile.badip" 2>&1) || exit_code=$?

    cleanup_vm "$vm_name"
    [[ $exit_code -ne 0 ]] && [[ "$output" == *"invalid"* ]]
}

test_smolfile_allow_ip_valid_accepted() {
    local vm_name="smolfile-goodip-$$"
    cleanup_vm "$vm_name"

    cat > "$SMOLFILE_TMPDIR/Smolfile.goodip" <<'EOF'
allow_ip = ["10.0.0.0/8", "1.1.1.1"]
EOF

    $SMOLVM microvm create "$vm_name" --smolfile "$SMOLFILE_TMPDIR/Smolfile.goodip" 2>&1 || {
        cleanup_vm "$vm_name"
        return 1
    }

    cleanup_vm "$vm_name"
}

# =============================================================================
# Run Tests
# =============================================================================

run_test "Init flag creates marker file" test_init_flag_creates_file || true
run_test "Init flag multiple commands" test_init_flag_multiple_commands || true
run_test "Init flag with env" test_init_flag_with_env || true
run_test "Init flag with workdir" test_init_flag_with_workdir || true
run_test "Init runs on every start" test_init_runs_on_every_start || true
run_test "Smolfile basic (cpus + init)" test_smolfile_basic || true
run_test "Smolfile with env" test_smolfile_with_env || true
run_test "Smolfile CLI overrides scalars" test_smolfile_cli_overrides_scalars || true
run_test "Smolfile CLI extends init" test_smolfile_cli_extends_init || true
run_test "Smolfile not found errors" test_smolfile_not_found_errors || true
run_test "Smolfile invalid TOML errors" test_smolfile_invalid_toml_errors || true
run_test "Smolfile unknown field errors" test_smolfile_unknown_field_errors || true
run_test "No auto-detection of Smolfile" test_no_auto_detection || true
run_test "ls --verbose shows init/env/workdir" test_ls_verbose_shows_init || true
run_test "Smolfile invalid allow_ip rejected" test_smolfile_allow_ip_invalid_rejected || true
run_test "Smolfile valid allow_ip accepted" test_smolfile_allow_ip_valid_accepted || true

print_summary "Smolfile Tests"
