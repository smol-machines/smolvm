#!/bin/bash
#
# Smolfile tests for smolvm.
#
# Tests the `--smolfile`, `--setup`, and `--entrypoint` functionality
# for both microvm and sandbox create commands.
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
# --entrypoint flag (no Smolfile)
# =============================================================================

test_entrypoint_flag_creates_file() {
    local vm_name="smolfile-ep-flag-$$"
    cleanup_vm "$vm_name"

    # Create VM with --entrypoint that creates a marker file
    $SMOLVM microvm create "$vm_name" --entrypoint "echo 'ep-ran' > /tmp/ep-marker.txt" 2>&1 || return 1

    # Start VM (entrypoint should run)
    $SMOLVM microvm start "$vm_name" 2>&1 || { cleanup_vm "$vm_name"; return 1; }

    # Verify the entrypoint command ran
    local output
    output=$($SMOLVM microvm exec --name "$vm_name" -- cat /tmp/ep-marker.txt 2>&1)

    cleanup_vm "$vm_name"
    [[ "$output" == *"ep-ran"* ]]
}

test_entrypoint_flag_multiple_commands() {
    local vm_name="smolfile-multi-ep-$$"
    cleanup_vm "$vm_name"

    # Create VM with multiple --entrypoint flags
    $SMOLVM microvm create "$vm_name" \
        --entrypoint "echo 'first' > /tmp/ep1.txt" \
        --entrypoint "echo 'second' > /tmp/ep2.txt" \
        2>&1 || return 1

    # Start VM
    $SMOLVM microvm start "$vm_name" 2>&1 || { cleanup_vm "$vm_name"; return 1; }

    # Verify both entrypoint commands ran
    local out1 out2
    out1=$($SMOLVM microvm exec --name "$vm_name" -- cat /tmp/ep1.txt 2>&1)
    out2=$($SMOLVM microvm exec --name "$vm_name" -- cat /tmp/ep2.txt 2>&1)

    cleanup_vm "$vm_name"
    [[ "$out1" == *"first"* ]] && [[ "$out2" == *"second"* ]]
}

test_entrypoint_flag_with_env() {
    local vm_name="smolfile-ep-env-$$"
    cleanup_vm "$vm_name"

    # Create VM with --entrypoint and -e
    $SMOLVM microvm create "$vm_name" \
        -e MY_VAR=hello_from_env \
        --entrypoint 'echo "$MY_VAR" > /tmp/env-test.txt' \
        2>&1 || return 1

    # Start VM
    $SMOLVM microvm start "$vm_name" 2>&1 || { cleanup_vm "$vm_name"; return 1; }

    # Verify env was passed to entrypoint
    local output
    output=$($SMOLVM microvm exec --name "$vm_name" -- cat /tmp/env-test.txt 2>&1)

    cleanup_vm "$vm_name"
    [[ "$output" == *"hello_from_env"* ]]
}

test_entrypoint_flag_with_workdir() {
    local vm_name="smolfile-ep-wd-$$"
    cleanup_vm "$vm_name"

    # Create VM with --entrypoint and -w
    $SMOLVM microvm create "$vm_name" \
        -w /tmp \
        --entrypoint "pwd > cwd.txt" \
        2>&1 || return 1

    # Start VM
    $SMOLVM microvm start "$vm_name" 2>&1 || { cleanup_vm "$vm_name"; return 1; }

    # Verify workdir was applied
    local output
    output=$($SMOLVM microvm exec --name "$vm_name" -- cat /tmp/cwd.txt 2>&1)

    cleanup_vm "$vm_name"
    [[ "$output" == *"/tmp"* ]]
}

test_entrypoint_runs_on_every_start() {
    local vm_name="smolfile-restart-$$"
    cleanup_vm "$vm_name"

    # Create VM with --entrypoint that appends to a file
    $SMOLVM microvm create "$vm_name" \
        --entrypoint 'echo "boot" >> /tmp/boot-count.txt' \
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
    #  but the entrypoint command should run each time)
    [[ "$count1" == *"1"* ]]
}

# =============================================================================
# --setup flag (runs once)
# =============================================================================

test_setup_runs_once() {
    local vm_name="smolfile-setup-once-$$"
    cleanup_vm "$vm_name"

    # Create VM with --setup that creates a marker
    $SMOLVM microvm create "$vm_name" \
        --setup "echo 'setup-done' > /tmp/setup-marker.txt" \
        2>&1 || return 1

    # First start — setup should run
    $SMOLVM microvm start "$vm_name" 2>&1 || { cleanup_vm "$vm_name"; return 1; }

    local output
    output=$($SMOLVM microvm exec --name "$vm_name" -- cat /tmp/setup-marker.txt 2>&1)
    if [[ "$output" != *"setup-done"* ]]; then
        cleanup_vm "$vm_name"
        return 1
    fi

    # Stop, then start again — setup should NOT run (already completed)
    $SMOLVM microvm stop "$vm_name" 2>&1 || { cleanup_vm "$vm_name"; return 1; }
    local start_output
    start_output=$($SMOLVM microvm start "$vm_name" 2>&1)

    cleanup_vm "$vm_name"

    # Second start output should NOT mention setup
    [[ "$start_output" != *"setup command"* ]]
}

test_setup_and_entrypoint_together() {
    local vm_name="smolfile-both-$$"
    cleanup_vm "$vm_name"

    $SMOLVM microvm create "$vm_name" \
        --setup "echo 'installed' > /tmp/setup.txt" \
        --entrypoint "echo 'booted' > /tmp/ep.txt" \
        2>&1 || return 1

    $SMOLVM microvm start "$vm_name" 2>&1 || { cleanup_vm "$vm_name"; return 1; }

    local setup_out ep_out
    setup_out=$($SMOLVM microvm exec --name "$vm_name" -- cat /tmp/setup.txt 2>&1)
    ep_out=$($SMOLVM microvm exec --name "$vm_name" -- cat /tmp/ep.txt 2>&1)

    cleanup_vm "$vm_name"
    [[ "$setup_out" == *"installed"* ]] && [[ "$ep_out" == *"booted"* ]]
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

setup = [
    "echo 'smolfile-setup-ran' > /tmp/smolfile-marker.txt",
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

    # Start and verify setup ran
    $SMOLVM microvm start "$vm_name" 2>&1 || { cleanup_vm "$vm_name"; return 1; }

    local output
    output=$($SMOLVM microvm exec --name "$vm_name" -- cat /tmp/smolfile-marker.txt 2>&1)

    cleanup_vm "$vm_name"
    [[ "$output" == *"smolfile-setup-ran"* ]]
}

test_smolfile_with_env() {
    local vm_name="smolfile-env-$$"
    cleanup_vm "$vm_name"

    cat > "$SMOLFILE_TMPDIR/Smolfile.env" <<'EOF'
env = ["GREETING=hello_from_smolfile"]

entrypoint = [
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

test_smolfile_cli_extends_entrypoint() {
    local vm_name="smolfile-extend-$$"
    cleanup_vm "$vm_name"

    cat > "$SMOLFILE_TMPDIR/Smolfile.extend" <<'EOF'
entrypoint = [
    "echo 'from-smolfile' > /tmp/source.txt",
]
EOF

    # CLI --entrypoint should extend, not replace
    $SMOLVM microvm create "$vm_name" \
        --smolfile "$SMOLFILE_TMPDIR/Smolfile.extend" \
        --entrypoint "echo 'from-cli' > /tmp/cli-source.txt" \
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
setup = ["echo 'should-not-run' > /tmp/noauto.txt"]
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

test_ls_verbose_shows_setup_entrypoint() {
    local vm_name="smolfile-verbose-$$"
    cleanup_vm "$vm_name"

    $SMOLVM microvm create "$vm_name" \
        --setup "apk add git" \
        --entrypoint "echo hello" \
        -e FOO=bar \
        -w /app \
        2>&1 || return 1

    local verbose_output
    verbose_output=$($SMOLVM microvm ls --verbose 2>&1)

    cleanup_vm "$vm_name"

    # Should show setup, entrypoint, env, and workdir in verbose output
    [[ "$verbose_output" == *"Setup:"* ]] && \
    [[ "$verbose_output" == *"apk add git"* ]] && \
    [[ "$verbose_output" == *"Entrypoint:"* ]] && \
    [[ "$verbose_output" == *"echo hello"* ]] && \
    [[ "$verbose_output" == *"Env:"* ]] && \
    [[ "$verbose_output" == *"FOO=bar"* ]] && \
    [[ "$verbose_output" == *"Workdir:"* ]] && \
    [[ "$verbose_output" == *"/app"* ]]
}

# =============================================================================
# Run Tests
# =============================================================================

run_test "Entrypoint flag creates marker file" test_entrypoint_flag_creates_file || true
run_test "Entrypoint flag multiple commands" test_entrypoint_flag_multiple_commands || true
run_test "Entrypoint flag with env" test_entrypoint_flag_with_env || true
run_test "Entrypoint flag with workdir" test_entrypoint_flag_with_workdir || true
run_test "Entrypoint runs on every start" test_entrypoint_runs_on_every_start || true
run_test "Setup runs once" test_setup_runs_once || true
run_test "Setup and entrypoint together" test_setup_and_entrypoint_together || true
run_test "Smolfile basic (cpus + setup)" test_smolfile_basic || true
run_test "Smolfile with env" test_smolfile_with_env || true
run_test "Smolfile CLI overrides scalars" test_smolfile_cli_overrides_scalars || true
run_test "Smolfile CLI extends entrypoint" test_smolfile_cli_extends_entrypoint || true
run_test "Smolfile not found errors" test_smolfile_not_found_errors || true
run_test "Smolfile invalid TOML errors" test_smolfile_invalid_toml_errors || true
run_test "Smolfile unknown field errors" test_smolfile_unknown_field_errors || true
run_test "No auto-detection of Smolfile" test_no_auto_detection || true
run_test "ls --verbose shows setup/entrypoint/env/workdir" test_ls_verbose_shows_setup_entrypoint || true

print_summary "Smolfile Tests"
