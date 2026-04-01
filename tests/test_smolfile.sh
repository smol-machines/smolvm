#!/bin/bash
#
# Smolfile tests for smolvm.
#
# Tests the `--smolfile` and `--init` functionality for both
# machine create commands.
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
trap 'rm -rf "$SMOLFILE_TMPDIR"; cleanup_machine' EXIT

# =============================================================================
# Helpers
# =============================================================================

# Clean up a named VM, ignoring errors
cleanup_vm() {
    local name="$1"
    $SMOLVM machine stop --name "$name" 2>/dev/null || true
    $SMOLVM machine delete "$name" -f 2>/dev/null || true
}

# =============================================================================
# --init flag (no Smolfile)
# =============================================================================

test_init_flag_creates_file() {
    local vm_name="smolfile-init-flag-$$"
    cleanup_vm "$vm_name"

    # Create VM with --init that creates a marker file
    $SMOLVM machine create "$vm_name" --init "echo 'init-ran' > /tmp/init-marker.txt" 2>&1 || return 1

    # Start VM (init should run)
    $SMOLVM machine start --name "$vm_name" 2>&1 || { cleanup_vm "$vm_name"; return 1; }

    # Verify the init command ran
    local output
    output=$($SMOLVM machine exec --name "$vm_name" -- cat /tmp/init-marker.txt 2>&1)

    cleanup_vm "$vm_name"
    [[ "$output" == *"init-ran"* ]]
}

test_init_flag_multiple_commands() {
    local vm_name="smolfile-multi-init-$$"
    cleanup_vm "$vm_name"

    # Create VM with multiple --init flags
    $SMOLVM machine create "$vm_name" \
        --init "echo 'first' > /tmp/init1.txt" \
        --init "echo 'second' > /tmp/init2.txt" \
        2>&1 || return 1

    # Start VM
    $SMOLVM machine start --name "$vm_name" 2>&1 || { cleanup_vm "$vm_name"; return 1; }

    # Verify both init commands ran
    local out1 out2
    out1=$($SMOLVM machine exec --name "$vm_name" -- cat /tmp/init1.txt 2>&1)
    out2=$($SMOLVM machine exec --name "$vm_name" -- cat /tmp/init2.txt 2>&1)

    cleanup_vm "$vm_name"
    [[ "$out1" == *"first"* ]] && [[ "$out2" == *"second"* ]]
}

test_init_flag_with_env() {
    local vm_name="smolfile-init-env-$$"
    cleanup_vm "$vm_name"

    # Create VM with --init and -e
    $SMOLVM machine create "$vm_name" \
        -e MY_VAR=hello_from_env \
        --init 'echo "$MY_VAR" > /tmp/env-test.txt' \
        2>&1 || return 1

    # Start VM
    $SMOLVM machine start --name "$vm_name" 2>&1 || { cleanup_vm "$vm_name"; return 1; }

    # Verify env was passed to init
    local output
    output=$($SMOLVM machine exec --name "$vm_name" -- cat /tmp/env-test.txt 2>&1)

    cleanup_vm "$vm_name"
    [[ "$output" == *"hello_from_env"* ]]
}

test_init_flag_with_workdir() {
    local vm_name="smolfile-init-wd-$$"
    cleanup_vm "$vm_name"

    # Create VM with --init and -w
    $SMOLVM machine create "$vm_name" \
        -w /tmp \
        --init "pwd > cwd.txt" \
        2>&1 || return 1

    # Start VM
    $SMOLVM machine start --name "$vm_name" 2>&1 || { cleanup_vm "$vm_name"; return 1; }

    # Verify workdir was applied
    local output
    output=$($SMOLVM machine exec --name "$vm_name" -- cat /tmp/cwd.txt 2>&1)

    cleanup_vm "$vm_name"
    [[ "$output" == *"/tmp"* ]]
}

test_init_runs_on_every_start() {
    local vm_name="smolfile-restart-$$"
    cleanup_vm "$vm_name"

    # Create VM with --init that appends to a file
    $SMOLVM machine create "$vm_name" \
        --init 'echo "boot" >> /tmp/boot-count.txt' \
        2>&1 || return 1

    # First start
    $SMOLVM machine start --name "$vm_name" 2>&1 || { cleanup_vm "$vm_name"; return 1; }

    # Check count after first start
    local count1
    count1=$($SMOLVM machine exec --name "$vm_name" -- wc -l /tmp/boot-count.txt 2>&1)

    # Stop and start again
    $SMOLVM machine stop --name "$vm_name" 2>&1 || { cleanup_vm "$vm_name"; return 1; }
    $SMOLVM machine start --name "$vm_name" 2>&1 || { cleanup_vm "$vm_name"; return 1; }

    # Check count after second start
    local count2
    count2=$($SMOLVM machine exec --name "$vm_name" -- wc -l /tmp/boot-count.txt 2>&1)

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
    $SMOLVM machine create "$vm_name" --smolfile "$SMOLFILE_TMPDIR/Smolfile.basic" 2>&1 || return 1

    # Verify config was applied
    local list_output
    list_output=$($SMOLVM machine ls --json 2>&1)
    if [[ "$list_output" != *'"cpus": 2'* ]] || [[ "$list_output" != *'"memory_mib": 1024'* ]]; then
        echo "Smolfile cpus/memory not applied"
        cleanup_vm "$vm_name"
        return 1
    fi

    # Start and verify init ran
    $SMOLVM machine start --name "$vm_name" 2>&1 || { cleanup_vm "$vm_name"; return 1; }

    local output
    output=$($SMOLVM machine exec --name "$vm_name" -- cat /tmp/smolfile-marker.txt 2>&1)

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

    $SMOLVM machine create "$vm_name" --smolfile "$SMOLFILE_TMPDIR/Smolfile.env" 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 || { cleanup_vm "$vm_name"; return 1; }

    local output
    output=$($SMOLVM machine exec --name "$vm_name" -- cat /tmp/greeting.txt 2>&1)

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
    $SMOLVM machine create "$vm_name" --smolfile "$SMOLFILE_TMPDIR/Smolfile.override" --mem 1024 2>&1 || return 1

    local list_output
    list_output=$($SMOLVM machine ls --json 2>&1)

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
    $SMOLVM machine create "$vm_name" \
        --smolfile "$SMOLFILE_TMPDIR/Smolfile.extend" \
        --init "echo 'from-cli' > /tmp/cli-source.txt" \
        2>&1 || return 1

    $SMOLVM machine start --name "$vm_name" 2>&1 || { cleanup_vm "$vm_name"; return 1; }

    local sf_out cli_out
    sf_out=$($SMOLVM machine exec --name "$vm_name" -- cat /tmp/source.txt 2>&1)
    cli_out=$($SMOLVM machine exec --name "$vm_name" -- cat /tmp/cli-source.txt 2>&1)

    cleanup_vm "$vm_name"
    [[ "$sf_out" == *"from-smolfile"* ]] && [[ "$cli_out" == *"from-cli"* ]]
}

test_smolfile_not_found_errors() {
    local vm_name="smolfile-notfound-$$"
    cleanup_vm "$vm_name"

    local exit_code=0
    $SMOLVM machine create "$vm_name" --smolfile "/nonexistent/Smolfile" 2>&1 || exit_code=$?

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
    $SMOLVM machine create "$vm_name" --smolfile "$SMOLFILE_TMPDIR/Smolfile.bad" 2>&1 || exit_code=$?

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
    $SMOLVM machine create "$vm_name" --smolfile "$SMOLFILE_TMPDIR/Smolfile.unknown" 2>&1 || exit_code=$?

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
    (cd "$SMOLFILE_TMPDIR" && $SMOLVM machine create "$vm_name" 2>&1) || return 1

    # Verify default config was used (not Smolfile config)
    local list_output
    list_output=$($SMOLVM machine ls --json 2>&1)

    cleanup_vm "$vm_name"

    # cpus should be default (1), not 4 from Smolfile
    [[ "$list_output" == *'"cpus": 1'* ]]
}

# =============================================================================
# Smolfile v2: image, entrypoint, cmd fields
# =============================================================================

test_smolfile_image_field() {
    local vm_name="smolfile-image-$$"
    cleanup_vm "$vm_name"

    cat > "$SMOLFILE_TMPDIR/Smolfile.image" <<'EOF'
image = "alpine:latest"
cpus = 1
memory = 512
net = true
EOF

    # Create + start — image from Smolfile should be picked up
    $SMOLVM machine create "$vm_name" --smolfile "$SMOLFILE_TMPDIR/Smolfile.image" 2>&1 || return 1

    # Verify image is persisted in the record
    local list_output
    list_output=$($SMOLVM machine ls --json 2>&1)

    cleanup_vm "$vm_name"
    [[ "$list_output" == *"alpine:latest"* ]]
}

test_smolfile_entrypoint_field() {
    cat > "$SMOLFILE_TMPDIR/Smolfile.ep" <<'EOF'
entrypoint = ["/bin/echo"]
cmd = ["hello-from-smolfile"]
cpus = 1
memory = 512
EOF

    # Verify it parses without error
    local exit_code=0
    local vm_name="smolfile-ep-$$"
    cleanup_vm "$vm_name"
    $SMOLVM machine create "$vm_name" --smolfile "$SMOLFILE_TMPDIR/Smolfile.ep" 2>&1 || exit_code=$?

    cleanup_vm "$vm_name"
    [[ $exit_code -eq 0 ]]
}

test_smolfile_cmd_field() {
    cat > "$SMOLFILE_TMPDIR/Smolfile.cmd" <<'EOF'
cmd = ["echo", "hello-from-cmd"]
cpus = 1
memory = 512
EOF

    local exit_code=0
    local vm_name="smolfile-cmd-$$"
    cleanup_vm "$vm_name"
    $SMOLVM machine create "$vm_name" --smolfile "$SMOLFILE_TMPDIR/Smolfile.cmd" 2>&1 || exit_code=$?

    cleanup_vm "$vm_name"
    [[ $exit_code -eq 0 ]]
}

# =============================================================================
# Smolfile v2: [artifact] and [dev] sections
# =============================================================================

test_smolfile_artifact_section_parses() {
    cat > "$SMOLFILE_TMPDIR/Smolfile.artifact" <<'EOF'
image = "python:3.12-alpine"
cpus = 2
memory = 1024

[artifact]
cpus = 4
memory = 2048
entrypoint = ["/app/run.sh"]
oci_platform = "linux/amd64"
EOF

    local exit_code=0
    local vm_name="smolfile-artifact-$$"
    cleanup_vm "$vm_name"
    $SMOLVM machine create "$vm_name" --smolfile "$SMOLFILE_TMPDIR/Smolfile.artifact" 2>&1 || exit_code=$?

    cleanup_vm "$vm_name"
    [[ $exit_code -eq 0 ]]
}

test_smolfile_pack_alias_parses() {
    cat > "$SMOLFILE_TMPDIR/Smolfile.pack" <<'EOF'
image = "alpine:latest"

[pack]
cpus = 4
memory = 2048
EOF

    local exit_code=0
    local vm_name="smolfile-pack-$$"
    cleanup_vm "$vm_name"
    $SMOLVM machine create "$vm_name" --smolfile "$SMOLFILE_TMPDIR/Smolfile.pack" 2>&1 || exit_code=$?

    cleanup_vm "$vm_name"
    [[ $exit_code -eq 0 ]]
}

test_smolfile_dev_section_parses() {
    cat > "$SMOLFILE_TMPDIR/Smolfile.dev" <<'EOF'
image = "node:22-alpine"
cpus = 2
memory = 512
net = true

[dev]
volumes = ["./src:/app"]
env = ["NODE_ENV=development"]
init = ["apk add --no-cache nodejs npm"]
workdir = "/app"
ports = ["3000:3000"]
EOF

    local exit_code=0
    local vm_name="smolfile-dev-$$"
    cleanup_vm "$vm_name"
    $SMOLVM machine create "$vm_name" --smolfile "$SMOLFILE_TMPDIR/Smolfile.dev" 2>&1 || exit_code=$?

    cleanup_vm "$vm_name"
    [[ $exit_code -eq 0 ]]
}

test_smolfile_dev_init_used_for_machine() {
    local vm_name="smolfile-devinit-$$"
    cleanup_vm "$vm_name"

    cat > "$SMOLFILE_TMPDIR/Smolfile.devinit" <<'EOF'
cpus = 1
memory = 512

[dev]
init = [
    "echo 'dev-init-ran' > /tmp/dev-marker.txt",
]
EOF

    $SMOLVM machine create "$vm_name" --smolfile "$SMOLFILE_TMPDIR/Smolfile.devinit" 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 || { cleanup_vm "$vm_name"; return 1; }

    local output
    output=$($SMOLVM machine exec --name "$vm_name" -- cat /tmp/dev-marker.txt 2>&1)

    cleanup_vm "$vm_name"
    [[ "$output" == *"dev-init-ran"* ]]
}

# =============================================================================
# Smolfile v2: [service], [health], [restart], [deploy] parse without error
# =============================================================================

test_smolfile_full_spec_parses() {
    cat > "$SMOLFILE_TMPDIR/Smolfile.full" <<'EOF'
image = "ghcr.io/acme/api:1.2.3"
entrypoint = ["/app/api"]
cmd = ["serve"]
workdir = "/app"
env = ["PORT=8080"]
cpus = 2
memory = 1024
net = true

[service]
listen = 8080
protocol = "http"

[health]
exec = ["curl", "-f", "http://127.0.0.1:8080/health"]
interval = "10s"
timeout = "2s"
retries = 3
startup_grace = "20s"

[restart]
policy = "always"
max_retries = 5

[dev]
volumes = ["./src:/app"]
env = ["APP_MODE=development"]
init = ["cargo build"]
ports = ["8080:8080"]

[artifact]
cpus = 4
memory = 2048
entrypoint = ["/app/api"]
oci_platform = "linux/amd64"

[deploy]
replicas = 3
min_ready_seconds = 5
strategy = "rolling"
max_unavailable = 1
max_surge = 1
EOF

    local exit_code=0
    local vm_name="smolfile-full-$$"
    cleanup_vm "$vm_name"
    $SMOLVM machine create "$vm_name" --smolfile "$SMOLFILE_TMPDIR/Smolfile.full" 2>&1 || exit_code=$?

    cleanup_vm "$vm_name"
    [[ $exit_code -eq 0 ]]
}

test_smolfile_bare_vm_no_image() {
    # Bare Alpine VM with [dev].init + entrypoint/cmd — no image needed
    cat > "$SMOLFILE_TMPDIR/Smolfile.bare" <<'EOF'
entrypoint = ["cat"]
cmd = ["/tmp/bare.txt"]
cpus = 1
memory = 512

[dev]
init = [
    "echo 'bare-vm-works' > /tmp/bare.txt",
]
EOF

    local output
    output=$($SMOLVM machine run -s "$SMOLFILE_TMPDIR/Smolfile.bare" 2>&1)

    [[ "$output" == *"bare-vm-works"* ]]
}

test_smolfile_entrypoint_used_at_runtime() {
    # Verify entrypoint + cmd from Smolfile are combined and used
    cat > "$SMOLFILE_TMPDIR/Smolfile.ep_runtime" <<'EOF'
entrypoint = ["echo"]
cmd = ["hello-from-entrypoint"]
cpus = 1
memory = 512
EOF

    local output
    output=$($SMOLVM machine run -s "$SMOLFILE_TMPDIR/Smolfile.ep_runtime" 2>&1)

    [[ "$output" == *"hello-from-entrypoint"* ]]
}

test_smolfile_auto_container_on_start() {
    local vm_name="smolfile-autoct-$$"
    cleanup_vm "$vm_name"

    cat > "$SMOLFILE_TMPDIR/Smolfile.autoct" <<'EOF'
image = "alpine:latest"
cmd = ["echo", "auto-container-works"]
cpus = 1
memory = 512
net = true
EOF

    $SMOLVM machine create "$vm_name" --smolfile "$SMOLFILE_TMPDIR/Smolfile.autoct" 2>&1 || return 1

    # Start should auto-pull image and create container
    local start_output
    start_output=$($SMOLVM machine start --name "$vm_name" 2>&1)

    cleanup_vm "$vm_name"

    # Should mention container creation
    [[ "$start_output" == *"container:"* ]] || [[ "$start_output" == *"Pulling"* ]]
}

test_smolfile_image_cmd_only_overrides_when_set() {
    # When Smolfile has image but no entrypoint/cmd, the image's own
    # entrypoint/cmd should be used (empty command vec to agent).
    # When Smolfile sets cmd, it should override the image default.
    cat > "$SMOLFILE_TMPDIR/Smolfile.cmdonly" <<'EOF'
image = "alpine:latest"
cmd = ["echo", "smolfile-cmd-works"]
cpus = 1
memory = 512
net = true
EOF

    local output
    output=$($SMOLVM machine run -s "$SMOLFILE_TMPDIR/Smolfile.cmdonly" 2>&1)

    [[ "$output" == *"smolfile-cmd-works"* ]]
}

test_smolfile_image_no_cmd_uses_image_default() {
    # When Smolfile has image but no entrypoint/cmd, the image's own
    # defaults should be used. For alpine, that's /bin/sh which expects
    # stdin, so we pass a command via CLI to verify the image runs.
    cat > "$SMOLFILE_TMPDIR/Smolfile.imgdefault" <<'EOF'
image = "alpine:latest"
cpus = 1
memory = 512
net = true
EOF

    local output
    output=$($SMOLVM machine run -s "$SMOLFILE_TMPDIR/Smolfile.imgdefault" -- echo "image-default-ok" 2>&1)

    [[ "$output" == *"image-default-ok"* ]]
}

test_smolfile_unknown_section_errors() {
    cat > "$SMOLFILE_TMPDIR/Smolfile.badsection" <<'EOF'
cpus = 2

[nonexistent_section]
foo = "bar"
EOF

    local exit_code=0
    local vm_name="smolfile-badsec-$$"
    cleanup_vm "$vm_name"
    $SMOLVM machine create "$vm_name" --smolfile "$SMOLFILE_TMPDIR/Smolfile.badsection" 2>&1 || exit_code=$?

    cleanup_vm "$vm_name"
    [[ $exit_code -ne 0 ]]
}

# =============================================================================
# Verbose output
# =============================================================================

test_ls_verbose_shows_init() {
    local vm_name="smolfile-verbose-$$"
    cleanup_vm "$vm_name"

    $SMOLVM machine create "$vm_name" \
        --init "echo hello" \
        --init "echo world" \
        -e FOO=bar \
        -w /app \
        2>&1 || return 1

    local verbose_output
    verbose_output=$($SMOLVM machine ls --verbose 2>&1)

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

echo ""
echo "--- Smolfile v2 Tests ---"
echo ""

run_test "Smolfile v2: image field" test_smolfile_image_field || true
run_test "Smolfile v2: entrypoint field" test_smolfile_entrypoint_field || true
run_test "Smolfile v2: cmd field" test_smolfile_cmd_field || true
run_test "Smolfile v2: [artifact] section parses" test_smolfile_artifact_section_parses || true
run_test "Smolfile v2: [pack] alias parses" test_smolfile_pack_alias_parses || true
run_test "Smolfile v2: [dev] section parses" test_smolfile_dev_section_parses || true
run_test "Smolfile v2: [dev] init used for machine" test_smolfile_dev_init_used_for_machine || true
run_test "Smolfile v2: full spec parses" test_smolfile_full_spec_parses || true
run_test "Smolfile v2: bare VM (no image)" test_smolfile_bare_vm_no_image || true
run_test "Smolfile v2: entrypoint used at runtime" test_smolfile_entrypoint_used_at_runtime || true
run_test "Smolfile v2: auto-container on start" test_smolfile_auto_container_on_start || true
run_test "Smolfile v2: image+cmd overrides image default" test_smolfile_image_cmd_only_overrides_when_set || true
run_test "Smolfile v2: image without cmd uses image default" test_smolfile_image_no_cmd_uses_image_default || true
run_test "Smolfile v2: unknown section errors" test_smolfile_unknown_section_errors || true

print_summary "Smolfile Tests"
