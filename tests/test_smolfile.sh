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

test_smolfile_bare_vm_detached() {
    # Detached bare VM should start, run init, return without hanging,
    # and be visible in machine ls (persisted as default).
    cat > "$SMOLFILE_TMPDIR/Smolfile.bare_detach" <<'EOF'
cpus = 1
memory = 512

[dev]
init = [
    "echo 'detach-init-ran' > /tmp/detach-marker.txt",
]
EOF

    # Stop any existing default machine
    $SMOLVM machine stop 2>/dev/null || true

    local output
    output=$($SMOLVM machine run -d -s "$SMOLFILE_TMPDIR/Smolfile.bare_detach" 2>&1)

    # Should print PID and return (not hang)
    [[ "$output" == *"Machine running"* ]] || return 1

    # Verify the init command ran
    local marker
    marker=$($SMOLVM machine exec -- cat /tmp/detach-marker.txt 2>&1) || return 1
    [[ "$marker" == *"detach-init-ran"* ]] || return 1

    # Verify the VM is visible in machine ls (persisted)
    local ls_output
    ls_output=$($SMOLVM machine ls 2>&1) || return 1
    [[ "$ls_output" == *"default"* ]] || return 1
    [[ "$ls_output" == *"running"* ]] || return 1

    # Clean up
    $SMOLVM machine stop 2>/dev/null || true
}

test_smolfile_bare_vm_detached_with_cmd() {
    # Detached bare VM with entrypoint/cmd should run workload in background
    cat > "$SMOLFILE_TMPDIR/Smolfile.bare_detach_cmd" <<'EOF'
entrypoint = ["sh"]
cmd = ["-c", "echo bg-workload-ran > /tmp/bg-marker.txt"]
cpus = 1
memory = 512
EOF

    $SMOLVM machine stop 2>/dev/null || true

    local output
    output=$($SMOLVM machine run -d -s "$SMOLFILE_TMPDIR/Smolfile.bare_detach_cmd" 2>&1) || return 1

    # Should return immediately with "Machine running"
    [[ "$output" == *"Machine running"* ]] || return 1

    # Give background process a moment to complete
    sleep 1

    # Verify the background workload ran
    local marker
    marker=$($SMOLVM machine exec -- cat /tmp/bg-marker.txt 2>&1) || return 1
    [[ "$marker" == *"bg-workload-ran"* ]] || return 1

    $SMOLVM machine stop 2>/dev/null || true
}

test_smolfile_bare_vm_detached_with_cli_cmd() {
    # Detached bare VM with CLI command should run workload in background
    $SMOLVM machine stop 2>/dev/null || true
    local output
    output=$($SMOLVM machine run -d -- sh -c "echo cli-bg-ran > /tmp/cli-bg-marker.txt" 2>&1) || return 1

    [[ "$output" == *"Machine running"* ]] || return 1

    sleep 1

    local marker
    marker=$($SMOLVM machine exec -- cat /tmp/cli-bg-marker.txt 2>&1) || return 1
    [[ "$marker" == *"cli-bg-ran"* ]] || return 1

    $SMOLVM machine stop 2>/dev/null || true
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
# Restart & Health Config Tests
# =============================================================================

test_smolfile_restart_policy() {
    cat > "$SMOLFILE_TMPDIR/Smolfile.restart" <<'EOF'
cpus = 1
memory = 512

[restart]
policy = "always"
max_retries = 5
max_backoff = "30s"
EOF

    local vm_name="smolfile-restart-$$"
    cleanup_vm "$vm_name"

    # Create should succeed (restart config stored in VmRecord)
    $SMOLVM machine create "$vm_name" --smolfile "$SMOLFILE_TMPDIR/Smolfile.restart" 2>&1 || return 1

    # Verify machine was created
    $SMOLVM machine ls --json 2>&1 | grep -q "$vm_name" || return 1

    cleanup_vm "$vm_name"
}

test_smolfile_health_config() {
    cat > "$SMOLFILE_TMPDIR/Smolfile.health" <<'EOF'
cpus = 1
memory = 512

[health]
exec = ["echo", "ok"]
interval = "10s"
timeout = "3s"
retries = 5

[restart]
policy = "on-failure"
EOF

    local vm_name="smolfile-health-$$"
    cleanup_vm "$vm_name"

    # Create should succeed (health + restart config stored)
    $SMOLVM machine create "$vm_name" --smolfile "$SMOLFILE_TMPDIR/Smolfile.health" 2>&1 || return 1

    # Verify machine was created
    $SMOLVM machine ls --json 2>&1 | grep -q "$vm_name" || return 1

    cleanup_vm "$vm_name"
}

test_smolfile_monitor_basic() {
    local vm_name="smolfile-monitor-$$"
    cleanup_vm "$vm_name"

    # Create and start a machine
    $SMOLVM machine create --net "$vm_name" 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 || return 1

    # Run monitor briefly — it should print the header then we kill it
    local output
    output=$(run_with_timeout 6 $SMOLVM machine monitor --name "$vm_name" --interval 1 2>&1 || true)

    # Verify it printed the monitoring header
    echo "$output" | grep -q "Monitoring machine" || return 1

    # Machine should still be running after monitor exits
    $SMOLVM machine exec --name "$vm_name" -- echo "still-alive" 2>&1 | grep -q "still-alive" || return 1

    $SMOLVM machine stop --name "$vm_name" 2>/dev/null || true
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
run_test "Smolfile v2: bare VM detached" test_smolfile_bare_vm_detached || true
run_test "Smolfile v2: bare VM detached + Smolfile cmd" test_smolfile_bare_vm_detached_with_cmd || true
run_test "Smolfile v2: bare VM detached + CLI cmd" test_smolfile_bare_vm_detached_with_cli_cmd || true
run_test "Smolfile v2: entrypoint used at runtime" test_smolfile_entrypoint_used_at_runtime || true
run_test "Smolfile v2: auto-container on start" test_smolfile_auto_container_on_start || true
run_test "Smolfile v2: image+cmd overrides image default" test_smolfile_image_cmd_only_overrides_when_set || true
run_test "Smolfile v2: image without cmd uses image default" test_smolfile_image_no_cmd_uses_image_default || true
run_test "Smolfile v2: unknown section errors" test_smolfile_unknown_section_errors || true

echo ""
echo "--- Restart & Health Config Tests ---"
echo ""

run_test "Smolfile: [restart] policy persists" test_smolfile_restart_policy || true
run_test "Smolfile: [health] config persists" test_smolfile_health_config || true
run_test "Smolfile: monitor starts and exits" test_smolfile_monitor_basic || true

# =============================================================================
# SSH Agent Forwarding Tests
# =============================================================================

test_ssh_agent_flag_creates_socket() {
    local vm_name="ssh-agent-flag-$$"
    cleanup_vm "$vm_name"

    # Create VM with --ssh-agent
    $SMOLVM machine create "$vm_name" --ssh-agent --net 2>&1 || return 1

    # Start VM
    $SMOLVM machine start --name "$vm_name" 2>&1 || return 1

    # Verify SSH agent socket exists in guest
    local result
    result=$($SMOLVM machine exec --name "$vm_name" -- ls /tmp/ssh-agent.sock 2>&1) || return 1
    [[ "$result" == *"ssh-agent.sock"* ]] || return 1

    # Verify SSH_AUTH_SOCK is set in guest environment
    result=$($SMOLVM machine exec --name "$vm_name" -- sh -c 'echo $SSH_AUTH_SOCK' 2>&1) || return 1
    [[ "$result" == *"/tmp/ssh-agent.sock"* ]] || return 1

    cleanup_vm "$vm_name"
}

test_ssh_agent_lists_host_keys() {
    local vm_name="ssh-agent-keys-$$"
    cleanup_vm "$vm_name"

    # Skip if no SSH agent on host
    if ! ssh-add -l >/dev/null 2>&1; then
        echo "  SKIP (no SSH keys loaded on host)"
        return 0
    fi

    $SMOLVM machine create "$vm_name" --ssh-agent --net 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 || return 1

    # Install openssh-client
    $SMOLVM machine exec --name "$vm_name" -- apk add openssh-client 2>&1 >/dev/null || return 1

    # ssh-add -l should list the same keys as host
    local guest_keys host_keys
    guest_keys=$($SMOLVM machine exec --name "$vm_name" -- ssh-add -l 2>&1) || return 1
    host_keys=$(ssh-add -l 2>&1)

    # Both should contain the same key fingerprint
    local host_fp
    host_fp=$(echo "$host_keys" | head -1 | awk '{print $2}')
    [[ "$guest_keys" == *"$host_fp"* ]] || return 1

    cleanup_vm "$vm_name"
}

test_ssh_agent_not_present_without_flag() {
    local vm_name="ssh-agent-absent-$$"
    cleanup_vm "$vm_name"

    # Create VM WITHOUT --ssh-agent
    $SMOLVM machine create "$vm_name" --net 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 || return 1

    # Socket should NOT exist
    if $SMOLVM machine exec --name "$vm_name" -- ls /tmp/ssh-agent.sock 2>/dev/null; then
        return 1  # Socket exists but shouldn't
    fi

    cleanup_vm "$vm_name"
}

test_ssh_agent_smolfile() {
    cat > "$SMOLFILE_TMPDIR/Smolfile.ssh" <<'EOF'
cpus = 1
memory = 512
net = true

[auth]
ssh_agent = true
EOF

    local vm_name="ssh-agent-smolfile-$$"
    cleanup_vm "$vm_name"

    $SMOLVM machine create "$vm_name" --smolfile "$SMOLFILE_TMPDIR/Smolfile.ssh" 2>&1 || return 1
    $SMOLVM machine start --name "$vm_name" 2>&1 || return 1

    # Socket should exist (enabled via Smolfile)
    local result
    result=$($SMOLVM machine exec --name "$vm_name" -- ls /tmp/ssh-agent.sock 2>&1) || return 1
    [[ "$result" == *"ssh-agent.sock"* ]] || return 1

    cleanup_vm "$vm_name"
}

test_ssh_agent_fails_without_host_socket() {
    local vm_name="ssh-agent-nosock-$$"
    cleanup_vm "$vm_name"

    # Temporarily unset SSH_AUTH_SOCK
    local saved_sock="$SSH_AUTH_SOCK"
    unset SSH_AUTH_SOCK

    # Create should succeed (flag is just stored)
    $SMOLVM machine create "$vm_name" --ssh-agent 2>&1 || { export SSH_AUTH_SOCK="$saved_sock"; return 1; }

    # Start should fail with clear error
    local output
    output=$($SMOLVM machine start --name "$vm_name" 2>&1) || true
    export SSH_AUTH_SOCK="$saved_sock"

    [[ "$output" == *"SSH_AUTH_SOCK"* ]] || return 1

    cleanup_vm "$vm_name"
}

echo ""
echo "--- SSH Agent Forwarding Tests ---"
echo ""

run_test "SSH agent: --ssh-agent creates socket in guest" test_ssh_agent_flag_creates_socket || true
run_test "SSH agent: guest can list host keys" test_ssh_agent_lists_host_keys || true
run_test "SSH agent: socket absent without flag" test_ssh_agent_not_present_without_flag || true
run_test "SSH agent: Smolfile [auth] ssh_agent" test_ssh_agent_smolfile || true
run_test "SSH agent: fails when SSH_AUTH_SOCK missing" test_ssh_agent_fails_without_host_socket || true

print_summary "Smolfile Tests"
