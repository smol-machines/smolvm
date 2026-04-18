#!/bin/bash
#
# virtio-net tests for smolvm.
#
# This suite covers the user-visible launcher/runtime behavior from the staged
# virtio-net transplant:
# - part 3: the guest sees a configured virtio NIC and can use the host-side
#   gateway for DNS and outbound TCP
# - part 4: the `create -> start -> exec`, `machine run`, and `pack run` flows
#   all drive real virtio-backed guest networking
# - unsupported features like published ports and policy still fail clearly

source "$(dirname "$0")/common.sh"
init_smolvm

log_info "Pre-flight cleanup: killing orphan processes..."
kill_orphan_smolvm_processes

TEST_DIR=$(mktemp -d)
trap "rm -rf '$TEST_DIR'; cleanup_machine" EXIT

echo ""
echo "=========================================="
echo "  smolvm Virtio-Net Tests"
echo "=========================================="
echo ""

VIRTIO_TEST_IMAGE="${VIRTIO_TEST_IMAGE:-alpine:latest}"

virtio_guest_probe_script() {
    cat <<'EOF'
ip route | grep -F 'default via 100.96.0.1 dev eth0' &&
ip route | grep -F '100.96.0.0/30 dev eth0' &&
ip addr show dev eth0 | grep -F 'link/ether 02:53:4d:00:00:02' &&
ip addr show dev eth0 | grep -F 'inet 100.96.0.2/30' &&
nslookup example.com >/tmp/virtio-nslookup.out &&
grep -F '100.96.0.1' /tmp/virtio-nslookup.out &&
apk add --no-cache curl bash >/dev/null &&
command -v curl >/dev/null &&
command -v bash >/dev/null &&
echo virtio-net-ok
EOF
}

probe_running_virtio_guest_network() {
    local vm_name="$1"
    local output
    local script
    script=$(virtio_guest_probe_script)

    output=$($SMOLVM machine exec --name "$vm_name" -- sh -c "$script" 2>&1) || {
        echo "virtio-net guest networking probe failed"
        echo "$output"
        return 1
    }

    [[ "$output" == *"virtio-net-ok"* ]] || {
        echo "expected guest networking probe to finish successfully"
        echo "$output"
        return 1
    }
}

test_machine_create_virtio_net_works() {
    cleanup_machine
    local vm_name="virtio-create-test-$$"
    local output

    output=$($SMOLVM machine create "$vm_name" --net --net-backend virtio-net 2>&1) || {
        echo "expected virtio-net machine create to succeed"
        echo "$output"
        $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
        return 1
    }

    local list_output
    list_output=$($SMOLVM machine ls --json 2>&1)
    [[ "$list_output" == *"$vm_name"* ]] || {
        echo "virtio-net create should persist machine state"
        $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
        return 1
    }

    $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
}

test_machine_create_start_exec_virtio_net_works() {
    cleanup_machine
    local vm_name="virtio-create-start-exec-test-$$"

    $SMOLVM machine create "$vm_name" --image "$VIRTIO_TEST_IMAGE" --net --net-backend virtio-net >/dev/null 2>&1 || {
        echo "expected virtio-net machine create to succeed before start"
        $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
        return 1
    }

    $SMOLVM machine start --name "$vm_name" >/dev/null 2>&1 || {
        $SMOLVM machine delete "$vm_name" -f >/dev/null 2>&1 || true
        return 1
    }
    probe_running_virtio_guest_network "$vm_name" || {
        $SMOLVM machine stop --name "$vm_name" >/dev/null 2>&1 || true
        $SMOLVM machine delete "$vm_name" -f >/dev/null 2>&1 || true
        return 1
    }

    $SMOLVM machine stop --name "$vm_name" >/dev/null 2>&1 || {
        $SMOLVM machine delete "$vm_name" -f >/dev/null 2>&1 || true
        return 1
    }
    $SMOLVM machine start --name "$vm_name" >/dev/null 2>&1 || {
        $SMOLVM machine delete "$vm_name" -f >/dev/null 2>&1 || true
        return 1
    }
    probe_running_virtio_guest_network "$vm_name" || {
        $SMOLVM machine stop --name "$vm_name" >/dev/null 2>&1 || true
        $SMOLVM machine delete "$vm_name" -f >/dev/null 2>&1 || true
        return 1
    }

    $SMOLVM machine stop --name "$vm_name" >/dev/null 2>&1 || true
    $SMOLVM machine delete "$vm_name" -f >/dev/null 2>&1 || true
}

test_machine_run_virtio_net_works() {
    cleanup_machine
    local output
    local script
    script=$(virtio_guest_probe_script)

    output=$($SMOLVM machine run --image "$VIRTIO_TEST_IMAGE" --net --net-backend virtio-net -- sh -c "$script" 2>&1) || {
        echo "virtio-net machine run probe failed"
        echo "$output"
        return 1
    }

    [[ "$output" == *"virtio-net-ok"* ]] || {
        echo "expected machine run virtio-net probe to finish successfully"
        echo "$output"
        return 1
    }
}

test_machine_create_virtio_net_ports_rejected() {
    cleanup_machine
    local vm_name="virtio-ports-test-$$"
    local exit_code=0
    local output

    output=$($SMOLVM machine create "$vm_name" --net --net-backend virtio-net -p 18080:80 2>&1) || exit_code=$?
    [[ $exit_code -ne 0 ]] || {
        echo "expected create failure for virtio-net published port request"
        $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
        return 1
    }
    [[ "$output" == *"published ports are not supported"* ]] || {
        echo "$output"
        return 1
    }
}

test_machine_create_virtio_net_policy_rejected() {
    cleanup_machine
    local vm_name="virtio-policy-test-$$"
    local exit_code=0
    local output

    output=$($SMOLVM machine create "$vm_name" --net --net-backend virtio-net --allow-cidr 1.1.1.1/32 2>&1) || exit_code=$?
    [[ $exit_code -ne 0 ]] || {
        echo "expected create failure for virtio-net policy request"
        $SMOLVM machine delete "$vm_name" -f 2>/dev/null || true
        return 1
    }
    [[ "$output" == *"allow-cidr/allow-host policies are not supported"* ]] || {
        echo "unexpected output: $output"
        return 1
    }
}

test_pack_run_virtio_net_works() {
    local output_path="$TEST_DIR/virtio-pack"
    local output
    local script
    script=$(virtio_guest_probe_script)

    if [[ ! -f "$output_path.smolmachine" ]]; then
        $SMOLVM pack create --image "$VIRTIO_TEST_IMAGE" -o "$output_path" >/dev/null 2>&1 || {
            echo "expected pack create to succeed before pack run"
            return 1
        }
    fi

    output=$($SMOLVM pack run --sidecar "$output_path.smolmachine" --net --net-backend virtio-net -- sh -c "$script" 2>&1) || {
        echo "virtio-net pack run probe failed"
        echo "$output"
        return 1
    }

    [[ "$output" == *"virtio-net-ok"* ]] || {
        echo "expected pack run virtio-net probe to finish successfully"
        echo "$output"
        return 1
    }
}

run_test "Machine create: virtio-net works" test_machine_create_virtio_net_works || true
run_test "Machine create/start/exec: virtio-net guest networking works" test_machine_create_start_exec_virtio_net_works || true
run_test "Machine run: virtio-net guest networking works" test_machine_run_virtio_net_works || true
run_test "Machine create: virtio-net + published ports rejected" test_machine_create_virtio_net_ports_rejected || true
run_test "Machine create: virtio-net + policy rejected" test_machine_create_virtio_net_policy_rejected || true
run_test "Pack run: virtio-net guest networking works" test_pack_run_virtio_net_works || true

print_summary "Virtio-Net Tests"
