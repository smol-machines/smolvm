#!/usr/bin/env bash
# Run the CUDA driver-API probe inside a --cuda machine and assert its values.
#
# usage: run-cuda-probe.sh [<image>]      (default python:3.12-slim)
#
# The image must be glibc. The injected shim is glibc, so an Alpine (musl) guest
# cannot load it. python:3.12-slim is small and already has Python, which CUDA
# base images do not.

set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
IMAGE="${1:-python:3.12-slim}"

SMOLVM="${SMOLVM:-$(command -v smolvm 2>/dev/null)}"
if [ -z "$SMOLVM" ]; then
    printf 'smolvm not found; set SMOLVM to its path\n' >&2
    exit 2
fi

out="$("$SMOLVM" machine run --cuda --net --mem 8192 \
    -v "$here:/probe:ro" --image "$IMAGE" -- python3 /probe/cuda-probe.py 2>&1)"
printf '%s\n' "$out" | sed 's/^/  /'

fail=0
check() {
    if printf '%s' "$out" | grep -q "$2"; then
        printf '%s=ok\n' "$1"
    else
        printf '%s=FAIL\n' "$1"
        fail=1
    fi
}

# A device NAME, not a zero return code: on a remoted API a program links and
# exits zero without a GPU ever being reached.
check device_named 'cuDeviceGetName -> 0 name = ..*'
# And the round trip, which is the only proof that bytes reached the device.
check data_roundtrip 'roundtrip first 16 bytes match: True'

# A host that cannot load the NVIDIA driver library answers with a CPU emulation device, which
# passes both checks above. The device name is what tells them apart.
if printf '%s' "$out" | grep -qi 'name = .*emulation'; then
    printf 'device_kind=cpu_emulation\n'
    printf 'result=cpu_emulation_not_gpu\n'
    printf 'The guest reached a device and the round trip returned, but the device is\n'
    printf 'smolvm CPU emulation, not an NVIDIA GPU. Nothing here was accelerated. Run\n'
    printf 'scripts/preflight.sh: gpu_present=no says the same thing without starting a VM.\n'
    exit 1
fi
# A run that reached no device at all names none, so it must not read as a GPU.
if printf '%s' "$out" | grep -q 'cuDeviceGetName -> 0 name = ..*'; then printf 'device_kind=gpu\n'; else printf 'device_kind=none\n'; fi

if [ "$fail" -eq 0 ]; then
    printf 'result=cuda_ok\n'
else
    printf 'result=FAILED\n'
    printf 'Run scripts/preflight.sh. The three causes, and none of them says so in the error:\n'
    printf '  - A guest too large for this host. The probe asks for 8192 MiB, and a host that cannot\n'
    printf '    boot that inside the fixed 30 s fails with "agent did not become ready within 30\n'
    printf '    seconds". Run smolvm machine run --mem 8192 --net --image alpine -- true: if that\n'
    printf '    fails the same way, it is the host, not CUDA.\n'
    printf '  - A musl image. The injected shim is glibc, so an Alpine guest cannot load it.\n'
    printf '  - A machine started without --cuda, in which case /opt/smolvm-cuda does not exist.\n'
fi
exit "$fail"
