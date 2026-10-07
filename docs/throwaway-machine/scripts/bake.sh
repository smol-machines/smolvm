#!/usr/bin/env bash
# Bake an image into the host cache. This is the only step in which a machine
# has a network, and it runs with nothing untrusted mounted.
#
# usage: bake.sh [<image>]      (default python:3.12-alpine)
#
# Do this before the untrusted code is anywhere near the machine. Afterwards the
# runs' machines need no network at all, which is materially stronger isolation
# than granting egress and hoping the workload behaves. The host CLI still asks
# the registry for the image's manifest on every run.

set -uo pipefail

IMAGE="${1:-python:3.12-alpine}"

SMOLVM="${SMOLVM:-$(command -v smolvm 2>/dev/null)}"
if [ -z "$SMOLVM" ]; then
    printf 'smolvm not found; set SMOLVM to its path\n' >&2
    exit 2
fi

# Before v1.20.2, on macOS --oci-cache plus any -v mount never boots (#1192,
# fixed by #1467), so a bake buys nothing there. v1.20.2 and later bake here.
version="$("$SMOLVM" --version 2>/dev/null | awk '{print $NF}')"
fixed="$(printf '%s\n%s\n' "${version:-0}" 1.20.2 | sort -V | head -1)"
if [ "$(uname -s)" = "Darwin" ] && [ "$fixed" != "1.20.2" ]; then
    printf 'result=unsupported_on_macos\n'
    printf 'A baked image is only useful to a run that also mounts something, and on macOS\n'
    printf '%s\n' '--oci-cache plus any -v mount times out the boot (smol-machines/smolvm#1192).'
    printf 'Fixed in v1.20.2; this binary is %s. Upgrade, or read references/macos.md.\n' "${version:-unknown}"
    exit 2
fi

start="$(date +%s)"
out="$("$SMOLVM" machine run --mem 2048 --net --oci-cache --image "$IMAGE" -- true 2>&1)"
rc=$?
elapsed=$(( $(date +%s) - start ))
printf '%s\n' "$out" | sed 's/^/  /'

printf 'image=%s\n' "$IMAGE"
printf 'elapsed_s=%s\n' "$elapsed"

# Assert the value, not the exit code. A bake that did not cache still exits
# zero, and the run that depends on it then fails much later with a message
# about the registry.
if printf '%s' "$out" | grep -q 'baked in'; then
    printf 'result=baked\n'
    exit 0
fi

# A second bake of an already-cached image reports the cache hit instead.
if printf '%s' "$out" | grep -q 'host cache hit'; then
    printf 'result=already_baked\n'
    exit 0
fi

printf 'result=FAILED rc=%s\n' "$rc"

# Diagnose rather than hand the error back. A ready timeout here names neither
# the helper VM nor its memory, and the cause is usually one of two things.
if printf '%s' "$out" | grep -q 'did not become ready'; then
    printf 'diagnosis: the bake runs in a helper machine (init-bake-<hash>-<pid>) which takes\n'
    printf '  the DEFAULT memory, 8192 MiB, ignoring the --mem on your command. If this host\n'
    printf '  cannot boot a VM that large, the bake can never succeed and the error says so\n'
    printf '  nowhere. Control boot at 2048 MiB:\n'
    if "$SMOLVM" machine run --mem 2048 --net --image alpine -- echo CONTROL_OK 2>&1 | grep -q CONTROL_OK; then
        printf '  control_boot_2048=ok\n'
        printf '  So small VMs boot here and the helper does not: this host cannot give the bake\n'
        printf '  the memory it takes. From v1.23.0 a persistent machine created with no network\n'
        printf '  boots the image with no bake (README.md, "The network is off unless you ask\n'
        printf '  for it"). Otherwise use the network-on route (scripts/run.sh --route\n'
        printf '  network-on), and read references/macos.md, which explains what that route\n'
        printf '  costs you. It is the same trade on any host that cannot bake.\n'
    else
        printf '  control_boot_2048=failed\n'
        printf '  Nothing boots here at all. This is not a bake problem: run the install\n'
        printf '  packet preflight, which checks KVM access and the macOS socket path length.\n'
    fi
else
    printf 'The bake is the only step with a networked machine. If it failed on the registry,\n'
    printf 'fix that here rather than adding --net to the workload run, which is what the CLI\n'
    printf 'hint suggests and is the opposite of what an isolated run wants.\n'
fi
exit 1
