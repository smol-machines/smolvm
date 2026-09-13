#!/usr/bin/env bash
# Bake an image into the host cache. This is the only step that talks to a
# registry, and it runs with the network on and nothing untrusted mounted.
#
# usage: bake.sh [<image>]      (default python:3.12-alpine)
#
# Do this before the untrusted code is anywhere near the machine. Afterwards the
# sandbox runs need no network at all, which is a materially stronger sandbox
# than granting egress and hoping the workload behaves.

set -uo pipefail

IMAGE="${1:-python:3.12-alpine}"

SMOLVM="${SMOLVM:-$(command -v smolvm 2>/dev/null)}"
if [ -z "$SMOLVM" ]; then
    printf 'smolvm not found; set SMOLVM to its path\n' >&2
    exit 2
fi

if [ "$(uname -s)" = "Darwin" ]; then
    printf 'result=unsupported_on_macos\n'
    printf 'A baked image is only useful to a run that also mounts something, and on macOS\n'
    printf '%s\n' '--oci-cache plus any -v mount times out the boot (smol-machines/smolvm#1192).'
    printf 'Read references/macos.md instead. Baking here would succeed and buy you nothing.\n'
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
        printf '  the memory it takes. Use the network-on route instead (scripts/run.sh\n'
        printf '  --route network-on), and read references/macos.md, which explains what that\n'
        printf '  route costs you. It is the same trade on any host that cannot bake.\n'
    else
        printf '  control_boot_2048=failed\n'
        printf '  Nothing boots here at all. This is not a bake problem: run the install\n'
        printf '  packet preflight, which checks KVM access and the macOS socket path length.\n'
    fi
else
    printf 'The bake is the only networked step. If it failed on the registry, fix that here\n'
    printf 'rather than adding --net to the workload run, which is what the CLI hint suggests\n'
    printf 'and is the opposite of what a sandbox wants.\n'
fi
exit 1
