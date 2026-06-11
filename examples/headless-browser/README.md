# Headless browsers in smolvm — and pre-warmed browser pools via fork

`browser.smolfile` covers the basics: a GPU-accelerated headless Chromium you
`create` + `start` + `exec` against. This doc covers the harder-won part —
running Chromium as a **persistent, forkable workload** so you can keep a pool
of pre-warmed browsers and skip cold startup on every task.

## Why fork a browser at all

A browser's cold start (process launch + shared-library load + JS-engine init +
first navigation) costs **1–3+ seconds**. A smolvm fork is a copy-on-write clone
of a *running* VM, so a clone inherits the golden's **already-running,
already-initialized browser** — same process, same warmed heap, same listening
CDP port. You pay the cold start **once** (in the golden) and materialize warm
clones in **~50–130 ms** each.

```
warm one golden  ──fork──▶ clone 1 (browser already up)   ~90 ms to agent-ready
                  ──fork──▶ clone 2 (browser already up)
                  ──fork──▶ clone N ...
```

## The #1 gotcha: fork-friendly Chromium flags

**Chromium MUST be launched with `--no-zygote` (plus `--no-sandbox` and
`--disable-dev-shm-usage`) for the browser to survive a fork.**

Chromium's default process model uses a *zygote* — a pre-forked template process
the browser clones renderers from. That model does **not** survive a
cross-process VM fork cleanly: after the fork, joining the restored container
(`crun exec`, which is what `machine exec` does for an image VM) **hangs**. With
`--no-zygote`, Chromium runs a flat process tree that forks and execs correctly
on the clone.

```
# fork-friendly:
chromium --headless=new --no-zygote --no-sandbox --disable-dev-shm-usage \
         --remote-debugging-port=9222 --user-data-dir=/tmp/cdata about:blank

# NOT fork-friendly (the image's bare default CMD, zygote on):
#   → golden runs fine, but `machine exec` into a forked clone hangs.
```

`--no-sandbox` is required because the microVM guest typically lacks the
user-namespace / setuid-sandbox plumbing Chromium expects; `--disable-dev-shm-usage`
avoids the tiny default `/dev/shm`.

## Setup: a persistent, forkable browser golden

The browser has to be **running at fork time**, so launch it as the machine's
persistent workload — not via a one-shot `machine exec` (which is torn down when
the exec returns). Pass the command at `create` (an image machine with no
command instead adopts the image's OCI `CMD`/`ENTRYPOINT`):

```sh
smolvm machine create --name browser-golden \
    --image chromedp/headless-shell:latest --net \
    --workdir /headless-shell \
    -- ./headless-shell --headless=new --no-zygote --no-sandbox \
       --disable-dev-shm-usage --remote-debugging-port=9222 --user-data-dir=/tmp/cd

# --forkable enables the CoW-fork machinery (memfd-backed RAM + control socket).
smolvm machine start --name browser-golden --forkable

# Fork a warm clone on demand (one golden → N clones):
smolvm machine fork --golden browser-golden --name worker-1
smolvm machine fork --golden browser-golden --name worker-2

# Each clone's browser is already up; exec / drive it:
smolvm machine exec --name worker-1 -- /bin/sh -c 'echo ready'
```

The golden stays **frozen** as the CoW base while clones exist — don't `start`
it again until the clones are gone.

## What survives the fork (and what doesn't)

| Preserved (it's in the restored RAM/CoW disk) | NOT preserved |
|---|---|
| The running browser process + warmed heap / JIT | **Live network connections** (reset on restore — freeze the golden at an *idle* point, not mid-request) |
| Loaded shared libraries, parsed/blank page | **GPU renderer context** (host-side virgl/Venus state isn't transferred; headless / software rendering is unaffected) |
| The listening CDP port (`127.0.0.1:9222`) | Wall-clock-sensitive timers can jump forward by the freeze duration |
| Open file handles into the rootfs | |

Per-clone identity is rejuvenated automatically (distinct hostname, fresh
entropy), and each clone gets its own CoW disk overlay, so clones are isolated.

## Driving the warm browser (CDP)

Chromium binds the DevTools endpoint to **`127.0.0.1`** regardless of
`--remote-debugging-address` (security hardening), so reach it from *inside* the
VM (the agent shares the guest network namespace) or proxy it out.

Use a real CDP/WebSocket client — **puppeteer** or **chrome-remote-interface** —
not raw `curl`/`socat`. A raw TCP client connects but won't get the DevTools
JSON body back reliably, and the WebSocket CDP path needs
`--remote-allow-origins=*`. The HTTP `/json/*` endpoints also require a
`Host: localhost` header (DNS-rebinding protection).

## Performance

Measured on Apple M4 Max (APFS, instant `clonefile` CoW disks):

- End-to-end `machine fork` to a usable, agent-reachable warm clone: **~50–130 ms**.
- Clone boot-from-snapshot to agent-ready: **~90 ms**.
- Density: golden ~300 MB RSS, each clone only ~30–40 MB (RAM CoW-shared).

On Linux the per-fork time is the same class on a reflink-capable filesystem
(btrfs/xfs); on ext4 the disk copy dominates (~0.4–0.9 s).

## Status

Forking (`--forkable`, `machine fork`) is part of the fast-fork work and is
validated on both Linux/KVM (x86_64) and macOS/HVF (aarch64). The persistent
warm browser → fork → drive path is validated end-to-end with the flags above.
The cross-arch caveat is fundamental: a clone runs on the **same CPU arch +
hypervisor + host** as its golden (a fork is a live CoW clone, not a portable
snapshot). For portable, cold artifacts use `smolvm pack` instead.
