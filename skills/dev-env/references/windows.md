# A dev machine on Windows

**Re-run on 2026-09-11 against smolvm v1.14.6** on Windows 11 Home build 10.0.26200.0 UBR 9445
x86_64 (Intel Core Ultra 9 185H, 31.6 GB), in an elevated session. **A dev machine on Windows
survives a stop and a start**, so the use case holds there as it does on Unix.

The timings in the next section and the device ceiling further down are from the earlier run on
the same host, on v1.14.2, and were not measured again.

## What works, and matches Unix exactly

```
create                  in 0.5s   Created machine: wd   Init commands: 2
first start             in 4.9s   Running 2 init command(s)...
init user / exec user   initran=root   execuser=app   workdir=/tmp
install requests        in 9.1s   2.34.2
stop                    in 0.4s   Stopped machine: wd
```

So `init` runs as root while the workload runs as the Smolfile `user`, identical to Linux and
macOS, and `init` runs once: the second start printed
`Init already completed, skipping 2 command(s)`.

## Stop and start, which is what this use case rests on

Run on v1.14.6 through create, start, stop, start, stop, start, with a marker written inside the
machine and read back after each start:

```
Created machine: wd
  --- first start
    out: Machine 'wd' running (PID: 2028)
    MARKER_V1146
  --- stop 1
    Stopped machine: wd
  --- start 2 (this is what failed on v1.14.2 with Bad message os error 74)
    out: Machine 'wd' running (PID: 14784)
  --- marker after start 2
    MARKER_V1146
  --- stop 2
    Stopped machine: wd
  --- start 3
    out: Machine 'wd' running (PID: 13820)
  --- marker after start 3
    MARKER_V1146
```

**Both restarts succeed and the marker survives both.** State written inside the machine is still
there after a stop, which is the promise this packet makes everywhere else.

The history, because the earlier version of this page was built around it: on v1.14.2 the second
start failed with `pull image: Bad message (os error 74)` and left the machine stopped, which is
[smolvm#1196](https://github.com/smol-machines/smolvm/issues/1196) and is fixed in v1.14.6.

## The device ceiling belongs in a Windows preflight

WHP gives the guest an eleven-IRQ budget, the same as Linux. Measured on the tested host:
**four `-v` mounts boot and five fail** with `no more IRQs are available`, and **any published
port costs one of those slots**, so four mounts plus two ports fails while two plus two boots.

A dev machine that mounts a source tree, a cache, a build output directory and a config directory
is already at the limit before it publishes a dev server's port.

## Driving it from a script

`machine start` never returns to a caller that captures its output: the background VM inherits
the parent's stdout handle. Use `Start-Process -RedirectStandardOutput` and poll `HasExited`. The
full measurement and the working pattern are in the `install` packet's `references/windows.md`.

State cannot be relocated on Windows, so a dev machine's disks land in `%LOCALAPPDATA%\smolvm`
and have to be removed by hand. See the `teardown` packet.
