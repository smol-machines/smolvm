# Installing smolvm on Windows

## Contents

- Preflight, before anything is downloaded
- Install from the zip
- Prove the boot
- State, and what you cannot move
- The trap that breaks every script: captured output never returns
- When a boot fails, read the guest console before cleaning up
- Other Windows behaviour worth knowing at install time

**Re-run on 2026-09-11 against smolvm v1.14.6** on Windows 11 Home build 10.0.26200.0 UBR 9445
x86_64 (Intel Core Ultra 9 185H, 31.6 GB), in an elevated session with Developer Mode off.
Everything below confirmed; only the release version and the zip's size and hash changed. The
outputs are reproduced verbatim. Treat it as a record of a run, not as a promise about your host.

Not covered at all: Windows 10, Windows Server, non-admin users, WSL2 as a host.

`scripts/preflight.sh` reports `result=blocked` on Windows and points here. This packet ships no
PowerShell script, because a script nobody has executed is worse than a procedure somebody has.

## 1. Preflight, before anything is downloaded

All read-only.

```powershell
[Environment]::OSVersion
(Get-CimInstance Win32_OperatingSystem).Caption
Get-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform | Select-Object State
```

`State : Enabled` is the gate. The Windows Hypervisor Platform is available on Windows 11
**Home**, unlike Hyper-V: `Microsoft-Hyper-V-All` returned no state on the tested host while
`HypervisorPlatform` was `Enabled`. Enabling WHP is a system change and needs a reboot.

**Also check symlink creation before the first run.** The agent rootfs ships as a tarball on
Windows and its extraction drops symlinks silently without the privilege, after which the guest
cannot exec `/sbin/init` and the boot ends as `boot process exited (code 127)`. The tolerant
extraction path that lets a failed extraction be marked complete still exists at v1.14.6
(`src/agent/manager.rs`), so the check is worth making rather than discovering afterwards. The
re-run above was an elevated session with Developer Mode off, so it did not exercise the
unprivileged path either.

```powershell
# Either of these is enough. Developer Mode is the one a non-admin user can turn on.
(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock' `
  -Name AllowDevelopmentWithoutDevLicense -EA SilentlyContinue).AllowDevelopmentWithoutDevLicense
whoami /priv | Select-String SeCreateSymbolicLinkPrivilege
```

`1` from the first, or a line from the second, means extraction will keep its symlinks. Neither
was verified on an unprivileged shell: the tested host's SSH session was elevated and already
held `SeCreateSymbolicLinkPrivilege`, so 389 reparse points extracted cleanly there and the
unprivileged path could not be exercised.

## 2. Install from the zip

Windows does not use `install.sh`.

```powershell
Invoke-WebRequest -Uri 'https://github.com/smol-machines/smolvm/releases/download/v1.14.6/smolvm-1.14.6-windows-x86_64.zip' -OutFile "$dir\smolvm.zip"
Invoke-WebRequest -Uri 'https://github.com/smol-machines/smolvm/releases/download/v1.14.6/checksums.sha256' -OutFile "$dir\checksums.sha256"
(Get-FileHash -Algorithm SHA256 -LiteralPath "$dir\smolvm.zip").Hash
Expand-Archive -LiteralPath "$dir\smolvm.zip" -DestinationPath "$dir\dist"
```

Observed: 40104648 bytes, SHA256
`70105f035cf4b566c1abbb026ac113b7157f5000d26a1466bbdf4966e06b6b10`, matching the release
checksums exactly.

**The zip contains a nested versioned folder.** The exe is at
`dist\smolvm-1.14.6-windows-x86_64\smolvm.exe`, not `dist\smolvm.exe`. A script that assumes the
flat layout fails here, and the failure looks like a bad download.

```powershell
& "$dir\dist\smolvm-1.14.6-windows-x86_64\smolvm.exe" --version   # smolvm 1.14.6
```

## 3. Prove the boot

```powershell
& $exe machine run --net --image alpine -- sh -c "echo HELLO_FROM_WINDOWS; uname -srm"
```

Observed, including the image pull:

```
Starting ephemeral machine (vm-f0d4c640)...
Pulling image alpine... done.
HELLO_FROM_WINDOWS
Linux 6.12.95 x86_64
```

Native Windows runs x86_64 Linux guests. The guest kernel differs from the host, which is the
assertion that proves it is a VM.

## 4. State, and what you cannot move

smolvm writes to `%LOCALAPPDATA%\smolvm` (`server\`, `rootfs\`, `vms\`). **You cannot relocate
it.** There is no `SMOLVM_DATA_DIR` in the Windows binary, and pointing `$env:LOCALAPPDATA` at a
scratch directory changed nothing: smolvm still created `C:\Users\<user>\AppData\Local\smolvm`,
because it resolves the known folder through the Windows API, which ignores the variable.

Two consequences. There is no isolated-HOME trick for testing on Windows, so a test run writes
into the real profile. And teardown has to remove that tree by hand: it reached **30756 MB** in
one session, since each machine's storage and overlay images are sparse files with 20 GiB and
10 GiB apparent size. See the `teardown` packet.

`machine list` is not read-only either: it creates the state directory and `server\smolvm.db`.

## 5. The trap that breaks every script: captured output never returns

`machine start` leaves the VM running as a background `smolvm.exe _boot-vm` child that inherits
the parent's stdout handle. Any caller that **captures** that output waits for the handle to
close, which happens only when the VM dies.

| invocation | result |
|---|---|
| `& $exe machine start --name X 2>&1 \| Out-String` | still blocked after 90 s, while `machine list` showed the machine `running` |
| `cmd /c "smolvm.exe machine start ... > out.txt 2>&1"` | also blocks, though the file already shows `Machine 'X' running (PID ...)` |
| `Start-Process -RedirectStandardOutput out.txt -PassThru`, poll `HasExited` | returns in 4.9 s |

The command itself is fast and correct. The shell is what hangs, and it cost about an hour on the
tested host and produced two wrong conclusions before it was found: `machine branch` and
`machine checkpoint` both looked like indefinite hangs when the `machine start` before them was
what blocked, and neither had run at all.

The pattern that works:

```powershell
$p = Start-Process -FilePath $exe -ArgumentList @('machine','start','--name','X') `
     -RedirectStandardOutput out.txt -RedirectStandardError err.txt -WindowStyle Hidden -PassThru
while (-not $p.HasExited) { Start-Sleep -Milliseconds 400 }
Get-Content out.txt
```

One caveat on that pattern: `-ArgumentList` applies its own quoting and mangles nested shell
quoting such as `-- sh -c "echo $(id -un)"`. For `exec` commands containing quotes, `cmd /c` with
file redirection is correct and does not block, because `exec` leaves no new background VM.

## 6. When a boot fails, read the guest console before cleaning up

Since v1.14.0 the guest console is written to
`%LOCALAPPDATA%\smolvm\vms\<hash>\agent-console.log`, beside `agent-startup-error.log`. It holds
the real reason (`Couldn't execute '/sbin/init': ENOENT` when the rootfs extraction is broken)
while the CLI prints only `boot process exited (code 127)`. Nothing surfaces it for you.

**It exists only while the VM directory does**, so read it after the failure and before any
cleanup step removes the directory.

```powershell
Get-Content "$env:LOCALAPPDATA\smolvm\vms\<hash>\agent-console.log" -Tail 40
```

## 7. Other Windows behaviour worth knowing at install time

- **PowerShell turns the exe's stderr into error records.** A fully successful run prints
  `smolvm.exe : Starting ephemeral machine (...)` followed by `NativeCommandError`. The command
  succeeded and `$LASTEXITCODE` is 0. Do not set `$ErrorActionPreference = 'Stop'` around a
  smolvm call, and do not read red text as failure.
- **Device ceiling on WHP.** Four `-v` mounts boot; five fail with `no more IRQs are available`.
  Any `-p` costs one of those slots, so four mounts plus two ports fails while two plus two boots.
- **Path length was not a problem** in the paths this run exercised: a volume mount from a
  237-character directory worked and nothing broke approaching 260 characters.
- **The rest of the platform picture**, in the `dev-env`, `local-api` and `gpu-cuda` packets.
  `--net` gives a real `eth0` with inbound port-forwarding, and `--cuda` reaches a real NVIDIA
  GPU. Vulkan (`--gpu`) is accepted and silently does nothing.
