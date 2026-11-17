# Run on a Windows x86_64 host with WHP enabled and a matching smolvm/libkrun build.
# Checks guest tmpfs and boot identity across a portable checkpoint and a frozen branch.
param(
    [string]$Smolvm = ".\smolvm.exe",
    [int]$Cpus = 1,
    [int]$MemoryMiB = 512,
    [int]$RamPayloadMiB = 32,
    [switch]$KeepOnFailure,
    [switch]$HoldBeforeBranch,
    [switch]$FreshOnly,
    [switch]$CheckpointOnly,
    [switch]$PauseResume,
    [switch]$Workload,
    [switch]$DebugBoot,
    [switch]$PreSync
)

$ErrorActionPreference = "Stop"
$suffix = ([guid]::NewGuid().ToString('N')).Substring(0, 8)
$source = "win-checkpoint-$suffix"
$child = "win-branch-$suffix"
$peer = "win-peer-$suffix"
$restored = "win-restored-$suffix"
$artifact = Join-Path ([System.IO.Path]::GetTempPath()) "$child.checkpoint"
$passed = $false
if ($DebugBoot) {
    $env:SMOLVM_BOOT_DEBUG = '1'
    $env:SMOLVM_KRUN_LOG_LEVEL = '4'
}

function Invoke-Smolvm {
    # Windows PowerShell 5.1 can promote a native stderr line to a terminating
    # error when ErrorActionPreference is Stop. Launching commands spawn a VMM
    # with its own null stdio; wait on the CLI process only.
    $ErrorActionPreference = "Continue"
    Write-Host "smolvm $($args -join ' ')"
    if ($args.Count -ge 2 -and $args[0] -eq "machine" -and
        $args[1] -in @("start", "branch", "resume")) {
        $start = New-Object System.Diagnostics.ProcessStartInfo
        $start.FileName = (Resolve-Path $Smolvm).Path
        $start.Arguments = ($args | ForEach-Object { '"' + $_.Replace('"', '\"') + '"' }) -join ' '
        $start.UseShellExecute = $false
        $start.CreateNoWindow = $true
        $process = [System.Diagnostics.Process]::Start($start)
        $process.WaitForExit(300000) | Out-Null
        if (-not $process.HasExited) {
            $process.Kill()
            throw "smolvm $($args -join ' ') timed out"
        }
        if ($process.ExitCode -ne 0) {
            throw "smolvm $($args -join ' ') failed with exit code $($process.ExitCode)"
        }
        return ""
    }
    $stdout = [System.IO.Path]::GetTempFileName()
    $stderr = [System.IO.Path]::GetTempFileName()
    try {
        & $Smolvm @args 1> $stdout 2> $stderr
        $code = $LASTEXITCODE
        $output = [System.IO.File]::ReadAllText($stdout) + [System.IO.File]::ReadAllText($stderr)
    }
    finally {
        Remove-Item $stdout, $stderr -Force -ErrorAction SilentlyContinue
    }
    if ($code -ne 0) {
        throw "smolvm $($args -join ' ') failed: $output"
    }
    return $output
}

function Guest-BootId([string]$name) {
    $output = Invoke-Smolvm machine exec --name $name -- cat /proc/sys/kernel/random/boot_id
    $match = [regex]::Match($output, '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
    if (-not $match.Success) { throw "missing guest boot ID for ${name}: $output" }
    return $match.Value
}

function Assert-GuestTimer([string]$name) {
    $output = Invoke-Smolvm machine exec --name $name -- sh -c 'sleep 1; printf timer-ok'
    if ($output -notmatch 'timer-ok') { throw "guest timer stalled in ${name}: $output" }
}

function Assert-PauseResume([string]$name, [string]$bootId, [string]$marker) {
    Invoke-Smolvm machine pause --name $name | Out-Null
    Invoke-Smolvm machine resume --name $name | Out-Null
    if ((Guest-BootId $name) -ne $bootId) { throw 'pause/resume changed the guest boot ID' }
    $saved = Invoke-Smolvm machine exec --name $name -- cat /tmp/smolvm-checkpoint-probe
    if ($saved -notmatch $marker) { throw 'pause/resume lost guest tmpfs' }
    Assert-GuestTimer $name
    if ($Workload) { Assert-Workload $name }
}

function Seed-Workload([string]$name) {
    $seed = 'mkdir -p /workspace/smolvm-checkpoint-test; printf disk-parent > /workspace/smolvm-checkpoint-test/parent; dd if=/dev/urandom of=/tmp/smolvm-ram-payload bs=1M count={0} status=none; sha256sum /tmp/smolvm-ram-payload > /workspace/smolvm-checkpoint-test/ram.sha' -f $RamPayloadMiB
    Invoke-Smolvm machine exec --name $name -- sh -c $seed | Out-Null
    Invoke-Smolvm machine exec --name $name -- sh -c 'while :; do printf tick >> /tmp/smolvm-worker-ticks; sleep 1; done </dev/null >/tmp/smolvm-worker.log 2>&1 & echo $! >/tmp/smolvm-worker.pid' | Out-Null
    Assert-Workload $name
}

function Assert-Workload([string]$name) {
    $output = Invoke-Smolvm machine exec --name $name -- sh -c 'set -e; test $(cat /workspace/smolvm-checkpoint-test/parent) = disk-parent; sha256sum -c /workspace/smolvm-checkpoint-test/ram.sha; kill -0 $(cat /tmp/smolvm-worker.pid); a=$(wc -c < /tmp/smolvm-worker-ticks); sleep 2; b=$(wc -c < /tmp/smolvm-worker-ticks); test $b -gt $a; printf workload-ok'
    if ($output -notmatch 'workload-ok') { throw "workload did not survive in ${name}: $output" }
}

try {
    Invoke-Smolvm machine create --name $source --cpus $Cpus --mem $MemoryMiB | Out-Null
    Invoke-Smolvm machine start --name $source --branchable | Out-Null
    Invoke-Smolvm machine exec --name $source -- sh -c 'printf checkpoint-ram > /tmp/smolvm-checkpoint-probe' | Out-Null
    $bootId = Guest-BootId $source
    if ($Workload) { Seed-Workload $source }
    if ($FreshOnly) {
        for ($iteration = 1; $iteration -le 10; $iteration++) {
            Start-Sleep -Seconds 3
            Assert-GuestTimer $source
            if ($Workload) { Assert-Workload $source }
            Write-Host "Fresh VM iteration $iteration passed."
        }
        $passed = $true
        return
    }
    if ($PauseResume -and $CheckpointOnly) { Assert-PauseResume $source $bootId 'checkpoint-ram' }

    if ($CheckpointOnly) {
        Invoke-Smolvm machine checkpoint --name $source --output $artifact | Out-Null
        Invoke-Smolvm machine create --name $restored --from $artifact | Out-Null
        Invoke-Smolvm machine start --name $restored | Out-Null
        if ((Guest-BootId $restored) -ne $bootId) { throw 'checkpoint changed the guest boot ID' }
        $saved = Invoke-Smolvm machine exec --name $restored -- cat /tmp/smolvm-checkpoint-probe
        if ($saved -notmatch 'checkpoint-ram') { throw 'checkpoint lost guest tmpfs' }
        Assert-GuestTimer $restored
        if ($Workload) { Assert-Workload $restored }
        if ($PauseResume) { Assert-PauseResume $restored $bootId 'checkpoint-ram' }
        $passed = $true
        Write-Host 'Windows portable checkpoint smoke test passed.'
        return
    }

    if ($HoldBeforeBranch) {
        Write-Host "Holding $source for 60 seconds before branching."
        Start-Sleep -Seconds 60
    }

    Invoke-Smolvm machine branch --from $source --name $child --freeze-source | Out-Null
    if ((Guest-BootId $child) -ne $bootId) { throw 'branch changed the guest boot ID' }
    $branched = Invoke-Smolvm machine exec --name $child -- cat /tmp/smolvm-checkpoint-probe
    if ($branched -notmatch 'checkpoint-ram') { throw 'branch lost guest tmpfs' }
    Assert-GuestTimer $child
    if ($Workload) { Assert-Workload $child }
    Invoke-Smolvm machine exec --name $child -- sh -c 'printf child-only > /tmp/smolvm-checkpoint-probe' | Out-Null
    if ($Workload) {
        Invoke-Smolvm machine exec --name $child -- sh -c 'printf child-disk > /workspace/smolvm-checkpoint-test/child; printf child-ram > /tmp/smolvm-child-only' | Out-Null
        Invoke-Smolvm machine branch --from $source --name $peer --freeze-source | Out-Null
        if ((Guest-BootId $peer) -ne $bootId) { throw 'second branch changed the guest boot ID' }
        $peerState = Invoke-Smolvm machine exec --name $peer -- sh -c 'set -e; test ! -e /workspace/smolvm-checkpoint-test/child; test ! -e /tmp/smolvm-child-only; test $(cat /tmp/smolvm-checkpoint-probe) = checkpoint-ram; printf isolated-ok'
        if ($peerState -notmatch 'isolated-ok') { throw "frozen branches are not isolated: $peerState" }
        Assert-Workload $peer
    }
    if ($PreSync) {
        $syncTime = Measure-Command { Invoke-Smolvm machine exec --name $child --timeout 120s -- /bin/sync | Out-Null }
        Write-Host "Guest sync took $([math]::Round($syncTime.TotalSeconds, 2)) seconds."
    }

    Invoke-Smolvm machine checkpoint --name $child --output $artifact | Out-Null
    Invoke-Smolvm machine create --name $restored --from $artifact | Out-Null
    Invoke-Smolvm machine start --name $restored | Out-Null
    if ((Guest-BootId $restored) -ne $bootId) { throw 'checkpoint changed the guest boot ID' }
    $saved = Invoke-Smolvm machine exec --name $restored -- cat /tmp/smolvm-checkpoint-probe
    if ($saved -notmatch 'child-only') { throw 'checkpoint lost the branched guest tmpfs' }
    Assert-GuestTimer $restored
    if ($Workload) {
        Assert-Workload $restored
        $childState = Invoke-Smolvm machine exec --name $restored -- sh -c 'set -e; test $(cat /workspace/smolvm-checkpoint-test/child) = child-disk; test $(cat /tmp/smolvm-child-only) = child-ram; printf child-state-ok'
        if ($childState -notmatch 'child-state-ok') { throw "branch changes did not survive checkpoint: $childState" }
    }
    if ($PauseResume) { Assert-PauseResume $restored $bootId 'child-only' }

    $passed = $true
    Write-Host 'Windows checkpoint restore and frozen branch smoke test passed.'
}
catch {
    Write-Host "Windows smoke test failed: $_"
    throw
}
finally {
    if ($KeepOnFailure -and -not $passed) {
        Write-Host "Preserved $source, $child, $peer, $restored and $artifact for diagnosis."
    }
    else {
        foreach ($name in @($peer, $child, $restored, $source)) {
            try {
                $ErrorActionPreference = "Continue"
                & $Smolvm machine delete --name $name --force *> $null
            }
            catch { }
        }
        if (Test-Path $artifact) { Remove-Item $artifact -Force }
    }
}
