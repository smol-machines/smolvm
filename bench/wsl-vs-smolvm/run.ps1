# WSL vs smolvm on the same Windows box, same guest script, same 2 vCPU / 4 GB.
#   .\run.ps1 [-Distro Alpine] [-Full] [-Runs 3]
# Prereqs: WSL with an Alpine distro (import the Alpine minirootfs: wsl --import Alpine C:\wsl\alpine alpine-minirootfs-3.23.0-x86_64.tar),
#   %USERPROFILE%\.wslconfig with processors=2 and memory=4GB (then `wsl --shutdown`),
#   smolvm.exe on PATH with the Windows Hypervisor Platform feature enabled.
param([string]$Distro = "Alpine", [switch]$Full, [int]$Runs = 3)
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$flag = if ($Full) { "--full" } else { "" }
$results = @()
function Parse($lines, $target, $run) {
  foreach ($l in $lines) { if ($l -match '^([a-z_]+),([^,]+),(.+)$') { $script:results += [pscustomobject]@{ target=$target; run=$run; name=$Matches[1]; value=$Matches[2]; unit=$Matches[3] } } }
}
$wslPath = (wsl -d $Distro -- wslpath -a "$here/guest.sh").Trim()
for ($r = 1; $r -le $Runs; $r++) {
  Write-Host "== WSL run $r"
  $out = wsl -d $Distro -- sh $wslPath $flag 2>&1
  Parse $out "wsl" $r
  Write-Host "== smolvm run $r"
  $out = smolvm machine run --net --cpus 2 --mem 4096 --image alpine:3.23 -v "${here}:/bench" -- sh /bench/guest.sh $flag 2>&1
  Parse $out "smolvm" $r
}
$results | Export-Csv -NoTypeInformation -Path "$here/results.csv"
Write-Host "`nmedian of $Runs runs"
$results | Where-Object { $_.name -notin @("host","cpus","mem_mb") } | Group-Object name | ForEach-Object {
  $n = $_.Name
  $w = ($_.Group | Where-Object target -eq "wsl" | ForEach-Object { [double]$_.value } | Sort-Object)
  $s = ($_.Group | Where-Object target -eq "smolvm" | ForEach-Object { [double]$_.value } | Sort-Object)
  $wm = if ($w.Count) { $w[[int][math]::Floor(($w.Count-1)/2)] } else { "NA" }
  $sm = if ($s.Count) { $s[[int][math]::Floor(($s.Count-1)/2)] } else { "NA" }
  [pscustomobject]@{ workload=$n; wsl=$wm; smolvm=$sm; unit=($_.Group[0].unit) }
} | Format-Table -AutoSize
Write-Host "raw: $here/results.csv"
