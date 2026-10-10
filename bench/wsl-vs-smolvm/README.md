# WSL vs smolvm, same box, same guest

Reproduces the workloads from [WSL2 vs WSL3 benchmarks](https://tonym.us/wsl2-vs-wsl3-benchmarks.html):
`perf bench syscall/basic`, `sched/pipe`, `sched/messaging` (20 groups, 800 tasks), `mem/memcpy` (1 GB),
and optionally a cold `go build` of GoReleaser, inside an Alpine guest pinned to 2 vCPU and 4 GB, once
under WSL and once under smolvm on the Windows Hypervisor Platform.

`guest.sh` is the only thing that runs inside either guest, so the two sides differ only in what boots it.
`run.ps1` alternates WSL and smolvm runs, takes the median, and writes `results.csv`.

```powershell
.\run.ps1                 # perf workloads, 3 runs each
.\run.ps1 -Full -Runs 1   # adds the GoReleaser cold build
```

Setup on the Windows side: an Alpine WSL distro (import the minirootfs with `wsl --import`), a
`.wslconfig` with `processors=2` and `memory=4GB` followed by `wsl --shutdown`, and `smolvm.exe` on
PATH with the Windows Hypervisor Platform feature enabled. Report the WSL version (`wsl --version`),
the smolvm version, the CPU, and whether VBS is on; the post's box was an i5-8500T with VBS active.
