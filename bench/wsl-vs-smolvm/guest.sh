#!/bin/sh
# The workloads from https://tonym.us/wsl2-vs-wsl3-benchmarks.html, run identically inside WSL and
# inside a smolvm guest. Prints one `name,value,unit` line per workload. Alpine only (apk).
# Usage: sh guest.sh [--full]   (--full adds the cold GoReleaser build, ~3-5 min and ~1 GB)
set -eu
FULL=${1:-}
have() { command -v "$1" >/dev/null 2>&1; }
if ! have perf; then apk add --no-cache -q perf >/dev/null 2>&1 || { echo "apk add perf failed (need --net)" >&2; exit 1; }; fi
echo "host,$(uname -r),kernel"
echo "cpus,$(nproc),count"
echo "mem_mb,$(awk '/MemTotal/{printf "%d", $2/1024}' /proc/meminfo),MiB"
# perf prints to stderr; parse the figures the post reports.
v=$(perf bench syscall basic 2>&1 | awk '/ops\/sec/{print $(NF-1)}' | tr -d ','); echo "getppid_ops_per_sec,${v:-NA},ops/s"
v=$(perf bench sched pipe 2>&1 | awk '/usecs\/op/{print $1}'); echo "sched_pipe_usec_per_op,${v:-NA},us/op"
v=$(perf bench sched messaging -g 20 -l 800 2>&1 | awk '/Total time/{print $3}'); echo "hackbench_seconds,${v:-NA},s"
v=$(perf bench mem memcpy -s 1GB 2>&1 | awk '/GB\/sec/{print $1; exit}'); echo "memcpy_gb_per_sec,${v:-NA},GB/s"
if [ "$FULL" = "--full" ]; then
  have go || apk add --no-cache -q go git >/dev/null
  [ -d /tmp/goreleaser ] || git clone -q --depth 1 https://github.com/goreleaser/goreleaser /tmp/goreleaser
  cd /tmp/goreleaser && go mod download >/dev/null 2>&1 && go clean -cache
  s=$(date +%s.%N); go build -a -o /dev/null ./... >/dev/null 2>&1 || go build -a -o /dev/null . >/dev/null 2>&1; e=$(date +%s.%N)
  echo "goreleaser_build_seconds,$(awk "BEGIN{printf \"%.1f\", $e-$s}"),s"
fi
