#!/bin/bash
# One-command head-to-head: smolvm forks vs cold container replicas, identical
# workload/venv/model on the same GPU. Prints both arms' numbers and a summary.
#
#   ./benchmark.sh              # default N=8, STEPS=8, both arms
#   N=16 STEPS=6 ./benchmark.sh # denser sweep
#   ARMS=smolvm ./benchmark.sh  # smolvm arm only (skip docker)
#
# Configure paths in config.sh (or export them). See ../QUICKSTART.md.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/config.sh"
: "${ARMS:=smolvm containers}"

echo "############################################################"
echo "# smolvm fork density benchmark   N=$N  STEPS=$STEPS  MODEL=$MODEL"
echo "############################################################"

# --- preflight: fail early with a clear message ------------------------------
fail=0
[ -x "$SMOLVM" ] || { echo "MISSING: smolvm binary at $SMOLVM (set SMOLVM=...)"; fail=1; }
[ -f "$DRVLIB/libcudart.so" ] || [ -f "$DRVLIB/libcudart.so.12" ] || { echo "MISSING: guest shims in $DRVLIB (set DRVLIB=...)"; fail=1; }
[ -d "$VENV" ] || { echo "MISSING: venv at $VENV (set VENV=...)"; fail=1; }
[ -f "$WORKLOAD" ] || { echo "MISSING: workload at $WORKLOAD"; fail=1; }
command -v nvidia-smi >/dev/null || { echo "MISSING: nvidia-smi (no GPU driver?)"; fail=1; }
[ "$fail" = 0 ] || { echo "Preflight failed — fix the above and re-run."; exit 1; }

SMOLVM_OUT=""; CTR_OUT=""
for arm in $ARMS; do
  echo; echo "------------------------------------------------------------"
  case "$arm" in
    smolvm)     SMOLVM_OUT="$(bash "$HERE/run-smolvm.sh")";     echo "$SMOLVM_OUT" ;;
    containers) CTR_OUT="$(bash "$HERE/run-containers.sh")";    echo "$CTR_OUT"   ;;
    *) echo "unknown arm: $arm" ;;
  esac
done

echo; echo "############################################################"
echo "# HEAD-TO-HEAD  (N=$N)"
echo "############################################################"
pick() { echo "$1" | grep -oE "$2" | head -1 | grep -oE '[0-9.]+'; }
s_tok=$(pick "$SMOLVM_OUT" 'agg_tok_s=[0-9]+'); s_mem=$(pick "$SMOLVM_OUT" 'peak_gpu_mem_MiB=[0-9]+'); s_load=$(pick "$SMOLVM_OUT" 'golden_load_s=[0-9.]+')
c_tok=$(pick "$CTR_OUT"    'agg_tok_s=[0-9]+'); c_mem=$(pick "$CTR_OUT"    'peak_gpu_mem_MiB=[0-9]+')
printf "%-22s %-14s %-14s\n" "metric" "smolvm forks" "containers"
printf "%-22s %-14s %-14s\n" "aggregate tok/s" "${s_tok:-?}" "${c_tok:-?}"
printf "%-22s %-14s %-14s\n" "peak GPU MiB" "${s_mem:-?}" "${c_mem:-?}"
printf "%-22s %-14s %-14s\n" "golden load s (once)" "${s_load:-?}" "n/a (per replica)"
if [ -n "${s_mem:-}" ] && [ -n "${c_mem:-}" ] && [ "$s_mem" -gt 0 ]; then
  echo; echo "smolvm density: containers use $(echo "scale=1; $c_mem/$s_mem" | bc)x the VRAM for the same N."
fi
echo "(raw per-learner detail above; results are 1 run each — average a few for a stable number.)"
