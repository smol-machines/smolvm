#!/bin/bash
# Container arm (the incumbent pattern): N docker replicas, each independently
# loading the model + CUDA-initializing, then QLoRA-training. Shares one GPU.
# Same workload and venv as the smolvm arm — the ONLY difference is fork-share
# vs cold-replicate. Prints ready time, done time, aggregate tok/s, peak VRAM.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/config.sh"

CO="$HOME/coord_ctr"; rm -rf "$CO"; mkdir -p "$CO"
DOCKER="docker"; command -v docker >/dev/null || DOCKER="sudo docker"

echo "== CONTAINER baseline: $N replicas, $STEPS steps each =="
t0=$(date +%s.%N)
for i in $(seq 0 $((N-1))); do
  $DOCKER run -d --rm --name "learner_$i" --gpus '"device=0"' \
    -v "$VENV:/ptwork:ro" -v "$HF:/hf:ro" -v "$CO:/coord:rw" -v "$WORKLOAD:/qlora_train.py:ro" \
    -e HF_HOME=/hf -e HF_HUB_OFFLINE=0 -e LEARNER_ID="$i" -e STEPS="$STEPS" \
    -e COORD=/coord -e ARM=container -e MODEL="$MODEL" \
    -e PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True \
    "$IMG" /ptwork/bin/python /qlora_train.py >/dev/null 2>&1
done

ready=0; done=0; maxvram=0; READY_T=""
for s in $(seq 1 900); do
  ready=$(grep -l '"event": "ready"' "$CO"/learner_*.jsonl 2>/dev/null | wc -l)
  done=$(grep -l '"event": "done"' "$CO"/learner_*.jsonl 2>/dev/null | wc -l)
  v=$(nvidia-smi --query-gpu=memory.used --format=csv,noheader,nounits 2>/dev/null)
  [ "$v" -gt "$maxvram" ] 2>/dev/null && maxvram=$v
  if [ "$ready" -ge "$N" ] && [ -z "$READY_T" ]; then READY_T=$(date +%s.%N); fi
  [ "$done" -ge "$N" ] && break
  sleep 2
done
tend=$(date +%s.%N)
echo "time_to_all_ready_s=$(echo "${READY_T:-$tend} - $t0" | bc)"
echo "time_to_all_done_s=$(echo "$tend - $t0" | bc)"
echo "peak_gpu_mem_MiB=$maxvram   ($N replicas)"
$DOCKER rm -f $($DOCKER ps -aq --filter name=learner_) >/dev/null 2>&1

python3 "$HERE/summarize.py" "$CO" container
