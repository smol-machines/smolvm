#!/bin/bash
# Per-process GPU memory during a fork run. With CUDA remoted, the golden's
# context and each clone worker are separate HOST processes, so this shows
# directly whether the frozen base is shared or re-materialized per clone.
OUT=$HOME/procmem.log; : > "$OUT"
for i in $(seq 1 240); do
  [ -f "$HOME/.probe_stop" ] && break
  ts=$(date +%s)
  nvidia-smi --query-compute-apps=pid,used_memory --format=csv,noheader,nounits 2>/dev/null > /tmp/.apps
  while read -r line; do
    pid=$(echo "$line" | cut -d, -f1 | tr -d ' ')
    mem=$(echo "$line" | cut -d, -f2 | tr -d ' ')
    cmd=$(ps -p "$pid" -o args= 2>/dev/null | cut -c1-55)
    echo "$ts pid=$pid mem=${mem}MiB cmd=$cmd" >> "$OUT"
  done < /tmp/.apps
  echo "$ts TOTAL=$(nvidia-smi --query-gpu=memory.used --format=csv,noheader,nounits)MiB" >> "$OUT"
  sleep 5
done
