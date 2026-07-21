#!/usr/bin/env python3
"""Aggregate per-learner JSONL results into one line + per-learner detail.
Usage: summarize.py <coord_dir> <arm-label>"""
import sys, glob, json

co, arm = sys.argv[1], sys.argv[2]
learners = []
for f in glob.glob(f"{co}/learner_*.jsonl"):
    ev = {}
    for line in open(f):
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        ev[e.get("event")] = e
    if "done" in ev:
        learners.append((ev.get("ready", {}), ev["done"]))

if not learners:
    print(f"[{arm}] no completed learners (check the arm's g.err / docker logs)")
    sys.exit(0)

agg = sum(d["tok_s"] for _, d in learners)
peak = max(d["peak_gb"] for _, d in learners)
loads = [r.get("load_ms", 0) for r, _ in learners if r]
med_load = sorted(loads)[len(loads) // 2] if loads else "?"
print(
    f"[{arm}] learners_done={len(learners)} agg_tok_s={agg} "
    f"per_learner_peak_gb={peak:.1f} median_load_ms={med_load}"
)
for _, d in sorted(learners, key=lambda z: int(z[1]["lid"])):
    print(
        f"   learner {d['lid']}: loss {d['loss0']}->{d['lossN']} "
        f"tok/s={d['tok_s']} peak={d['peak_gb']}GB"
    )
