#!/usr/bin/env python3
"""Summarize bench.sh results: median per (arm, n, cpus) + the native/fork ratio.

Reports the median across repetitions and the min-max spread, because the two
numbers that decide this comparison are both known to be unstable: the golden
load is bimodal (~15s vs ~156s) and per-learner throughput moves with GPU
contention. A single run of either arm is not evidence.

Usage: ./summarize.py [results_dir]
"""
import json
import glob
import os
import statistics
import sys


def med(xs):
    xs = [x for x in xs if x is not None]
    return statistics.median(xs) if xs else None


def fmt(v, unit="", nd=0):
    if v is None:
        return "-"
    return f"{v:.{nd}f}{unit}"


def main():
    d = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "results")
    runs = [json.load(open(f)) for f in sorted(glob.glob(os.path.join(d, "*.json")))]
    if not runs:
        print(f"no results in {d}")
        return

    groups = {}
    for r in runs:
        groups.setdefault((r["arm"], r["n"], r["cpus_per_learner"],
                           r.get("batch", 0), r.get("maxseq", 0)), []).append(r)

    print(f"{'arm':<7} {'N':>3} {'bxseq':>9} {'reps':>4} {'wall_s':>8} {'agg_tok/s':>10} "
          f"{'peak_GPU':>9} {'golden_s':>9} {'done':>7}")
    print("-" * 78)
    rows = {}
    for (arm, n, cpus, batch, maxseq), rs in sorted(groups.items()):
        wall = med([r["wall_s"] for r in rs])
        agg = med([r["agg_tok_s"] for r in rs])
        peak = med([r["peak_gpu_mib"] for r in rs])
        gold = med([r["golden_load_s"] for r in rs])
        done = f"{sum(r['learners_done'] for r in rs)}/{sum(r['learners_expected'] for r in rs)}"
        rows[(arm, n, cpus, batch, maxseq)] = (wall, agg, peak)
        shape = f"{batch}x{maxseq}" if batch else "-"
        # A cell where learners did not all finish is usually an OOM; flag it
        # rather than letting a partial aggregate look like a real datapoint.
        incomplete = "" if all(r["learners_done"] == r["learners_expected"] for r in rs) else "  <-- INCOMPLETE (OOM?)"
        print(f"{arm:<7} {n:>3} {shape:>9} {len(rs):>4} {fmt(wall,'',1):>8} {fmt(agg):>10} "
              f"{fmt(peak,'MiB'):>9} {fmt(gold,'',1):>9} {done:>7}{incomplete}")
        if len(rs) > 1:
            w = [r["wall_s"] for r in rs]
            g = [r["golden_load_s"] for r in rs if r["golden_load_s"] is not None]
            spread = f"           spread: wall {min(w):.1f}-{max(w):.1f}s"
            if g:
                spread += f", golden {min(g):.1f}-{max(g):.1f}s"
            print(spread)

    print()
    for (arm, n, cpus, batch, maxseq), (wall, agg, peak) in sorted(rows.items()):
        if arm != "fork":
            continue
        base = rows.get(("native", n, cpus, batch, maxseq))
        if not base:
            continue
        bw, ba, bp = base
        print(f"N={n}, {cpus} cpu/learner, batch {batch}x{maxseq} — fork vs native:")
        if bw and wall:
            print(f"  wall:      {wall:.1f}s vs {bw:.1f}s   ({wall/bw:.2f}x {'slower' if wall > bw else 'faster'})")
        if ba and agg:
            print(f"  agg tok/s: {agg:.0f} vs {ba:.0f}   ({ba/agg:.2f}x {'slower' if agg < ba else 'faster'})")
        if bp and peak:
            print(f"  peak GPU:  {peak:.0f} vs {bp:.0f} MiB   ({peak/bp:.2f}x)")


if __name__ == "__main__":
    main()
