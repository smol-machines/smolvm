import json, glob, os
rows = []
for f in sorted(glob.glob("/home/ubuntu/bench/results/*.json")):
    r = json.load(open(f))
    ls = [str(l.get("lossN")).lower() for l in r.get("learners", [])]
    nan = sum(1 for x in ls if x == "nan")
    rows.append((os.path.basename(f)[:28], r["arm"], r["n"], r["steps"],
                 r["learners_done"], nan, r["peak_gpu_mib"]))
print("%-28s %-7s %3s %5s %6s %5s %9s" % ("run", "arm", "N", "steps", "done", "nan", "peakGPU"))
print("-" * 72)
for run, arm, n, s, done, nan, peak in rows:
    flag = "  <-- NAN" if nan else ""
    print("%-28s %-7s %3d %5d %6s %5d %9d%s" % (run, arm, n, s, "%d/%d" % (done, n), nan, peak, flag))
