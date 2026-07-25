import json, glob, sys, os
d = sys.argv[1]
n = nan = 0
out = []
for f in sorted(glob.glob(os.path.join(d, "learner_*.jsonl"))):
    rec = {}
    for line in open(f):
        e = json.loads(line); rec[e["event"]] = e
    if "done" in rec:
        z = rec["done"]; n += 1
        bad = str(z["lossN"]).lower() == "nan"
        nan += bad
        out.append("  learner %2s: %s -> %s%s" % (z["lid"], z["loss0"], z["lossN"], "   <-- NAN" if bad else ""))
print("\n".join(out))
print("  => done=%d  nan=%d" % (n, nan))
