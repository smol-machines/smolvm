#!/usr/bin/env python3
"""Measure smolvm's core operations, alone or as an interleaved A/B.

    smolbench.py --bin ./target/release/smolvm
    smolbench.py --bin old=/path/smolvm-main --bin new=./target/release/smolvm

One binary gives a baseline. Two binaries run round by round in alternation,
each in its own HOME, so machine drift hits both arms equally instead of
landing on whichever ran second. Every timed operation is checked for success
and its output verified, so a broken arm fails loudly instead of looking fast.

Results print as a table and are written to results/<run-id>.json together
with an environment manifest (binary version and md5, host, CPU, OS).
"""

import argparse
import datetime
import hashlib
import json
import os
import platform
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
IMAGE = "alpine:3.20"


class Arm:
    """One binary under test, with its own isolated HOME."""

    def __init__(self, label, binary, root):
        self.label = label
        self.binary = os.path.abspath(binary)
        # Short path: per-machine unix sockets must fit in sun_path.
        self.home = os.path.join(root, label)
        os.makedirs(self.home, exist_ok=True)
        self.env = dict(os.environ, HOME=self.home)
        # A rootfs or lib dir given by the caller stays where it is; the
        # isolated HOME must not hide it.
        for key in ("SMOLVM_AGENT_ROOTFS", "SMOLVM_LIB_DIR"):
            if key in os.environ:
                self.env[key] = os.environ[key]
        # Checkpoint and pack need the ext4 templates the installer puts in
        # ~/.smolvm. Link them in rather than formatting fresh ones per run.
        real = os.path.expanduser("~/.smolvm")
        os.makedirs(os.path.join(self.home, ".smolvm"), exist_ok=True)
        for name in ("storage-template.ext4", "overlay-template.ext4"):
            if os.path.exists(os.path.join(real, name)):
                os.symlink(os.path.join(real, name), os.path.join(self.home, ".smolvm", name))

    def sv(self, *args, check=True, timeout=600, stdin=None):
        """Run smolvm, returning (ms, stdout). Raises on failure if check."""
        t0 = time.perf_counter()
        proc = subprocess.run(
            [self.binary, *args],
            env=self.env,
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=stdin,
        )
        ms = (time.perf_counter() - t0) * 1000
        if check and proc.returncode != 0:
            raise RuntimeError(
                f"[{self.label}] smolvm {' '.join(args)} exited {proc.returncode}: "
                f"{proc.stderr.strip()[-400:]}"
            )
        return ms, proc.stdout


# --- scenarios -------------------------------------------------------------
#
# Each scenario has an optional setup(arm, ctx) run once per arm before any
# round, a measure(arm, ctx) run every round that returns {metric: value},
# and an optional teardown(arm, ctx). Values are ms unless the metric name
# ends in _mbps.


def setup_persistent(arm, ctx):
    arm.sv("machine", "create", "--name", "sb-persist")
    arm.sv("machine", "start", "--name", "sb-persist")
    arm.sv("machine", "stop", "--name", "sb-persist")


def measure_start_stop(arm, ctx):
    start, _ = arm.sv("machine", "start", "--name", "sb-persist")
    _, out = arm.sv("machine", "exec", "--name", "sb-persist", "--", "echo", "up")
    assert out.strip() == "up", out
    stop, _ = arm.sv("machine", "stop", "--name", "sb-persist")
    return {"start_ms": start, "stop_ms": stop}


def measure_run_bare(arm, ctx):
    ms, out = arm.sv("machine", "run", "--", "echo", "bare-ok")
    assert out.strip() == "bare-ok", out
    return {"run_bare_ms": ms}


def setup_run_image(arm, ctx):
    # The first run builds the image seed; measured rounds are warm.
    arm.sv("machine", "run", "--net", "--image", IMAGE, "--", "true", timeout=900)


def measure_run_image(arm, ctx):
    ms, out = arm.sv("machine", "run", "--net", "--image", IMAGE, "--", "echo", "img-ok")
    assert out.strip() == "img-ok", out
    return {"run_image_ms": ms}


def setup_running(arm, ctx):
    arm.sv("machine", "create", "--name", "sb-run")
    arm.sv("machine", "start", "--name", "sb-run")


def teardown_running(arm, ctx):
    arm.sv("machine", "delete", "--name", "sb-run", "-f", check=False)


def measure_exec(arm, ctx):
    ms, out = arm.sv("machine", "exec", "--name", "sb-run", "--", "echo", "exec-ok")
    assert out.strip() == "exec-ok", out
    return {"exec_ms": ms}


def setup_cp(arm, ctx):
    setup_running(arm, ctx)
    size = ctx["cp_mib"] << 20
    path = os.path.join(arm.home, "cp-src.bin")
    with open(path, "wb") as f:
        f.write(os.urandom(size))
    ctx.setdefault("cp_src", {})[arm.label] = path


def measure_cp(arm, ctx):
    src = ctx["cp_src"][arm.label]
    size_mb = os.path.getsize(src) / 1e6
    up, _ = arm.sv("machine", "cp", src, "sb-run:/workspace/cp.bin")
    dst = os.path.join(arm.home, "cp-dst.bin")
    if os.path.exists(dst):
        os.remove(dst)
    down, _ = arm.sv("machine", "cp", "sb-run:/workspace/cp.bin", dst)
    assert os.path.getsize(dst) == os.path.getsize(src), "download size mismatch"
    return {"cp_upload_mbps": size_mb / (up / 1000), "cp_download_mbps": size_mb / (down / 1000)}


def setup_checkpoint(arm, ctx):
    setup_running(arm, ctx)
    arm.sv("machine", "exec", "--name", "sb-run", "--", "sh", "-c", "echo state > /workspace/s")


def measure_checkpoint(arm, ctx):
    out = os.path.join(arm.home, "sb.checkpoint")
    if os.path.exists(out):
        os.remove(out)
    capture, report = arm.sv("machine", "checkpoint", "--name", "sb-run", "-o", out, timeout=900)
    pause = re.search(r"([0-9.]+)s source pause", report)
    assert pause, f"no source pause in checkpoint output: {report}"
    arm.sv("machine", "delete", "--name", "sb-restored", "-f", check=False)
    t0 = time.perf_counter()
    arm.sv("machine", "create", "--name", "sb-restored", "--from", out, timeout=900)
    arm.sv("machine", "start", "--name", "sb-restored", timeout=900)
    _, got = arm.sv("machine", "exec", "--name", "sb-restored", "--", "cat", "/workspace/s")
    restore = (time.perf_counter() - t0) * 1000
    assert got.strip() == "state", got
    arm.sv("machine", "delete", "--name", "sb-restored", "-f", check=False)
    return {"checkpoint_ms": capture, "checkpoint_pause_ms": float(pause.group(1)) * 1000,
            "restore_ms": restore}


def setup_branch(arm, ctx):
    arm.sv("machine", "create", "--name", "sb-src")
    arm.sv("machine", "start", "--name", "sb-src", "--branchable")


def measure_branch(arm, ctx):
    # A single named branch needs no branchpoint from the workload; --count
    # would wait for one that a bare machine never declares.
    ms, _ = arm.sv("machine", "branch", "--from", "sb-src", "-n", "sb-child", timeout=300)
    _, out = arm.sv("machine", "exec", "--name", "sb-child", "--", "echo", "child-ok")
    assert out.strip() == "child-ok", out
    arm.sv("machine", "delete", "--name", "sb-child", "-f")
    return {"branch_ms": ms}


def teardown_branch(arm, ctx):
    arm.sv("machine", "delete", "--name", "sb-src", "--cascade", check=False)


def setup_pack(arm, ctx):
    arm.sv("machine", "create", "--name", "sb-pack")
    arm.sv("machine", "start", "--name", "sb-pack")
    arm.sv("machine", "stop", "--name", "sb-pack")


def measure_pack(arm, ctx):
    out = os.path.join(arm.home, "sb-pack-out")
    for suffix in ("", ".smolmachine"):
        if os.path.exists(out + suffix):
            os.remove(out + suffix)
    ms, _ = arm.sv("pack", "create", "--from-vm", "sb-pack", "-o", out, timeout=1800)
    assert os.path.exists(out + ".smolmachine"), "pack produced no .smolmachine"
    return {"pack_ms": ms}


def measure_pull_cold(arm, ctx):
    # A fresh image name per round would need the network to serve it, so
    # instead clear this arm's seed and image caches before each run.
    for sub in ("Library/Caches/smolvm/image-seeds", ".cache/smolvm/image-seeds"):
        shutil.rmtree(os.path.join(arm.home, sub), ignore_errors=True)
    ms, out = arm.sv("machine", "run", "--net", "--image", IMAGE, "--", "echo", "cold-ok",
                     timeout=900)
    assert out.strip() == "cold-ok", out
    return {"pull_cold_ms": ms}


SCENARIOS = {
    "start_stop": (setup_persistent, measure_start_stop, None),
    "run_bare": (None, measure_run_bare, None),
    "run_image": (setup_run_image, measure_run_image, None),
    "exec": (setup_running, measure_exec, teardown_running),
    "cp": (setup_cp, measure_cp, teardown_running),
    "checkpoint": (setup_checkpoint, measure_checkpoint, teardown_running),
    "branch": (setup_branch, measure_branch, teardown_branch),
    "pack": (setup_pack, measure_pack, None),
    "pull_cold": (None, measure_pull_cold, None),
}
DEFAULT = ["start_stop", "run_bare", "run_image", "exec", "cp", "checkpoint", "branch", "pack"]


# --- reporting -------------------------------------------------------------


def summary(values):
    xs = sorted(values)
    q = statistics.quantiles(xs, n=4) if len(xs) >= 2 else [xs[0]] * 3
    return {
        "n": len(xs),
        "median": statistics.median(xs),
        "p25": q[0],
        "p75": q[2],
        "min": xs[0],
        "max": xs[-1],
        "values": xs,
    }


def manifest(arms):
    def run(cmd):
        try:
            return subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout.strip()
        except Exception:
            return ""

    cpu = run(["sysctl", "-n", "machdep.cpu.brand_string"]) if sys.platform == "darwin" else ""
    if not cpu and os.path.exists("/proc/cpuinfo"):
        with open("/proc/cpuinfo") as f:
            cpu = next((l.split(":", 1)[1].strip() for l in f if l.startswith("model name")), "")
    binaries = {}
    for arm in arms:
        with open(arm.binary, "rb") as f:
            md5 = hashlib.md5(f.read()).hexdigest()
        binaries[arm.label] = {
            "version": run([arm.binary, "--version"]),
            "md5": md5,
        }
    return {
        "date": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "os": f"{platform.system()} {platform.release()} {platform.machine()}",
        "cpu": cpu,
        "cores": os.cpu_count(),
        "memory_gib": os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") // (1 << 30),
        "binaries": binaries,
    }


def fmt(metric, value):
    return f"{value:.0f} MB/s" if metric.endswith("_mbps") else f"{value:.0f} ms"


def print_table(results, labels):
    print()
    if len(labels) == 1:
        print(f"{'metric':<20} {'median':>10} {'p25-p75':>16} {'n':>3}")
        for metric, arms in results.items():
            s = arms[labels[0]]
            spread = f"{s['p25']:.0f}-{s['p75']:.0f}"
            print(f"{metric:<20} {fmt(metric, s['median']):>10} {spread:>16} {s['n']:>3}")
        return
    a, b = labels
    print(f"{'metric':<20} {a:>12} {b:>12} {'change':>9}  note")
    for metric, arms in results.items():
        sa, sb = arms[a], arms[b]
        change = (sb["median"] - sa["median"]) / sa["median"] * 100
        # Better is lower for times and higher for throughput.
        better = change > 0 if metric.endswith("_mbps") else change < 0
        # Interquartile ranges that do not overlap make the change hard to
        # attribute to noise.
        separated = sb["p75"] < sa["p25"] or sa["p75"] < sb["p25"]
        note = ("better" if better else "worse") if separated else "within noise"
        print(f"{metric:<20} {fmt(metric, sa['median']):>12} {fmt(metric, sb['median']):>12} "
              f"{change:>+8.1f}%  {note}")


# --- main ------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--bin", action="append", required=True,
                        help="smolvm binary, optionally LABEL=PATH; give two for an A/B")
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--only", help="comma separated scenarios: " + ",".join(SCENARIOS))
    parser.add_argument("--cp-mib", type=int, default=256, help="file size for the cp scenario")
    parser.add_argument("--keep", action="store_true", help="keep the scratch homes")
    args = parser.parse_args()
    if len(args.bin) > 2:
        parser.error("give one binary for a baseline or two for an A/B")

    scenarios = args.only.split(",") if args.only else DEFAULT
    unknown = [s for s in scenarios if s not in SCENARIOS]
    if unknown:
        parser.error(f"unknown scenario(s): {', '.join(unknown)}")

    root = tempfile.mkdtemp(prefix="sb-", dir="/tmp")
    arms = []
    for i, spec in enumerate(args.bin):
        label, _, path = spec.rpartition("=")
        arms.append(Arm(label or ("a" if i == 0 else "b"), path, root))
    labels = [arm.label for arm in arms]
    ctx = {"cp_mib": args.cp_mib}
    results = {}
    failures = []

    try:
        for name in scenarios:
            setup, measure, teardown = SCENARIOS[name]
            print(f"== {name}", flush=True)
            try:
                for arm in arms:
                    if setup:
                        setup(arm, ctx)
                for r in range(args.rounds):
                    # Alternate which arm goes first so neither always runs
                    # on the warmer or cooler machine.
                    order = arms if r % 2 == 0 else list(reversed(arms))
                    for arm in order:
                        for metric, value in measure(arm, ctx).items():
                            results.setdefault(metric, {}).setdefault(arm.label, []).append(value)
                    print(f"   round {r + 1}/{args.rounds}", flush=True)
            except Exception as error:
                failures.append(f"{name}: {error}")
                print(f"   FAILED: {error}", flush=True)
            finally:
                for arm in arms:
                    if teardown:
                        teardown(arm, ctx)
    finally:
        # A timed out command can leave a VM behind; nothing under the
        # scratch root may outlive the run.
        subprocess.run(["pkill", "-f", root], capture_output=True)
        if not args.keep:
            shutil.rmtree(root, ignore_errors=True)

    summarized = {
        metric: {label: summary(values) for label, values in arms_values.items()}
        for metric, arms_values in results.items()
        if all(label in arms_values for label in labels)
    }
    print_table(summarized, labels)
    for failure in failures:
        print(f"FAILED {failure}")

    run_id = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    out_dir = os.path.join(HERE, "results")
    os.makedirs(out_dir, exist_ok=True)
    out = os.path.join(out_dir, f"{run_id}.json")
    with open(out, "w") as f:
        json.dump({"manifest": manifest(arms), "rounds": args.rounds, "scenarios": scenarios,
                   "results": summarized, "failures": failures}, f, indent=2)
    print(f"\nwrote {out}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
