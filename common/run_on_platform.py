"""
QFF 2026 Phase 2 - run any command on Platform A or Platform B.

    python common/run_on_platform.py --platform A -- python my_benchmark.py
    python common/run_on_platform.py --platform B -- python my_benchmark.py

Platform A = your machine as-is (all cores, no memory budget).
Platform B = the constrained profile defined in the kit:
             * pinned to ONE CPU core (Windows/Linux; macOS cannot pin - see note)
             * single-threaded math/crypto libraries (thread env vars forced to 1)
             * 128 MB peak-memory budget for the whole process tree; the run is
               stopped and marked BUDGET_EXCEEDED if it goes above that.

Your program can read the active platform from the environment variable QFF_PLATFORM.
A JSON record of every run is appended to platform_runs.jsonl - commit it.

macOS note: macOS does not allow CPU pinning. On macOS Platform B still applies the
single-thread and 128 MB rules, and the run record shows "cpu_pinning": "not supported".
That is accepted - just state it in your report.
"""
import argparse
import json
import os
import subprocess
import sys
import time

import psutil

PROFILES = {
    "A": {"cores": None, "mem_budget_mb": None, "threads": None},
    "B": {"cores": 1, "mem_budget_mb": 128, "threads": 1},
}


def tree_rss(proc):
    total = 0
    try:
        procs = [proc] + proc.children(recursive=True)
    except psutil.Error:
        return 0
    for p in procs:
        try:
            total += p.memory_info().rss
        except psutil.Error:
            pass
    return total


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--platform", choices=["A", "B"], required=True)
    ap.add_argument("--log", default="platform_runs.jsonl")
    ap.add_argument("cmd", nargs=argparse.REMAINDER, help="-- followed by the command to run")
    a = ap.parse_args()
    cmd = a.cmd[1:] if a.cmd and a.cmd[0] == "--" else a.cmd
    if not cmd:
        ap.error("give a command after --")

    prof = PROFILES[a.platform]
    env = dict(os.environ, QFF_PLATFORM=a.platform)
    if prof["threads"]:
        for v in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS",
                  "NUMEXPR_NUM_THREADS", "RAYON_NUM_THREADS", "VECLIB_MAXIMUM_THREADS"):
            env[v] = str(prof["threads"])

    start = time.perf_counter()
    child = psutil.Popen(cmd, env=env)
    pin = "n/a"
    if prof["cores"]:
        try:
            child.cpu_affinity([sorted(psutil.Process().cpu_affinity())[0]])
            pin = "pinned to 1 core"
        except (AttributeError, psutil.Error, OSError):
            pin = "not supported"

    peak, status = 0, "ok"
    budget = prof["mem_budget_mb"] * 2**20 if prof["mem_budget_mb"] else None
    while child.poll() is None:
        if prof["cores"] and pin == "pinned to 1 core":
            for c in child.children(recursive=True):   # keep sub-processes on the same core
                try:
                    c.cpu_affinity(child.cpu_affinity())
                except psutil.Error:
                    pass
        peak = max(peak, tree_rss(child))
        if budget and peak > budget:
            status = "BUDGET_EXCEEDED"
            for c in child.children(recursive=True):
                c.kill()
            child.kill()
            break
        time.sleep(0.01)
    child.wait()
    wall = time.perf_counter() - start

    rec = {
        "platform": a.platform,
        "command": " ".join(cmd),
        "started": time.strftime("%Y-%m-%d %H:%M:%S"),
        "status": status if status != "ok" else ("ok" if child.returncode == 0 else f"exit {child.returncode}"),
        "wall_time_s": round(wall, 3),
        "peak_rss_mb": round(peak / 2**20, 1),
        "mem_budget_mb": prof["mem_budget_mb"],
        "cpu_pinning": pin,
        "threads_forced": prof["threads"],
        "os": sys.platform,
    }
    with open(a.log, "a") as f:
        f.write(json.dumps(rec) + "\n")
    print(f"\n[Platform {a.platform}] status={rec['status']} wall={rec['wall_time_s']}s "
          f"peak_rss={rec['peak_rss_mb']} MB pinning={pin} -> logged to {a.log}")
    sys.exit(0 if rec["status"] == "ok" else 1)


if __name__ == "__main__":
    main()
