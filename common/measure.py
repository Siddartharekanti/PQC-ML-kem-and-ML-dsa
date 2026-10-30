"""
QFF 2026 Phase 2 - shared timing helper (optional, but using it keeps results comparable).

    from common.measure import time_op, summarize
    stats = time_op(lambda: sk.decapsulate(ct), warmup=10, trials=100)

Method (state this in your report):
  * time.perf_counter_ns() around each single call
  * `warmup` untimed calls first, then `trials` timed calls
  * garbage collector disabled during the timed loop
  * report median (primary), p25/p75, IQR, p95, min, max, mean, stdev, n
"""
import gc
import statistics
import time


def summarize(samples_ns):
    s = sorted(samples_ns)
    n = len(s)

    def q(p):
        if n == 1:
            return s[0]
        k = (n - 1) * p
        f = int(k)
        c = min(f + 1, n - 1)
        return s[f] + (s[c] - s[f]) * (k - f)

    ms = 1e6
    return {
        "n": n,
        "median_ms": q(0.5) / ms,
        "p25_ms": q(0.25) / ms,
        "p75_ms": q(0.75) / ms,
        "iqr_ms": (q(0.75) - q(0.25)) / ms,
        "p95_ms": q(0.95) / ms,
        "min_ms": s[0] / ms,
        "max_ms": s[-1] / ms,
        "mean_ms": statistics.fmean(s) / ms,
        "stdev_ms": (statistics.stdev(s) / ms) if n > 1 else 0.0,
    }


def time_op(fn, warmup=10, trials=100):
    for _ in range(warmup):
        fn()
    samples = []
    was = gc.isenabled()
    gc.disable()
    try:
        for _ in range(trials):
            t0 = time.perf_counter_ns()
            fn()
            samples.append(time.perf_counter_ns() - t0)
    finally:
        if was:
            gc.enable()
    return summarize(samples)
