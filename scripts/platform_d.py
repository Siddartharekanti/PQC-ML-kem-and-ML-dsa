"""Platform D (optional) - same handshake over an emulated constrained network link.

    python scripts/platform_d.py                  # 4 link profiles x PQC/classical, 15 trials each
    python scripts/platform_d.py --trials 30 --profiles constrained

Bob runs in his own process, the link emulator (src/qsc/netem.py) in another, Alice in this one.
Every measurement is labelled "emulated network (loopback + netem relay)".
Outputs: results/platform_D/handshake_netem.csv, results/platform_D/handshake_netem_trials.csv
"""
import argparse
import csv
import multiprocessing as mp
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, ROOT)

from qsc import benchlib as B  # noqa: E402
from qsc.lab import Lab  # noqa: E402
from qsc.netem import relay_main  # noqa: E402
from qsc.suites import get_suite  # noqa: E402

# name: (RTT ms, bandwidth Mbit/s, rationale)
PROFILES = {
    "lan": (1, 100, "office LAN / data-centre"),
    "mobile": (50, 10, "4G/LTE mobile broadband"),
    "constrained": (100, 1, "congested Wi-Fi / rural link / satellite backhaul share"),
    "narrowband": (300, 0.1, "IoT / LPWAN-class or HF-radio link (100 kbit/s)"),
}


def model_ms(rtt, mbps, c2s_first, s2c_flight, compute_ms):
    """Analytical expectation for Alice's handshake time (CH sent -> CV/CF sent)."""
    ser = lambda b: 8 * b / (mbps * 1e6) * 1e3  # noqa: E731
    return rtt + ser(c2s_first) + ser(s2c_flight) + compute_ms


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--suites", default="pqc,classical")
    ap.add_argument("--profiles", default=",".join(PROFILES))
    ap.add_argument("--trials", type=int, default=15)
    ap.add_argument("--warmup", type=int, default=2)
    ap.add_argument("--out", default=os.path.join(ROOT, "results", "platform_D"))
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    lab = Lab(server_suites=B.ALL_SUITES)
    server, port = B.start_server(B.server_spec(lab))
    # compute-only reference (in-process medians) for the analytical model
    ref = {}
    for s in [get_suite(x) for x in a.suites.split(",")]:
        tr = B.run_inproc(lab, s, 30, 5)
        ok = [t for t in tr if t["ok"]]
        ref[s.label] = (B.stats_ms([t["handshake_ns"] for t in ok])["median_ms"],
                        len(ok[0]["msgs"]["CH"]),
                        sum(len(ok[0]["msgs"][m]) for m in ("SH", "SV", "SF")))
    ctx = mp.get_context("spawn")
    rows, raw = [], []
    print(f"{'profile':12s} {'RTT':>5s} {'Mbit/s':>7s} {'suite':10s} {'hs median ms':>12s} {'IQR':>7s} "
          f"{'model ms':>9s} {'connect->confirmed ms':>22s} {'bytes':>6s} ok")
    try:
        for pname in a.profiles.split(","):
            rtt, mbps, why = PROFILES[pname]
            q = ctx.Queue()
            relay = ctx.Process(target=relay_main, args=(port, rtt, mbps, q), daemon=True)
            relay.start()
            rport = q.get(timeout=30)
            for suite in [get_suite(x) for x in a.suites.split(",")]:
                trials = B.run_tcp(lab, suite, "127.0.0.1", rport, a.trials, a.warmup)
                ok = [t for t in trials if t.get("ok")]
                st = B.stats_ms([t["handshake_ns"] for t in ok])
                cf = B.stats_ms([t["connect_to_confirmed_ns"] for t in ok])
                comp, ch_b, sflight_b = ref[suite.label]
                m = model_ms(rtt, mbps, ch_b, sflight_b, comp)
                row = {"platform": "D", "profile": pname, "rtt_ms": rtt, "bandwidth_mbps": mbps, "rationale": why,
                       "mode": "PQC" if suite.label == "PQC" else ("classical-baseline" if suite.is_baseline else suite.label),
                       "kem": suite.kem.name, "signature": suite.sig.name, "trials": len(trials),
                       "median_handshake_ms": round(st["median_ms"], 2), "iqr_ms": round(st["iqr_ms"], 2),
                       "p95_ms": round(st["p95_ms"], 2), "model_handshake_ms": round(m, 2),
                       "median_connect_to_confirmed_ms": round(cf["median_ms"], 2),
                       "total_handshake_bytes": ok[0]["c2s_bytes"] + ok[0]["s2c_bytes"],
                       "success_count": len(ok), "failure_count": len(trials) - len(ok),
                       "local_or_network": "emulated network (loopback + netem relay)"}
                rows.append(row)
                for i, t in enumerate(trials):
                    raw.append({"profile": pname, "suite": suite.label, "trial": i, "ok": t.get("ok"),
                                "handshake_ms": round(t.get("handshake_ns", 0) / 1e6, 3),
                                "connect_to_confirmed_ms": round(t.get("connect_to_confirmed_ns", 0) / 1e6, 3)})
                print(f"{pname:12s} {rtt:>5} {mbps:>7} {suite.label:10s} {row['median_handshake_ms']:>12} "
                      f"{row['iqr_ms']:>7} {row['model_handshake_ms']:>9} {row['median_connect_to_confirmed_ms']:>22} "
                      f"{row['total_handshake_bytes']:>6} {len(ok)}/{len(trials)}")
            relay.terminate()
            relay.join(5)
    finally:
        server.terminate()
        server.join(5)
    for fname, data in (("handshake_netem.csv", rows), ("handshake_netem_trials.csv", raw)):
        with open(os.path.join(a.out, fname), "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(data[0]))
            w.writeheader()
            w.writerows(data)
    print(f"\n-> {os.path.relpath(a.out, ROOT)}/handshake_netem.csv")
    sys.exit(0 if all(r["failure_count"] == 0 for r in rows) else 1)


if __name__ == "__main__":
    main()
