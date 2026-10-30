"""Objective 3 - handshake latency, bytes on the wire, success counts, primitive costs.

    python scripts/bench_handshake.py                       # 100 trials, in-process + TCP loopback, 3 suites
    python scripts/bench_handshake.py --trials 10 --modes inproc

Outputs (in --out, default results/):
  handshake_results.csv   organizer template + extra columns, one row per suite x mode
  handshake_trials.csv    every trial (raw samples)
  handshake_bytes.csv     serialized bytes per handshake message, split into crypto material / ids / framing
  primitive_timings.csv   per-operation cost (KEM keygen/encaps/decaps, sign, verify, key schedule)

Modes (labelled in every row):
  inproc   = local, in-process: both endpoints in one Python process, no sockets (pure protocol cost)
  loopback = local, TCP over 127.0.0.1: Bob runs in a separate process; real serialization + socket I/O
"""
import argparse
import csv
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, ROOT)

from common.measure import time_op  # noqa: E402
from qsc import benchlib as B  # noqa: E402
from qsc.keyschedule import HandshakeKeys, extract  # noqa: E402
from qsc.lab import Lab  # noqa: E402
from qsc.suites import get_suite  # noqa: E402


def write_csv(path, rows):
    fields = []
    for r in rows:
        fields += [k for k in r if k not in fields]
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, restval="")
        w.writeheader()
        w.writerows(rows)


def primitive_rows(suite, trials, warmup, platform):
    kem, sig = suite.kem, suite.sig
    sk, pk = kem.keygen()
    ss, ct = kem.encap(pk)
    isk, ipk = sig.keygen()
    th = os.urandom(32)
    s = sig.sign(isk, th, b"ctx")
    ops = [
        ("kem_keygen", f"{kem.name} KeyGen (ephemeral, Alice)", lambda: kem.keygen()),
        ("kem_encaps", f"{kem.name} Encaps (Bob)", lambda: kem.encap(pk)),
        ("kem_decaps", f"{kem.name} Decaps (Alice)", lambda: kem.decap(sk, ct)),
        ("sig_sign", f"{sig.name} Sign (each side once)", lambda: sig.sign(isk, th, b"ctx")),
        ("sig_verify", f"{sig.name} Verify (each side once)", lambda: sig.verify(ipk, s, th, b"ctx")),
        ("key_schedule", "HKDF-SHA256 extract + 7 expands", lambda: HandshakeKeys(extract(th * 2, ss), 1, th).traffic(th)),
    ]
    rows = []
    for op, desc, fn in ops:
        st = time_op(fn, warmup=warmup, trials=trials)
        rows.append({"platform": platform, "suite": suite.label, "operation": op, "description": desc,
                     "trials": st["n"], "median_ms": round(st["median_ms"], 4), "iqr_ms": round(st["iqr_ms"], 4),
                     "p95_ms": round(st["p95_ms"], 4), "local_or_network": "local (in-process)"})
    return rows


def summary_row(run_id, platform, suite, mode, trials, label, extra=None):
    ok = [t for t in trials if t.get("ok")]
    st = B.stats_ms([t["handshake_ns"] for t in ok]) if ok else None
    if mode == "inproc":
        c2s = sum(len(ok[0]["msgs"][m]) for m in ("CH", "CV", "CF")) if ok else ""
        s2c = sum(len(ok[0]["msgs"][m]) for m in ("SH", "SV", "SF")) if ok else ""
    else:
        c2s = ok[0]["c2s_bytes"] if ok else ""
        s2c = ok[0]["s2c_bytes"] if ok else ""
    row = {
        "run_id": run_id, "platform": platform,
        "mode": "PQC" if suite.label == "PQC" else ("classical-baseline" if suite.is_baseline else "hybrid-extension"),
        "kem": suite.kem.name, "signature": suite.sig.name, "trials": len(trials),
        "median_handshake_ms": round(st["median_ms"], 3) if st else "", "iqr_ms": round(st["iqr_ms"], 3) if st else "",
        "p95_ms": round(st["p95_ms"], 3) if st else "",
        "client_to_server_bytes": c2s, "server_to_client_bytes": s2c,
        "total_handshake_bytes": (c2s + s2c) if ok else "",
        "success_count": len(ok), "failure_count": len(trials) - len(ok), "local_or_network": label,
        "measurement": mode, "p25_ms": round(st["p25_ms"], 3) if st else "", "p75_ms": round(st["p75_ms"], 3) if st else "",
        "min_ms": round(st["min_ms"], 3) if st else "", "mean_ms": round(st["mean_ms"], 3) if st else "",
        "round_trips": 1,
    }
    row.update(extra or {})
    return row


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--suites", default="pqc,classical,hybrid")
    ap.add_argument("--modes", default="inproc,loopback")
    ap.add_argument("--trials", type=int, default=100)
    ap.add_argument("--warmup", type=int, default=10)
    ap.add_argument("--prim-trials", type=int, default=200)
    ap.add_argument("--out", default=os.path.join(ROOT, "results"))
    a = ap.parse_args()
    if a.trials < 10:
        ap.error("PS-P1 requires at least 10 successful handshakes")
    os.makedirs(a.out, exist_ok=True)
    platform = B.platform_label()
    suites = [get_suite(s) for s in a.suites.split(",")]
    modes = a.modes.split(",")
    lab = Lab(server_suites=B.ALL_SUITES)

    summary, raw, byte_rows, prim = [], [], [], []
    server = None
    if "loopback" in modes:
        server, port = B.start_server(B.server_spec(lab))
    run_id = 0
    print(f"Platform {platform}: {a.trials} trials (+{a.warmup} warm-up) per suite and mode\n")
    print(f"{'suite':10s} {'mode':9s} {'median ms':>10s} {'IQR ms':>8s} {'p95 ms':>8s} {'C->S B':>7s} {'S->C B':>7s} "
          f"{'total B':>8s} {'ok':>4s}")
    for suite in suites:
        for mode in modes:
            run_id += 1
            if mode == "inproc":
                trials = B.run_inproc(lab, suite, a.trials, a.warmup)
                ok = [t for t in trials if t.get("ok")]
                cs = B.stats_ms([t["client_ns"] for t in ok])
                ss = B.stats_ms([t["server_ns"] for t in ok])
                extra = {"client_compute_median_ms": round(cs["median_ms"], 3),
                         "server_compute_median_ms": round(ss["median_ms"], 3)}
                label = "local (in-process)"
                if ok:
                    byte_rows += B.byte_breakdown(ok[0]["msgs"], suite)
            else:
                trials = B.run_tcp(lab, suite, "127.0.0.1", port, a.trials, a.warmup)
                ok = [t for t in trials if t.get("ok")]
                tc = B.stats_ms([t["tcp_connect_ns"] for t in ok])
                cf = B.stats_ms([t["connect_to_confirmed_ns"] for t in ok])
                extra = {"tcp_connect_median_ms": round(tc["median_ms"], 3),
                         "connect_to_first_authenticated_reply_median_ms": round(cf["median_ms"], 3)}
                label = "local (TCP loopback 127.0.0.1)"
            row = summary_row(run_id, platform, suite, mode, trials, label, extra)
            summary.append(row)
            for i, t in enumerate(trials):
                raw.append({"platform": platform, "suite": suite.label, "measurement": mode, "trial": i,
                            "ok": t.get("ok"), "handshake_ms": round(t.get("handshake_ns", 0) / 1e6, 4),
                            "client_compute_ms": round(t.get("client_ns", 0) / 1e6, 4) if mode == "inproc" else "",
                            "server_compute_ms": round(t.get("server_ns", 0) / 1e6, 4) if mode == "inproc" else "",
                            "tcp_connect_ms": round(t.get("tcp_connect_ns", 0) / 1e6, 4) if mode != "inproc" else "",
                            "error": t.get("error", "")})
            print(f"{suite.label:10s} {mode:9s} {row['median_handshake_ms']:>10} {row['iqr_ms']:>8} {row['p95_ms']:>8} "
                  f"{row['client_to_server_bytes']:>7} {row['server_to_client_bytes']:>7} "
                  f"{row['total_handshake_bytes']:>8} {row['success_count']:>4}")
        prim += primitive_rows(suite, a.prim_trials, a.warmup, platform)
    if server is not None:
        server.terminate()
        server.join(5)

    write_csv(os.path.join(a.out, "handshake_results.csv"), summary)
    write_csv(os.path.join(a.out, "handshake_trials.csv"), raw)
    if byte_rows:
        write_csv(os.path.join(a.out, "handshake_bytes.csv"), byte_rows)
    write_csv(os.path.join(a.out, "primitive_timings.csv"), prim)
    print(f"\n-> {os.path.relpath(a.out, ROOT)}/handshake_results.csv, handshake_trials.csv, handshake_bytes.csv, "
          f"primitive_timings.csv")
    total_fail = sum(r["failure_count"] for r in summary)
    sys.exit(0 if total_fail == 0 else 1)


if __name__ == "__main__":
    main()
