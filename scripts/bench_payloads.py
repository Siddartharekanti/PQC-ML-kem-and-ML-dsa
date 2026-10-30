"""Objective 3 - encrypt/decrypt time and overhead for the three official payloads.

    python scripts/bench_payloads.py                 # PQC + classical sessions, 16 KiB records
    python scripts/bench_payloads.py --record-sizes 16384,max

Each trial encrypts the payload into records (Alice) and decrypts + reassembles it (Bob) inside an
established session; the SHA-256 of every decrypted payload is checked against payload_sha256.txt.
Measurement: local, in-process (no sockets), so only the record-layer cost is measured.
Output: results/payload_results.csv (organizer template columns + extras).
"""
import argparse
import csv
import hashlib
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, ROOT)

from common.measure import summarize  # noqa: E402
from qsc.benchlib import gc_off, platform_label  # noqa: E402
from qsc.lab import Lab  # noqa: E402
from qsc.payloads import load_all, official_hashes  # noqa: E402
from qsc.record import HEADER_LEN, NONCE_LEN, RECORD_OVERHEAD, TAG_LEN  # noqa: E402
from qsc.suites import CLASSICAL, HYBRID, PQC, get_suite  # noqa: E402

TRIALS = {"payload_1KB.bin": 200, "payload_100KB.bin": 100, "payload_10MB.bin": 15}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--suites", default="pqc,classical")
    ap.add_argument("--record-sizes", default="16384,max", help="comma list; 'max' = one record per payload")
    ap.add_argument("--scale", type=float, default=1.0, help="multiply trial counts (e.g. 0.2 for a quick run)")
    ap.add_argument("--out", default=os.path.join(ROOT, "results"))
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    platform = platform_label()
    payloads, want = load_all(), official_hashes()
    lab = Lab(server_suites=(PQC, CLASSICAL, HYBRID))
    rows = []
    print(f"{'suite':10s} {'payload':18s} {'rec size':>8s} {'records':>7s} {'ct bytes':>10s} {'ovh B':>6s} "
          f"{'enc ms':>9s} {'dec ms':>9s} {'MB/s enc':>8s} sha256")
    for suite in [get_suite(s) for s in a.suites.split(",")]:
        for rs_txt in a.record_sizes.split(","):
            for name, data in payloads.items():
                rs = len(data) if rs_txt == "max" else int(rs_txt)
                c, s, _ = lab.handshake(suite)
                n = max(5, int(TRIALS[name] * a.scale))
                enc, dec, match, ct_bytes, nrec = [], [], True, 0, 0
                for i in range(n + 2):  # first 2 = warm-up
                    with gc_off():
                        t0 = time.perf_counter_ns()
                        recs = c.send_message(data, rs)
                        t1 = time.perf_counter_ns()
                        out = s.receive_message(recs)
                        t2 = time.perf_counter_ns()
                    if i >= 2:
                        enc.append(t1 - t0)
                        dec.append(t2 - t1)
                        match &= hashlib.sha256(out).hexdigest() == want[name]
                    ct_bytes, nrec = sum(map(len, recs)), len(recs)
                    del recs, out
                se, sd = summarize(enc), summarize(dec)
                ovh = ct_bytes - len(data)
                row = {"platform": platform,
                       "mode": "PQC" if suite.label == "PQC" else ("classical-baseline" if suite.is_baseline else suite.label),
                       "payload": name, "plaintext_bytes": len(data), "ciphertext_bytes": ct_bytes,
                       "overhead_bytes": ovh, "trials": n, "median_encrypt_ms": round(se["median_ms"], 4),
                       "median_decrypt_ms": round(sd["median_ms"], 4), "sha256_match": match,
                       "record_size": rs, "records": nrec,
                       "overhead_per_record_bytes": f"{HEADER_LEN} header + {TAG_LEN} tag + 0 nonce (implicit {NONCE_LEN} B)",
                       "overhead_pct": round(100 * ovh / len(data), 3),
                       "encrypt_iqr_ms": round(se["iqr_ms"], 4), "decrypt_iqr_ms": round(sd["iqr_ms"], 4),
                       "encrypt_MBps": round(len(data) / 1e6 / (se["median_ms"] / 1e3), 1),
                       "decrypt_MBps": round(len(data) / 1e6 / (sd["median_ms"] / 1e3), 1),
                       "local_or_network": "local (in-process)"}
                assert ovh == nrec * RECORD_OVERHEAD
                rows.append(row)
                print(f"{suite.label:10s} {name:18s} {rs:>8d} {nrec:>7d} {ct_bytes:>10,d} {ovh:>6d} "
                      f"{row['median_encrypt_ms']:>9} {row['median_decrypt_ms']:>9} {row['encrypt_MBps']:>8} "
                      f"{'match' if match else 'MISMATCH'}")
    with open(os.path.join(a.out, "payload_results.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    print(f"\n-> {os.path.relpath(os.path.join(a.out, 'payload_results.csv'), ROOT)}")
    sys.exit(0 if all(r["sha256_match"] for r in rows) else 1)


if __name__ == "__main__":
    main()
