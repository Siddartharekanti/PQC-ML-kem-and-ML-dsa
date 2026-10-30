"""PS-P1 mandatory security test suite T1-T9 - ONE COMMAND:

    python run_security_tests.py                 # PQC suite + classical baseline + hybrid extension (~1 min)
    python run_security_tests.py --suites pqc    # PQC only
    python run_security_tests.py --quick         # T2 samples bit positions instead of flipping every byte

Prints PASS/FAIL and the observed behaviour for every test and sub-case, and writes
  results/security_tests.csv           (organizer template columns, one row per suite x test)
  results/security_tests_detailed.csv  (every sub-case)
Exit code 0 only if every test passes.
"""
import argparse
import csv
import os
import sys
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(ROOT, "tests"))
sys.path.insert(0, os.path.join(ROOT, "src"))

import security_suite as ss  # noqa: E402
from qsc.suites import get_suite  # noqa: E402

FAULTS = {
    "T1": "none",
    "T2": "1-bit flips in every field of every handshake message (KEM pk, KEM ct, nonces, identities, key ids, "
          "algorithm ids, signatures, Finished, headers) + random positions",
    "T3": "bit flip in ML-DSA/Ed25519 signature (ServerVerify and ClientVerify); random signature",
    "T4": "bit flip in application-record ciphertext (both directions; one fragment of the 10 MB message)",
    "T5": "bit flip in GCM tag, in every header (AAD) field; truncated tag",
    "T6": "attacker's own valid key + valid signature; copied key id; unpinned identities (client and server side)",
    "T7": "Bob's genuine signed flight replayed into a session naming another peer; trusted-but-different "
          "server; swapped role fields; role reflection of a signature",
    "T8": "record replay, reorder, reflection, cross-session replay; old ClientHello replay; full old "
          "handshake vs restarted server; old server flight",
    "T9": "suite id / algorithm ids / version rewritten in ClientHello and ServerHello; active MITM "
          "downgrade to X25519+Ed25519 against a migration-mode server",
}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--suites", default="pqc,classical,hybrid",
                    help="comma list of pqc, classical, hybrid (default: all three)")
    ap.add_argument("--tests", default="T1,T2,T3,T4,T5,T6,T7,T8,T9")
    ap.add_argument("--quick", action="store_true",
                    help="T2: flip bits in every field + 128 random positions per message instead of "
                         "one bit in EVERY byte (default: every byte)")
    ap.add_argument("--out", default=os.path.join(ROOT, "results"))
    a = ap.parse_args()

    suites = [get_suite(x.strip()) for x in a.suites.split(",") if x.strip()]
    tests = [t for t in ss.TESTS if t[0] in {x.strip().upper() for x in a.tests.split(",")}]
    os.makedirs(a.out, exist_ok=True)
    cmd = "python run_security_tests.py" + (f" --suites {a.suites}" if a.suites != "pqc,classical,hybrid" else "") \
        + (" --quick" if a.quick else "")

    print("QFF 2026 PS-P1 - security test suite (SECURITY_TESTS.md)")
    print("Mode: local, in-process (faults injected by a man-in-the-middle hook on the serialized bytes)\n")
    payloads = ss.load_all()
    lab = ss.make_lab()
    rows, detail, all_ok = [], [], True
    for suite in suites:
        print(f"=== Suite {suite}{'  [classical baseline]' if suite.is_baseline else ''}")
        for tid, desc, _ in tests:
            t0 = time.perf_counter()
            cases = ss.run_test(tid, lab, suite, payloads, exhaustive=not a.quick)
            dt = time.perf_counter() - t0
            ok = all(c.ok for c in cases)
            all_ok &= ok
            print(f"[{'PASS' if ok else 'FAIL'}] {tid} {desc}: {sum(c.ok for c in cases)}/{len(cases)} sub-cases "
                  f"({dt:.1f} s)")
            for c in cases:
                print(f"     {'PASS' if c.ok else 'FAIL'}  {c.name}: {c.observed}")
                detail.append({"suite": suite.label, "test_id": tid, "case": c.name, "injected_fault": c.fault,
                               "expected": c.expected, "observed": c.observed, "result": "PASS" if c.ok else "FAIL"})
            observed = f"{sum(c.ok for c in cases)}/{len(cases)} sub-cases as expected: " + \
                "; ".join(f"{c.name} -> {c.observed.split(';')[0][:90]}" for c in cases[:3]) + \
                ("; ..." if len(cases) > 3 else "")
            rows.append({"test_id": tid, "description": desc, "injected_fault": FAULTS[tid],
                         "expected": ss.EXPECTED[tid], "observed": observed,
                         "result": "PASS" if ok else "FAIL", "run_command": cmd,
                         "suite": suite.label, "subcases_passed": sum(c.ok for c in cases),
                         "subcases_total": len(cases), "seconds": round(dt, 2)})
        print()

    with open(os.path.join(a.out, "security_tests.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    with open(os.path.join(a.out, "security_tests_detailed.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(detail[0]))
        w.writeheader()
        w.writerows(detail)
    n_pass = sum(r["result"] == "PASS" for r in rows)
    print(f"{'ALL TESTS PASSED' if all_ok else 'SOME TESTS FAILED'}: {n_pass}/{len(rows)} (suite x test); "
          f"{sum(d['result'] == 'PASS' for d in detail)}/{len(detail)} sub-cases")
    print(f"-> {os.path.relpath(os.path.join(a.out, 'security_tests.csv'), ROOT)}, "
          f"{os.path.relpath(os.path.join(a.out, 'security_tests_detailed.csv'), ROOT)}")
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
