
"""Reproduce EVERY principal result with one command (Platform A; optional B and D included).

    python run_all.py            # full run (~3-5 min on a laptop)
    python run_all.py --quick    # smoke run: 20 handshakes, sampled T2, no Platform B/D (~1 min)

Steps (each one can also be run on its own - see README section 3):
  1. common/env_check.py                 environment self-test, writes platform_A_info.json
  2. P1_secure_channel/gen_payloads.py   official payloads + SHA-256 check
  3. run_security_tests.py               T1-T9  -> results/security_tests*.csv
  4. scripts/bench_handshake.py          100 handshakes x 3 suites x 2 modes -> results/handshake_*.csv
  5. scripts/bench_payloads.py           1 KB / 100 KB / 10 MB -> results/payload_results.csv
  6. Platform B (optional)               same benchmarks under common/run_on_platform.py --platform B
  7. Platform D (optional)               scripts/platform_d.py -> results/platform_D/
  8. scripts/make_figures.py             results/figures/*.png
  9. scripts/make_report.py              refreshes the auto-generated tables in report.md and RESULTS.md
"""
import argparse
import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable


def step(title, cmd, required=True):
    print(f"\n{'=' * 100}\n>>> {title}\n$ {' '.join(os.path.relpath(c, ROOT) if os.path.isabs(c) and c != PY else c for c in cmd)}\n",
          flush=True)
    t0 = time.time()
    rc = subprocess.call(cmd, cwd=ROOT)
    print(f"<<< {title}: {'OK' if rc == 0 else f'FAILED (exit {rc})'} in {time.time() - t0:.1f} s", flush=True)
    if rc != 0 and required:
        sys.exit(rc)
    return rc == 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--skip-b", action="store_true", help="skip optional Platform B")
    ap.add_argument("--skip-d", action="store_true", help="skip optional Platform D")
    a = ap.parse_args()
    trials = "20" if a.quick else "100"
    t0 = time.time()
    step("1. Environment check (Platform A record)", [PY, "common/env_check.py"])
    step("2. Official payloads", [PY, "P1_secure_channel/gen_payloads.py"])
    step("3. Security tests T1-T9", [PY, "run_security_tests.py"] + (["--quick"] if a.quick else []))
    step("4. Handshake benchmark (Platform A)", [PY, "scripts/bench_handshake.py", "--trials", trials])
    step("5. Payload benchmark (Platform A)", [PY, "scripts/bench_payloads.py"] + (["--scale", "0.2"] if a.quick else []))
    if not (a.quick or a.skip_b):
        step("6a. Handshake benchmark on Platform B (1 core, 128 MB, single-thread)",
             [PY, "common/run_on_platform.py", "--platform", "B", "--", PY, "scripts/bench_handshake.py",
              "--trials", trials, "--out", "results/platform_B"], required=False)
        step("6b. Payload benchmark on Platform B",
             [PY, "common/run_on_platform.py", "--platform", "B", "--", PY, "scripts/bench_payloads.py",
              "--out", "results/platform_B"], required=False)
    if not (a.quick or a.skip_d):
        step("7. Platform D - emulated network links", [PY, "scripts/platform_d.py"], required=False)
    step("8. Figures", [PY, "scripts/make_figures.py"])
    step("9. Report tables", [PY, "scripts/make_report.py"])
    print(f"\nALL DONE in {time.time() - t0:.0f} s. Results: results/  Figures: results/figures/  "
          f"Report: report.md  Summary: RESULTS.md")


if __name__ == "__main__":
    main()
