"""Regenerate RESULTS.md and the <!-- AUTO:... --> tables inside report.md from results/*.csv.

    python scripts/make_report.py

Every number in the report tables comes from a CSV written by a benchmark/test script, so the
report always matches the committed raw data.
"""
import csv
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES = os.path.join(ROOT, "results")


def read(path):
    p = os.path.join(RES, path)
    if not os.path.exists(p):
        return []
    with open(p) as f:
        return list(csv.DictReader(f))


def table(headers, rows):
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


def fnum(x, nd=3):
    try:
        return f"{float(x):.{nd}f}"
    except (TypeError, ValueError):
        return str(x)


def suite_name(mode):
    return {"PQC": "PQC (ML-KEM-768 + ML-DSA-65)", "classical-baseline": "Baseline (X25519 + Ed25519)",
            "hybrid-extension": "Hybrid ext. (X25519+ML-KEM-768 + ML-DSA-65)"}.get(mode, mode)


def blk_platform():
    p = os.path.join(ROOT, "platform_A_info.json")
    if not os.path.exists(p):
        return "_platform_A_info.json not found - run `python common/env_check.py`_"
    i = json.load(open(p))
    v = i.get("versions", {})
    return table(["Item", "Value"], [
        ["Platform", "A (team laptop/desktop, as-is)"], ["OS", f"{i['os']} ({i['machine']})"],
        ["CPU", f"{i['cpu_model']}, {i['physical_cores']} physical / {i['logical_cores']} logical cores"],
        ["RAM", f"{i['ram_total_gb']} GB"], ["Python", f"{i['python']} ({i['python_impl']})"],
        ["Libraries", f"cryptography {v.get('cryptography', '?')}, pqcrypto {v.get('pqcrypto', '?')}, "
                      f"psutil {v.get('psutil', '?')}"],
        ["On battery", i.get("on_battery")], ["Recorded", i["recorded_at"]]])


def blk_security():
    rows = read("security_tests.csv")
    if not rows:
        return "_run `python run_security_tests.py`_"
    suites = list(dict.fromkeys(r["suite"] for r in rows))
    tids = list(dict.fromkeys(r["test_id"] for r in rows))
    by = {(r["suite"], r["test_id"]): r for r in rows}
    body = []
    for t in tids:
        r0 = by[(suites[0], t)]
        body.append([t, r0["description"], r0["expected"]] +
                    [f"**{by[(s, t)]['result']}** ({by[(s, t)]['subcases_passed']}/{by[(s, t)]['subcases_total']})"
                     for s in suites])
    det = read("security_tests_detailed.csv")
    n_ok = sum(d["result"] == "PASS" for d in det)
    return (table(["ID", "Test", "Expected"] + [f"{s}" for s in suites], body) +
            f"\n\n{n_ok}/{len(det)} sub-cases passed. Command: `{rows[0]['run_command']}`. "
            f"Every sub-case with its observed error message: `results/security_tests_detailed.csv`.")


def blk_handshake(path="handshake_results.csv"):
    rows = read(path)
    if not rows:
        return "_not run_"
    body = [[suite_name(r["mode"]), r["local_or_network"], f"{r['success_count']}/{r['trials']}",
             fnum(r["median_handshake_ms"]), fnum(r["iqr_ms"]), fnum(r["p95_ms"]),
             r["client_to_server_bytes"], r["server_to_client_bytes"], f"**{r['total_handshake_bytes']}**"]
            for r in rows]
    return table(["Suite", "Measurement", "OK / trials", "Median ms", "IQR ms", "p95 ms", "C->S B", "S->C B",
                  "Total B"], body)


def blk_compute():
    rows = [r for r in read("handshake_results.csv") if r["measurement"] == "inproc"]
    if not rows:
        return ""
    return table(["Suite", "Alice compute median ms", "Bob compute median ms"],
                 [[suite_name(r["mode"]), fnum(r["client_compute_median_ms"]), fnum(r["server_compute_median_ms"])]
                  for r in rows])


def blk_bytes():
    rows = read("handshake_bytes.csv")
    if not rows:
        return "_not run_"
    msgs = list(dict.fromkeys(r["message"] for r in rows))
    suites = list(dict.fromkeys(r["suite"] for r in rows))
    by = {(r["suite"], r["message"]): r for r in rows}
    body = []
    for m in msgs:
        r = by[(suites[0], m)]
        body.append([f"{m} {r['message_name']}", r["direction"]] + [by[(s, m)]["bytes"] for s in suites] +
                    [by[("PQC", m)]["fields"].replace("; ", ", ")] if ("PQC", m) in by else [])
    body.append(["**Total**", ""] + [f"**{sum(int(by[(s, m)]['bytes']) for m in msgs):,}**" for s in suites] + [""])
    return table(["Message", "Direction"] + [f"{s} B" for s in suites] + ["PQC field sizes (B)"], body)


def blk_payloads(path="payload_results.csv"):
    rows = read(path)
    if not rows:
        return "_not run_"
    body = [[suite_name(r["mode"]), r["payload"], f"{int(r['plaintext_bytes']):,}", r["record_size"], r["records"],
             f"{int(r['ciphertext_bytes']):,}", f"{r['overhead_bytes']} ({r['overhead_pct']} %)", r["trials"],
             fnum(r["median_encrypt_ms"], 4), fnum(r["median_decrypt_ms"], 4), r["encrypt_MBps"], r["decrypt_MBps"],
             "yes" if r["sha256_match"] == "True" else "**NO**"] for r in rows]
    return table(["Session", "Payload", "Plaintext B", "Record size", "Records", "Wire B", "Overhead B",
                  "Trials", "Enc median ms", "Dec median ms", "Enc MB/s", "Dec MB/s", "SHA-256 match"], body)


def blk_prims():
    rows = read("primitive_timings.csv")
    if not rows:
        return "_not run_"
    return table(["Suite", "Operation", "Median ms", "IQR ms", "p95 ms", "n"],
                 [[r["suite"], r["description"], fnum(r["median_ms"], 4), fnum(r["iqr_ms"], 4), fnum(r["p95_ms"], 4),
                   r["trials"]] for r in rows])


def ratios():
    rows = read("handshake_results.csv")
    by = {(r["mode"], r["measurement"]): r for r in rows}
    out = {}
    for meas in ("inproc", "loopback"):
        p, c = by.get(("PQC", meas)), by.get(("classical-baseline", meas))
        if p and c:
            out[meas] = (float(p["median_handshake_ms"]), float(c["median_handshake_ms"]),
                         float(p["median_handshake_ms"]) / float(c["median_handshake_ms"]))
    p, c = by.get(("PQC", "inproc")), by.get(("classical-baseline", "inproc"))
    if p and c:
        out["bytes"] = (int(p["total_handshake_bytes"]), int(c["total_handshake_bytes"]),
                        int(p["total_handshake_bytes"]) / int(c["total_handshake_bytes"]))
    return out


def blk_ratios():
    r = ratios()
    if not r:
        return ""
    lines = []
    if "bytes" in r:
        p, c, x = r["bytes"]
        lines.append(f"- **Bytes:** PQC handshake = {p:,} B vs baseline {c:,} B -> **{x:.1f}x** "
                     f"(+{p - c:,} B per handshake; deterministic, identical on every machine).")
    for meas, lab in (("inproc", "in-process"), ("loopback", "TCP loopback")):
        if meas in r:
            p, c, x = r[meas]
            lines.append(f"- **Latency ({lab}):** PQC median {p:.3f} ms vs baseline {c:.3f} ms -> **{x:.2f}x** "
                         f"(+{p - c:.3f} ms).")
    pr = read("payload_results.csv")
    big = [x for x in pr if x["payload"] == "payload_10MB.bin" and x["record_size"] == "16384"]
    if len(big) >= 2:
        lines.append("- **Record layer:** identical AES-256-GCM in both suites - 10 MB encrypt median "
                     + " vs ".join(f"{fnum(b['median_encrypt_ms'], 2)} ms ({b['mode']})" for b in big)
                     + "; PQC changes only the handshake.")
    return "\n".join(lines)


def blk_platform_b():
    a = read("handshake_results.csv")
    b = read(os.path.join("platform_B", "handshake_results.csv"))
    log = os.path.join(ROOT, "platform_runs.jsonl")
    if not b:
        return "_Platform B not run (optional)._"
    ia = {(r["mode"], r["measurement"]): r for r in a}
    body = []
    for r in b:
        ra = ia.get((r["mode"], r["measurement"]))
        ratio = f"{float(r['median_handshake_ms']) / float(ra['median_handshake_ms']):.2f}" if ra else ""
        body.append([suite_name(r["mode"]), r["measurement"], f"{r['success_count']}/{r['trials']}",
                     fnum(ra["median_handshake_ms"]) if ra else "", fnum(r["median_handshake_ms"]), ratio])
    runs = []
    if os.path.exists(log):
        for line in open(log):
            j = json.loads(line)
            if j.get("platform") == "B":
                runs.append(j)
    ev = ""
    if runs:
        ev = "\n\nPlatform B evidence (`platform_runs.jsonl`): " + "; ".join(
            f"`{os.path.basename(j['command'].split()[1]) if len(j['command'].split()) > 1 else j['command']}` "
            f"status={j['status']}, peak RSS {j['peak_rss_mb']} MB / {j['mem_budget_mb']} MB, {j['cpu_pinning']}"
            for j in runs[-2:])
    return table(["Suite", "Measurement", "OK/trials (B)", "A median ms", "B median ms", "B/A"], body) + ev


def blk_platform_d():
    rows = read(os.path.join("platform_D", "handshake_netem.csv"))
    if not rows:
        return "_Platform D not run (optional)._"
    body = [[r["profile"], r["rtt_ms"], r["bandwidth_mbps"], suite_name(r["mode"]), f"{r['success_count']}/{r['trials']}",
             fnum(r["median_handshake_ms"], 2), fnum(r["iqr_ms"], 2), fnum(r["model_handshake_ms"], 2),
             fnum(r["median_connect_to_confirmed_ms"], 2), r["total_handshake_bytes"]] for r in rows]
    prof = list(dict.fromkeys(r["profile"] for r in rows))
    by = {(r["profile"], r["mode"]): r for r in rows}
    extra = []
    for p in prof:
        a, c = by.get((p, "PQC")), by.get((p, "classical-baseline"))
        if a and c:
            extra.append(f"{p}: PQC/baseline = {float(a['median_handshake_ms']) / float(c['median_handshake_ms']):.2f}x "
                         f"(+{float(a['median_handshake_ms']) - float(c['median_handshake_ms']):.1f} ms)")
    return table(["Profile", "RTT ms", "Mbit/s", "Suite", "OK/trials", "Handshake median ms", "IQR ms",
                  "Model ms", "Connect->confirmed ms", "Bytes"], body) + "\n\n" + "; ".join(extra) + "."


BLOCKS = {"platform": blk_platform, "security": blk_security, "handshake": blk_handshake, "compute": blk_compute,
          "bytes": blk_bytes, "payloads": blk_payloads, "prims": blk_prims, "ratios": blk_ratios,
          "platform_b": blk_platform_b, "platform_d": blk_platform_d}


def fill(path):
    if not os.path.exists(path):
        return
    text = open(path, encoding="utf-8").read()
    for name, fn in BLOCKS.items():
        pat = re.compile(rf"(<!-- AUTO:{name} -->)(.*?)(<!-- /AUTO:{name} -->)", re.S)
        text = pat.sub(lambda m: m.group(1) + "\n" + fn() + "\n" + m.group(3), text)
    open(path, "w", encoding="utf-8").write(text)


def results_md():
    parts = ["# Results summary (auto-generated by `python scripts/make_report.py` - do not edit)\n",
             "All measurements are labelled local (in-process / TCP loopback) or emulated network.\n",
             "## Platform A\n", blk_platform(), "\n## Security tests T1-T9\n", blk_security(),
             "\n## Handshake latency and bytes (Platform A)\n", blk_handshake(), "\n", blk_compute(),
             "\n### PQC vs classical baseline\n", blk_ratios(), "\n## Bytes per handshake message\n", blk_bytes(),
             "\n## Official payloads (record layer)\n", blk_payloads(), "\n## Primitive costs\n", blk_prims(),
             "\n## Platform B (optional)\n", blk_platform_b(), "\n## Platform D (optional)\n", blk_platform_d(),
             "\n## Figures\n", "![latency](results/figures/fig1_handshake_latency.png)\n",
             "![bytes](results/figures/fig2_handshake_bytes.png)\n",
             "![primitives](results/figures/fig3_primitive_costs.png)\n",
             "![platform D](results/figures/fig4_platform_D_links.png)\n"]
    with open(os.path.join(ROOT, "RESULTS.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(parts))


if __name__ == "__main__":
    results_md()
    for p in ("report.md", "README.md", "platform_D.md"):
        fill(os.path.join(ROOT, p))
    print("RESULTS.md written; AUTO blocks refreshed in report.md / README.md / platform_D.md")
    sys.exit(0)
