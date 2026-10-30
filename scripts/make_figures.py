"""Regenerate every figure in results/figures/ from the CSVs (separate process from the benchmarks).

    python scripts/make_figures.py
"""
import csv
import os
import sys

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES = os.path.join(ROOT, "results")
FIG = os.path.join(RES, "figures")

# categorical slots 1-3 of the validated reference palette (fixed order: PQC, classical, hybrid)
COLOR = {"PQC": "#2a78d6", "CLASSICAL": "#eb6834", "HYBRID": "#1baf7a"}
NAME = {"PQC": "PQC: ML-KEM-768 + ML-DSA-65", "CLASSICAL": "Baseline: X25519 + Ed25519",
        "HYBRID": "Hybrid: X25519+ML-KEM-768 + ML-DSA-65"}
INK, INK2, GRID, SURF = "#0b0b0b", "#52514e", "#e4e3df", "#fcfcfb"

plt.rcParams.update({
    "figure.facecolor": SURF, "axes.facecolor": SURF, "savefig.facecolor": SURF,
    "axes.edgecolor": GRID, "axes.labelcolor": INK2, "xtick.color": INK2, "ytick.color": INK2,
    "text.color": INK, "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.8,
    "axes.spines.top": False, "axes.spines.right": False, "font.size": 10, "axes.titlesize": 11,
    "axes.titleweight": "bold", "legend.frameon": False,
})


def read(path):
    with open(path) as f:
        return list(csv.DictReader(f))


def suite_of(row):
    m = row.get("mode", "")
    return {"PQC": "PQC", "classical-baseline": "CLASSICAL"}.get(m, "HYBRID")


def fig_latency():
    trials = read(os.path.join(RES, "handshake_trials.csv"))
    summary = read(os.path.join(RES, "handshake_results.csv"))
    platform = summary[0]["platform"]
    fig, axes = plt.subplots(1, 2, figsize=(10, 3.8), sharey=False)
    for ax, mode, label in ((axes[0], "inproc", "local, in-process"), (axes[1], "loopback", "local, TCP loopback")):
        suites = [s for s in ("PQC", "CLASSICAL", "HYBRID") if any(t["suite"] == s and t["measurement"] == mode
                                                                   for t in trials)]
        data = [[float(t["handshake_ms"]) for t in trials if t["suite"] == s and t["measurement"] == mode
                 and t["ok"] == "True"] for s in suites]
        if not any(data):
            ax.set_visible(False)
            continue
        orient = {"orientation": "horizontal"} if tuple(map(int, matplotlib.__version__.split(".")[:2])) >= (3, 10) \
            else {"vert": False}
        bp = ax.boxplot(data, **orient, widths=0.5, patch_artist=True, showfliers=True,
                        medianprops={"color": INK, "linewidth": 2},
                        flierprops={"marker": "o", "markersize": 3, "markeredgewidth": 0, "alpha": 0.6})
        for patch, s, fl in zip(bp["boxes"], suites, bp["fliers"]):
            patch.set_facecolor(COLOR[s])
            patch.set_alpha(0.85)
            patch.set_edgecolor(SURF)
            fl.set_markerfacecolor(COLOR[s])
        for w in bp["whiskers"] + bp["caps"]:
            w.set_color(INK2)
        for i, d in enumerate(data):
            med = sorted(d)[len(d) // 2]
            ax.annotate(f"median {med:.2f} ms", (med, i + 1 - 0.33), color=INK, fontsize=8.5, ha="center",
                        va="bottom")
        ax.set_yticks(range(1, len(suites) + 1), [NAME[s].split(":")[0] for s in suites])
        ax.invert_yaxis()
        ax.set_xlabel("handshake time (ms)")
        n = len(data[0])
        ax.set_title(f"{label}  (n = {n} per suite)", loc="left")
        ax.grid(axis="y", visible=False)
        ax.set_xlim(left=0)
    fig.suptitle(f"Handshake latency, Platform {platform} - PQC vs classical baseline", x=0.01, ha="left",
                 fontweight="bold")
    fig.tight_layout()
    fig.savefig(os.path.join(FIG, "fig1_handshake_latency.png"), dpi=160)
    plt.close(fig)


def fig_bytes():
    rows = read(os.path.join(RES, "handshake_bytes.csv"))
    msgs = ["CH", "SH", "SV", "SF", "CV", "CF"]
    suites = [s for s in ("PQC", "CLASSICAL", "HYBRID") if any(r["suite"] == s for r in rows)]
    fig, ax = plt.subplots(figsize=(10, 4))
    w = 0.8 / len(suites)
    for j, s in enumerate(suites):
        vals = [int(next(r["bytes"] for r in rows if r["suite"] == s and r["message"] == m)) for m in msgs]
        xs = [i + (j - (len(suites) - 1) / 2) * w for i in range(len(msgs))]
        ax.bar(xs, vals, width=w - 0.03, color=COLOR[s], label=NAME[s], edgecolor=SURF, linewidth=1)
        if s in ("PQC", "CLASSICAL"):
            for x, v in zip(xs, vals):
                ax.annotate(f"{v:,}", (x, v), xytext=(0, 3), textcoords="offset points", ha="center",
                            fontsize=7.5, color=INK2)
    tot = {s: sum(int(r["bytes"]) for r in rows if r["suite"] == s) for s in suites}
    ax.set_xticks(range(len(msgs)), [f"{m}\n{next(r['message_name'] for r in rows if r['message'] == m)}" for m in msgs])
    ax.set_ylabel("serialized bytes")
    ax.grid(axis="x", visible=False)
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.2), ncol=len(suites))
    ax.set_title("Bytes on the wire per handshake message (exact serialized size; totals: "
                 + ", ".join(f"{s.lower()} {tot[s]:,} B" for s in suites) + ")", loc="left", fontsize=10)
    fig.tight_layout()
    fig.savefig(os.path.join(FIG, "fig2_handshake_bytes.png"), dpi=160)
    plt.close(fig)


def fig_primitives():
    rows = read(os.path.join(RES, "primitive_timings.csv"))
    ops = ["kem_keygen", "kem_encaps", "kem_decaps", "sig_sign", "sig_verify", "key_schedule"]
    labels = ["KEM keygen", "KEM encaps", "KEM decaps", "sign", "verify", "HKDF schedule"]
    suites = [s for s in ("PQC", "CLASSICAL") if any(r["suite"] == s for r in rows)]
    fig, ax = plt.subplots(figsize=(9, 3.8))
    h = 0.38
    for j, s in enumerate(suites):
        vals = [float(next(r["median_ms"] for r in rows if r["suite"] == s and r["operation"] == o)) for o in ops]
        ys = [i + (j - 0.5) * h for i in range(len(ops))]
        ax.barh(ys, vals, height=h - 0.04, color=COLOR[s], label=NAME[s], edgecolor=SURF)
        for y, v in zip(ys, vals):
            ax.annotate(f"{v:.3f}", (v, y), xytext=(3, 0), textcoords="offset points", va="center", fontsize=7.5,
                        color=INK2)
    ax.set_yticks(range(len(ops)), labels)
    ax.invert_yaxis()
    ax.set_xlabel("median time per operation (ms)")
    ax.grid(axis="y", visible=False)
    ax.legend(loc="lower right")
    n = rows[0]["trials"]
    ax.set_title(f"Primitive cost, Platform {rows[0]['platform']} (local, in-process, n = {n} per op)", loc="left")
    fig.tight_layout()
    fig.savefig(os.path.join(FIG, "fig3_primitive_costs.png"), dpi=160)
    plt.close(fig)


def fig_platform_d():
    path = os.path.join(RES, "platform_D", "handshake_netem.csv")
    if not os.path.exists(path):
        return
    rows = read(path)
    profiles = list(dict.fromkeys(r["profile"] for r in rows))
    fig, ax = plt.subplots(figsize=(9, 3.6))
    for i, p in enumerate(profiles):
        pr = {suite_of(r): r for r in rows if r["profile"] == p}
        vals = {s: float(r["median_handshake_ms"]) for s, r in pr.items()}
        if "PQC" in vals and "CLASSICAL" in vals:
            ax.plot([vals["CLASSICAL"], vals["PQC"]], [i, i], color=GRID, linewidth=3, zorder=1)
            ax.annotate(f"+{vals['PQC'] - vals['CLASSICAL']:.0f} ms ({vals['PQC'] / vals['CLASSICAL']:.2f}x)",
                        (vals["PQC"], i), xytext=(8, 0), textcoords="offset points", va="center", fontsize=8.5,
                        color=INK)
        for s, v in vals.items():
            ax.scatter([v], [i], s=70, color=COLOR[s], zorder=3, edgecolor=SURF, linewidth=2,
                       label=NAME[s] if i == 0 else None)
    r0 = {r["profile"]: r for r in rows}
    ax.set_yticks(range(len(profiles)),
                  [f"{p}\n{r0[p]['rtt_ms']} ms RTT, {r0[p]['bandwidth_mbps']} Mbit/s" for p in profiles])
    ax.set_xscale("log")
    ax.set_xlabel("median handshake time (ms, log scale)")
    ax.invert_yaxis()
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.25), ncol=2)
    ax.grid(axis="y", visible=False)
    ax.set_title(f"Platform D: emulated links (loopback + netem relay), n = {rows[0]['trials']} per point",
                 loc="left")
    fig.tight_layout()
    fig.savefig(os.path.join(FIG, "fig4_platform_D_links.png"), dpi=160)
    plt.close(fig)


if __name__ == "__main__":
    os.makedirs(FIG, exist_ok=True)
    for f in (fig_latency, fig_bytes, fig_primitives, fig_platform_d):
        f()
    print("figures ->", os.path.relpath(FIG, ROOT), sorted(os.listdir(FIG)))
    sys.exit(0)
