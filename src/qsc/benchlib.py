"""Shared measurement code for the benchmark scripts (handshake, payloads, Platform B/D).

Timing method (same as the kit's common/measure.py): time.perf_counter_ns() around each trial,
`warmup` untimed trials first, garbage collector disabled during the timed loop, statistics =
median (primary), p25/p75, IQR, p95, min, max, mean, stdev, n.
"""
from __future__ import annotations

import gc
import multiprocessing as mp
import os
import sys
import time

from . import wire
from .handshake import ClientHandshake, ReplayCache, ServerConfig, ServerHandshake
from .identity import Identity, TrustStore
from .lab import Lab
from .suites import CLASSICAL, HYBRID, PQC, SIG_ALGS, SUITES

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
from common.measure import summarize  # noqa: E402  (kit timing statistics)

ALL_SUITES = (PQC, CLASSICAL, HYBRID)


def stats_ms(samples_ns):
    return summarize(samples_ns)


class gc_off:
    def __enter__(self):
        self.was = gc.isenabled()
        gc.collect()
        gc.disable()

    def __exit__(self, *exc):
        if self.was:
            gc.enable()


# --------------------------------------------------------------------------- in-process
def inproc_trial(lab: Lab, suite):
    c, s = lab.client(suite), lab.server()
    t0 = time.perf_counter_ns()
    ch = c.client_hello()
    t1 = time.perf_counter_ns()
    flight = s.handle_client_hello(ch)
    t2 = time.perf_counter_ns()
    cv, cf = c.handle_server_flight(*flight)
    t3 = time.perf_counter_ns()
    s.handle_client_auth(cv, cf)
    t4 = time.perf_counter_ns()
    ok = c.session.key_fingerprint == s.session.key_fingerprint
    msgs = {"CH": ch, "SH": flight[0], "SV": flight[1], "SF": flight[2], "CV": cv, "CF": cf}
    return {"handshake_ns": t4 - t0, "client_ns": (t1 - t0) + (t3 - t2), "server_ns": (t2 - t1) + (t4 - t3),
            "ok": ok, "msgs": msgs, "client": c.session, "server": s.session}


def run_inproc(lab, suite, trials, warmup):
    for _ in range(warmup):
        inproc_trial(lab, suite)
    out = []
    with gc_off():
        for _ in range(trials):
            try:
                r = inproc_trial(lab, suite)
            except Exception as e:  # noqa: BLE001
                r = {"ok": False, "error": repr(e)}
            out.append(r)
    for r in out:
        if r.get("ok"):  # verify each session really works (outside the timed region)
            rec = r["client"].send_message(b"ping")
            r["ok"] = r["server"].receive_message(rec) == b"ping"
        r.pop("client", None)
        r.pop("server", None)
    return out


# --------------------------------------------------------------------------- byte accounting
def byte_breakdown(msgs: dict, suite) -> list:
    """Per message: total bytes, crypto payload (keys/ciphertexts/signatures/MACs/nonces), framing."""
    crypto_fields = {"kem_public_key", "kem_ciphertext", "signature", "finished_mac", "client_nonce",
                     "server_nonce", "client_key_id", "server_key_id"}
    rows = []
    for name in ("CH", "SH", "SV", "SF", "CV", "CF"):
        m = msgs[name]
        spans = wire.field_spans(m)
        fields = {k: b - a for k, (a, b) in spans.items() if "tlv_header" not in k and k not in ("msg_type", "body_length")}
        crypto = sum(v for k, v in fields.items() if k in crypto_fields)
        direction = "client->server" if name in ("CH", "CV", "CF") else "server->client"
        rows.append({"suite": suite.label, "message": name, "message_name": wire.MSG_NAMES[m[0]],
                     "direction": direction, "bytes": len(m), "crypto_material_bytes": crypto,
                     "identity_and_algorithm_bytes": sum(v for k, v in fields.items() if k not in crypto_fields),
                     "framing_bytes": len(m) - sum(fields.values()),
                     "fields": "; ".join(f"{k}={v}" for k, v in fields.items())})
    return rows


# --------------------------------------------------------------------------- TCP (loopback / Platform D)
def server_spec(lab: Lab, suites=ALL_SUITES) -> dict:
    """Picklable description of Bob, so he can run in a separate process (spawn-safe)."""
    from .suites import SIG_ALGS as _S
    return {
        "keys": {a: _S[a].dump_private(lab.ids["bob"][a].sk).hex() for a in SIG_ALGS},
        "pins": [(n, a, lab.ids[n][a].pk.hex()) for n in ("alice", "carol") for a in SIG_ALGS],
        "suites": [s.suite_id for s in suites],
    }


def _server_main(spec, ready, host):
    from .transport import serve
    idents = []
    for a, raw in spec["keys"].items():
        sk = SIG_ALGS[a].load_private(bytes.fromhex(raw))
        idents.append(Identity("bob", a, sk, sk.public_key().public_bytes_raw()))
    ts = TrustStore()
    for n, a, pk in spec["pins"]:
        ts.pin(n, a, bytes.fromhex(pk))
    cfg = ServerConfig("bob", idents, ts, [SUITES[i] for i in spec["suites"]], ReplayCache(10**6))
    serve(cfg, host, 0, ready=ready)


def start_server(spec, host="127.0.0.1"):
    ctx = mp.get_context("spawn")
    q = ctx.Queue()
    p = ctx.Process(target=_server_main, args=(spec, q, host), daemon=True)
    p.start()
    return p, q.get(timeout=60)


def tcp_trial(lab: Lab, suite, host, port):
    from .transport import connect
    hs = lab.client(suite)
    t0 = time.perf_counter_ns()
    session, conn, st = connect(host, port, hs)
    hs_bytes = (conn.sent, conn.received)
    t1 = time.perf_counter_ns()
    conn.send_message(session, b"ping")           # proves Bob also completed the handshake
    reply = conn.receive_message(session)
    t2 = time.perf_counter_ns()
    import hashlib
    ok = reply == hashlib.sha256(b"ping").hexdigest().encode()
    conn.send(session.close_record())
    conn.close()
    return {"tcp_connect_ns": st["tcp_connect_ns"], "handshake_ns": st["handshake_ns"],
            "connect_to_confirmed_ns": t2 - t0, "confirm_rtt_ns": t2 - t1,
            "c2s_bytes": hs_bytes[0], "s2c_bytes": hs_bytes[1], "ok": ok}


def run_tcp(lab, suite, host, port, trials, warmup):
    for _ in range(warmup):
        tcp_trial(lab, suite, host, port)
    out = []
    with gc_off():
        for _ in range(trials):
            try:
                out.append(tcp_trial(lab, suite, host, port))
            except Exception as e:  # noqa: BLE001
                out.append({"ok": False, "error": repr(e)})
    return out


def platform_label():
    return os.environ.get("QFF_PLATFORM", "A")


__all__ = ["Lab", "ClientHandshake", "ServerHandshake", "PQC", "CLASSICAL", "HYBRID", "ALL_SUITES"]
