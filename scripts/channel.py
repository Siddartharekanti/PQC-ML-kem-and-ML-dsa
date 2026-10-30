"""Alice <-> Bob over a real TCP socket (loopback or two machines).

    # 1. provision long-term identities + pinned trust stores (out-of-band step)
    python scripts/channel.py provision                      # -> keys/ (git-ignored; private keys!)

    # 2. terminal 1 - Bob (server)
    python scripts/channel.py server --host 127.0.0.1 --port 8765 --suite pqc

    # 3. terminal 2 - Alice (client): sends the three official payloads, Bob answers with SHA-256
    python scripts/channel.py client --host 127.0.0.1 --port 8765 --suite pqc

For two machines: run `provision` once, copy keys/bob.* + keys/trust_bob.json to Bob's machine and
keys/alice.* + keys/trust_alice.json to Alice's machine, start the server with --host 0.0.0.0.
"""
import argparse
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from qsc.errors import HandshakeError  # noqa: E402
from qsc.handshake import ClientHandshake, ServerConfig  # noqa: E402
from qsc.identity import Identity, TrustStore  # noqa: E402
from qsc.payloads import load_all, official_hashes  # noqa: E402
from qsc.suites import SIG_ALGS, get_suite  # noqa: E402
from qsc.transport import connect, serve  # noqa: E402

KEYS = os.path.join(ROOT, "keys")


def provision(a):
    os.makedirs(a.keys, exist_ok=True)
    ids = {n: {alg: Identity.generate(n, alg) for alg in SIG_ALGS} for n in ("alice", "bob")}
    for n in ids:
        for ident in ids[n].values():
            ident.save(a.keys)
    ta, tb = TrustStore(), TrustStore()
    for alg in SIG_ALGS:
        ta.pin_identity(ids["bob"][alg])
        tb.pin_identity(ids["alice"][alg])
    ta.save(os.path.join(a.keys, "trust_alice.json"))
    tb.save(os.path.join(a.keys, "trust_bob.json"))
    print(f"provisioned alice + bob ({', '.join(SIG_ALGS)}) in {a.keys}")
    for alg in SIG_ALGS:
        print(f"  pin bob   {alg:10s} key id {ids['bob'][alg].key_id.hex()}")
        print(f"  pin alice {alg:10s} key id {ids['alice'][alg].key_id.hex()}")


def server(a):
    suites = [get_suite(s) for s in a.suite.split(",")]
    idents = [Identity.load(os.path.join(a.keys, f"bob.{alg}.key.json")) for alg in SIG_ALGS]
    cfg = ServerConfig("bob", idents, TrustStore.load(os.path.join(a.keys, "trust_bob.json")), suites)
    print(f"[bob] listening on {a.host}:{a.port}, policy: {', '.join(s.label for s in suites)}  (Ctrl+C to stop)")
    try:
        serve(cfg, a.host, a.port, log=print)
    except KeyboardInterrupt:
        pass


def client(a):
    suite = get_suite(a.suite)
    ident = Identity.load(os.path.join(a.keys, f"alice.{suite.sig_name}.key.json"))
    hs = ClientHandshake(ident, TrustStore.load(os.path.join(a.keys, "trust_alice.json")), "bob", suite)
    try:
        session, conn, st = connect(a.host, a.port, hs)
    except HandshakeError as e:
        print(f"[alice] handshake REJECTED: {type(e).__name__}: {e}")
        sys.exit(2)
    print(f"[alice] authenticated '{session.peer}' with {suite}")
    print(f"[alice] handshake {st['handshake_ns'] / 1e6:.2f} ms (+ TCP connect {st['tcp_connect_ns'] / 1e6:.2f} ms), "
          f"{st['c2s_bytes']} B sent, {st['s2c_bytes']} B received")
    want = official_hashes()
    ok_all = True
    for name, data in load_all().items():
        t0 = time.perf_counter()
        nrec = conn.send_message(session, data)
        reply = conn.receive_message(session).decode()
        dt = (time.perf_counter() - t0) * 1e3
        ok = reply == want[name]
        ok_all &= ok
        print(f"[alice] {name:18s} {len(data):>10,d} B in {nrec:4d} records -> Bob's SHA-256 "
              f"{'matches' if ok else 'MISMATCH'} ({dt:.1f} ms round trip)")
    conn.send(session.close_record())
    conn.close()
    sys.exit(0 if ok_all else 1)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("provision")
    p.add_argument("--keys", default=KEYS)
    for name in ("server", "client"):
        p = sub.add_parser(name)
        p.add_argument("--host", default="127.0.0.1")
        p.add_argument("--port", type=int, default=8765)
        p.add_argument("--suite", default="pqc", help="pqc | classical | hybrid (server: comma list = policy)")
        p.add_argument("--keys", default=KEYS)
    a = ap.parse_args()
    {"provision": provision, "server": server, "client": client}[a.cmd](a)
