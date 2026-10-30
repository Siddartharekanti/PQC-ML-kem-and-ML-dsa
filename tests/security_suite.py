"""PS-P1 mandatory security tests T1-T9 (SECURITY_TESTS.md).

Every test *actually injects* the fault through a man-in-the-middle hook or by editing
real serialized bytes, and checks the exact rejection. Each test is a list of sub-cases;
a test passes only if every sub-case passes.

Used by `run_security_tests.py` (one-command runner, writes results/security_tests.csv)
and by `tests/test_security.py` (pytest).
"""
from __future__ import annotations

import hashlib
import os
import random
import sys
from dataclasses import dataclass

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "src"))

from cryptography.exceptions import InvalidSignature, InvalidTag  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import x25519  # noqa: E402

from qsc import wire  # noqa: E402
from qsc.errors import (DecodeError, DowngradeError, FinishedError, HandshakeError,  # noqa: E402
                        HandshakeReplayError, IdentityMismatch, RecordAuthError, ReplayError,
                        SessionClosed, SignatureError, UntrustedIdentity)
from qsc.handshake import (CTX_CLIENT, CTX_SERVER, ClientHandshake, ReplayCache,  # noqa: E402
                           ServerConfig, ServerHandshake, run_handshake)
from qsc.identity import Identity  # noqa: E402
from qsc.keyschedule import HandshakeKeys, Transcript, extract, finished_mac  # noqa: E402
from qsc.lab import Lab  # noqa: E402
from qsc.payloads import load_all, official_hashes  # noqa: E402
from qsc.suites import CLASSICAL, HYBRID, PQC, SIG_ALGS, SUITES  # noqa: E402


@dataclass
class Case:
    name: str
    fault: str
    expected: str
    observed: str
    ok: bool


def flip(data: bytes, byte_index: int, bit: int = 0) -> bytes:
    b = bytearray(data)
    b[byte_index] ^= 1 << bit
    return bytes(b)


def rewrite(msg: bytes, msg_type: int, changes: dict) -> bytes:
    """Re-encode a handshake message with some fields (field id -> value) replaced by a MITM."""
    return wire.encode(msg_type, {**wire.decode(msg, msg_type), **changes})


def describe(exc: BaseException) -> str:
    cause = exc.__cause__
    c = f" <- {type(cause).__name__}" if isinstance(cause, (InvalidSignature, InvalidTag)) else ""
    return f"{type(exc).__name__}{c}: {exc}"


def expect_abort(lab, suite, tamper=None, client=None, server=None, expect=HandshakeError):
    """Run a handshake with a MITM hook; require an abort of type `expect` and no session."""
    c = client or lab.client(suite)
    s = server or lab.server()
    try:
        run_handshake(c, s, tamper)
    except HandshakeError as e:
        no_keys = c.session is None and s.session is None
        ok = isinstance(e, expect) and no_keys
        return ok, describe(e) + ("" if no_keys else " [BUT A SESSION EXISTS]")
    return False, "handshake COMPLETED - attack not detected"


# ============================================================================ T1
def t1_honest(lab, suite, payloads, **_):
    cases = []
    c, s, msgs = lab.handshake(suite)
    same = c.key_fingerprint == s.key_fingerprint and c.exporter == s.exporter \
        and c.transcript_hash == s.transcript_hash
    cases.append(Case("handshake", "none", "both sides derive identical traffic keys, mutual auth",
                      f"established; client peer={c.peer}, server peer={s.peer}; "
                      f"traffic-key fingerprint {c.key_fingerprint[:16]}... identical={same}",
                      same and c.peer == "bob" and s.peer == "alice"))
    want = official_hashes()
    for name, data in payloads.items():
        for direction, (tx, rx) in (("Alice->Bob", (c, s)), ("Bob->Alice", (s, c))):
            records = tx.send_message(data)
            out = rx.receive_message(records)
            h = hashlib.sha256(out).hexdigest()
            ok = h == want[name] and out == data
            cases.append(Case(f"{name} {direction}", "none", "decrypts byte-exact (SHA-256 match)",
                              f"{len(records)} records, sha256={h[:16]}... match={ok}", ok))
    return cases


# ============================================================================ T2
def t2_handshake_tampering(lab, suite, exhaustive=False, random_flips=128, **_):
    cases = []
    rng = random.Random(2026)
    ok, obs = expect_abort(lab, suite, lambda name, data: data)  # negative control: no fault
    completed = obs.startswith("handshake COMPLETED")
    cases.append(Case("control (no fault injected)", "none", "handshake completes (harness sanity check)",
                      "unmodified handshake completed normally" if completed else obs, completed))
    _, _, ref = lab.handshake(suite)  # only to learn the message layouts
    order = ["CH", "SH", "SV", "SF", "CV", "CF"]
    for mname in order:
        spans = wire.field_spans(ref[mname])
        targets = []  # (label, byte index, bit)
        for fname, (a, b) in spans.items():
            if b > a:
                for idx in sorted({a, (a + b) // 2, b - 1}):
                    targets.append((fname, idx, rng.randrange(8)))
        n = len(ref[mname])
        if exhaustive:
            targets += [("byte", i, i % 8) for i in range(n)]
        else:
            targets += [("random", i, rng.randrange(8)) for i in rng.sample(range(n), min(random_flips, n))]
        aborted, errors, failures = 0, {}, []
        for fname, idx, bit in targets:
            def hook(name, data, m=mname, i=idx, bt=bit):
                return flip(data, i, bt) if name == m else data
            ok, obs = expect_abort(lab, suite, hook)
            if ok:
                aborted += 1
                k = obs.split(":")[0]
                errors[k] = errors.get(k, 0) + 1
            else:
                failures.append(f"{fname}@{idx}: {obs}")
        fields = ", ".join(sorted({t[0] for t in targets if t[0] not in ("random", "byte")}))
        obs = (f"{aborted}/{len(targets)} aborted, no session; errors: "
               + ", ".join(f"{k} x{v}" for k, v in sorted(errors.items())))
        if failures:
            obs += " | NOT REJECTED: " + "; ".join(failures[:5])
        cases.append(Case(f"{wire.MSG_NAMES[wire.MSG_HDR.unpack_from(ref[mname])[0]]} ({mname}, {n} B)",
                          f"1-bit flip in each field [{fields}] + {'every byte' if exhaustive else f'{random_flips} random bits'}",
                          "handshake aborts, no traffic key", obs, not failures))
    return cases


# ============================================================================ T3
def t3_signature_tampering(lab, suite, **_):
    cases = []
    for mname, mtype in (("SV", wire.SERVER_VERIFY), ("CV", wire.CLIENT_VERIFY)):
        for where in ("first", "middle", "last"):
            def hook(name, data, m=mname, w=where):
                if name != m:
                    return data
                a, b = wire.field_spans(data)["signature"]
                i = {"first": a, "middle": (a + b) // 2, "last": b - 1}[w]
                return flip(data, i, 3)
            ok, obs = expect_abort(lab, suite, hook, expect=SignatureError)
            who = "server" if mname == "SV" else "client"
            cases.append(Case(f"{who} signature, {where} byte", f"bit flip in {suite.sig_name} signature ({mname})",
                              "SignatureError (InvalidSignature)", obs, ok))
    # a well-formed but random signature of the right length
    def hook_rand(name, data):
        if name != "SV":
            return data
        return wire.encode(wire.SERVER_VERIFY, {wire.F_SIGNATURE: os.urandom(suite.sig.sig_len)})
    ok, obs = expect_abort(lab, suite, hook_rand, expect=SignatureError)
    cases.append(Case("random signature", "ServerVerify replaced by random bytes", "SignatureError", obs, ok))
    return cases


# ============================================================================ T4 / T5
def _fresh(lab, suite):
    c, s, _ = lab.handshake(suite)
    return c, s


def _record_reject(rx, records, expect=RecordAuthError):
    try:
        out = rx.receive_message(records)
        return False, f"ACCEPTED, plaintext released ({len(out)} B)"
    except expect as e:
        # after a failure the session must be closed (fail-closed)
        closed = rx.closed
        return closed, describe(e) + f"; plaintext not released; session closed={closed}"
    except Exception as e:  # noqa: BLE001
        return False, f"wrong error: {describe(e)}"


def t4_ciphertext_tampering(lab, suite, payloads, **_):
    cases = []
    data = payloads["payload_1KB.bin"]
    for direction in ("Alice->Bob", "Bob->Alice"):
        for where in ("first", "middle", "last"):
            c, s = _fresh(lab, suite)
            tx, rx = (c, s) if direction == "Alice->Bob" else (s, c)
            rec = tx.send_message(data)[0]
            i = {"first": 14, "middle": 14 + len(data) // 2, "last": 14 + len(data) - 1}[where]
            ok, obs = _record_reject(rx, [flip(rec, i, 5)])
            if ok:  # session is dead: even the genuine record is now refused
                try:
                    rx.receive_message([rec])
                    ok, obs = False, obs + "; genuine record accepted after failure"
                except SessionClosed:
                    obs += "; later records refused (SessionClosed)"
            cases.append(Case(f"{direction} 1KB record, {where} ciphertext byte", "bit flip in record ciphertext",
                              "InvalidTag; plaintext never released", obs, ok))
    # multi-record message: corrupt record #300 of the 10 MB payload; nothing may be released
    c, s = _fresh(lab, suite)
    recs = c.send_message(payloads["payload_10MB.bin"])
    k = min(300, len(recs) - 1)
    recs[k] = flip(recs[k], 100, 0)
    ok, obs = _record_reject(s, recs)
    cases.append(Case("10MB message, record #%d of %d" % (k, len(recs)), "bit flip in one fragment",
                      "InvalidTag; no part of the message released", obs, ok))
    return cases


def t5_tag_aad_tampering(lab, suite, payloads, **_):
    cases = []
    data = payloads["payload_1KB.bin"]
    hdr_fields = {"content_type": 0, "flags": 1, "seq (MSB)": 2, "seq (LSB)": 9, "length (MSB)": 10,
                  "length (LSB)": 13}
    targets = [("GCM tag first byte", -16), ("GCM tag last byte", -1)] + \
              [(f"header {n} byte", i) for n, i in hdr_fields.items()]
    for label, idx in targets:
        c, s = _fresh(lab, suite)
        rec = c.send_message(data)[0]
        i = idx if idx >= 0 else len(rec) + idx
        ok, obs = _record_reject(s, [flip(rec, i, 0)])
        cases.append(Case(label, f"bit flip in {label} (authenticated header = AAD)" if "header" in label
                          else f"bit flip in {label}", "InvalidTag", obs, ok))
    # truncated tag
    c, s = _fresh(lab, suite)
    rec = c.send_message(data)[0]
    ok, obs = _record_reject(s, [rec[:-1]])
    cases.append(Case("tag truncated by 1 byte", "record shortened", "InvalidTag", obs, ok))
    return cases


# ============================================================================ T6
def _fake_server(lab, suite, name, signer: str, advertised_pk_of: str | None = None):
    """A server config named `name` that signs with `signer`'s key and advertises the key id of
    `advertised_pk_of` (default: its own)."""
    real = lab.ids[signer][suite.sig_name]
    pk = lab.ids[advertised_pk_of][suite.sig_name].pk if advertised_pk_of else real.pk
    ident = Identity(name, real.sig_alg, real.sk, pk)
    return ServerHandshake(ServerConfig(name, [ident], lab.trust["bob"], (suite,), ReplayCache()))


def t6_untrusted_identity(lab, suite, **_):
    cases = []
    ok, obs = expect_abort(lab, suite, server=_fake_server(lab, suite, "bob", "mallory"), expect=UntrustedIdentity)
    cases.append(Case("Mallory impersonates Bob (own valid key + valid signature)",
                      "server flight from attacker key, named 'bob'", "rejected: key != trust anchor", obs, ok))
    ok, obs = expect_abort(lab, suite, server=_fake_server(lab, suite, "bob", "mallory", "bob"), expect=SignatureError)
    cases.append(Case("Mallory copies Bob's key id, signs with own key",
                      "pinned key id + attacker signature", "rejected: signature fails under pinned key", obs, ok))
    ok, obs = expect_abort(lab, suite, client=lab.client(suite, server="mallory"),
                           server=_fake_server(lab, suite, "mallory", "mallory"), expect=UntrustedIdentity)
    cases.append(Case("Alice redirected to unpinned server 'mallory'", "peer not in trust store",
                      "rejected: identity not pinned", obs, ok))
    ok, obs = expect_abort(lab, suite, client=lab.client(suite, name="alice", identity_of="mallory"),
                           expect=UntrustedIdentity)
    cases.append(Case("Mallory impersonates Alice to Bob (own key)", "client key not matching Bob's pin",
                      "rejected by Bob at ClientHello", obs, ok))
    # Mallory advertises Alice's key id but signs ClientVerify with her own key
    m = lab.ids["mallory"][suite.sig_name]
    forged = ClientHandshake(Identity("alice", m.sig_alg, m.sk, lab.ids["alice"][suite.sig_name].pk),
                             lab.trust["alice"], "bob", suite)
    ok, obs = expect_abort(lab, suite, client=forged, expect=SignatureError)
    cases.append(Case("Mallory copies Alice's key id, signs with own key", "client signature from attacker key",
                      "rejected by Bob at ClientVerify", obs, ok))
    ok, obs = expect_abort(lab, suite, client=lab.client(suite, name="mallory"), expect=UntrustedIdentity)
    cases.append(Case("unknown client 'mallory'", "client identity not pinned", "rejected by Bob", obs, ok))
    return cases


# ============================================================================ T7
def t7_identity_swap(lab, suite, **_):
    cases = []
    _, _, old = lab.handshake(suite)  # genuine Alice<->Bob session, recorded by the attacker

    def replay_flight(rewrite_client=False):
        def hook(name, data):
            if name == "SH":
                if rewrite_client:
                    return rewrite(old["SH"], wire.SERVER_HELLO, {wire.F_CLIENT_ID: b"carol"})
                return old["SH"]
            if name in ("SV", "SF"):
                return old[name]
            return data
        return hook

    carol = lab.client(suite, name="carol")
    ok, obs = expect_abort(lab, suite, replay_flight(False), client=carol, expect=IdentityMismatch)
    cases.append(Case("Bob's signed flight from Alice's session replayed to Carol",
                      "genuine SH/SV/SF naming peer 'alice' injected into Carol's session",
                      "rejected: identity binding", obs, ok))
    ok, obs = expect_abort(lab, suite, replay_flight(True), client=lab.client(suite, name="carol"),
                           expect=SignatureError)
    cases.append(Case("same, with client name rewritten to 'carol'",
                      "identity field edited to match Carol", "rejected: transcript binding (signature)", obs, ok))
    ok, obs = expect_abort(lab, suite, server=lab.server("charlie"), expect=IdentityMismatch)
    cases.append(Case("connection redirected to trusted server Charlie",
                      "valid signature from a pinned but different peer", "rejected: session bound to 'bob'",
                      obs, ok))

    def swap(name, data):
        if name != "SH":
            return data
        f = wire.decode(data, wire.SERVER_HELLO)
        f[wire.F_SERVER_ID], f[wire.F_CLIENT_ID] = f[wire.F_CLIENT_ID], f[wire.F_SERVER_ID]
        return wire.encode(wire.SERVER_HELLO, f)
    ok, obs = expect_abort(lab, suite, swap, expect=IdentityMismatch)
    cases.append(Case("roles swapped in ServerHello", "server/client identity fields exchanged",
                      "rejected: identity binding", obs, ok))
    # role reflection: a genuine server-role signature presented for the client role (and back)
    c, s, msgs = lab.handshake(suite)
    tr = Transcript()
    for k in ("CH", "SH"):
        th_sh = tr.add(msgs[k])
    sig_s = wire.decode(msgs["SV"], wire.SERVER_VERIFY)[wire.F_SIGNATURE]
    alg = SIG_ALGS[suite.sig_name]
    bob_pk = lab.ids["bob"][suite.sig_name].pk
    alg.verify(bob_pk, sig_s, th_sh, CTX_SERVER)  # genuine in its own role
    try:
        alg.verify(bob_pk, sig_s, th_sh, CTX_CLIENT)
        ok, obs = False, "signature ACCEPTED in the other role"
    except SignatureError as e:
        ok, obs = True, describe(e)
    cases.append(Case("role reflection of a genuine signature",
                      "ServerVerify signature checked as a client-role signature",
                      "rejected: role-specific signature context", obs, ok))
    return cases


# ============================================================================ T8
def t8_replay(lab, suite, payloads, **_):
    cases = []
    data = payloads["payload_1KB.bin"]
    c, s = _fresh(lab, suite)
    r = [c.send_message(data + bytes([i]))[0] for i in range(3)]
    s.receive_message([r[0]])
    s.receive_message([r[1]])
    ok, obs = _record_reject(s, [r[0]], expect=ReplayError)
    cases.append(Case("record replay", "re-send record seq 0 after seq 0,1 accepted",
                      "rejected (sequence number)", obs, ok))
    c, s = _fresh(lab, suite)
    r = [c.send_message(data)[0] for _ in range(2)]
    ok, obs = _record_reject(s, [r[1]])
    cases.append(Case("record reordering / drop", "deliver seq 1 before seq 0",
                      "rejected (nonce bound to expected seq)", obs, ok))
    c, s = _fresh(lab, suite)
    rec = c.send_message(data)[0]
    ok, obs = _record_reject(c, [rec])
    cases.append(Case("reflection", "Alice's own c2s record sent back to Alice",
                      "rejected (separate per-direction keys)", obs, ok))
    c1, s1 = _fresh(lab, suite)
    c2, s2 = _fresh(lab, suite)
    ok, obs = _record_reject(s2, [c1.send_message(data)[0]])
    cases.append(Case("cross-session record replay", "record from session 1 injected into session 2",
                      "rejected (fresh per-session keys)", obs, ok))
    # handshake replay against the same server (nonce cache)
    srv_cfg = ServerConfig("bob", lab.ids["bob"].values(), lab.trust["bob"], (suite,), ReplayCache())
    cl = lab.client(suite)
    _, _, old = run_handshake(cl, ServerHandshake(srv_cfg))
    try:
        ServerHandshake(srv_cfg).handle_client_hello(old["CH"])
        ok, obs = False, "replayed ClientHello accepted"
    except HandshakeReplayError as e:
        ok, obs = True, describe(e)
    cases.append(Case("old ClientHello replayed to Bob", "byte-exact replay of a previous ClientHello",
                      "rejected (ClientHello nonce cache)", obs, ok))
    # server restarted (empty cache): old CH is answered, but old CV/CF cannot complete
    fresh = ServerHandshake(ServerConfig("bob", lab.ids["bob"].values(), lab.trust["bob"], (suite,), ReplayCache()))
    try:
        fresh.handle_client_hello(old["CH"])
        fresh.handle_client_auth(old["CV"], old["CF"])
        ok, obs = False, "replayed handshake COMPLETED"
    except SignatureError as e:
        ok, obs = fresh.session is None, describe(e) + "; no session (fresh server nonce + KEM ciphertext)"
    cases.append(Case("full old handshake replayed to restarted Bob", "old CH + old CV/CF, empty nonce cache",
                      "rejected (fresh server randomness in transcript)", obs, ok))

    def old_server_flight(name, d):
        return old[name] if name in ("SH", "SV", "SF") else d
    ok, obs = expect_abort(lab, suite, old_server_flight)
    cases.append(Case("old server flight replayed to Alice", "previous SH/SV/SF injected into new session",
                      "rejected (fresh client nonce + KEM key in transcript)", obs, ok))
    return cases


# ============================================================================ T9
def t9_downgrade(lab, suite, **_):
    cases = []
    other = CLASSICAL if suite is not CLASSICAL else PQC

    def ch_suite(name, data):
        if name != "CH":
            return data
        return rewrite(data, wire.CLIENT_HELLO, {wire.F_SUITE: other.suite_id.to_bytes(2, "big")})
    ok, obs = expect_abort(lab, suite, ch_suite, server=lab.server(allowed=(suite,), replay_cache=ReplayCache()), expect=DowngradeError)
    cases.append(Case(f"ClientHello suite id -> {other.label}", "suite_id rewritten",
                      "rejected (policy)", obs, ok))

    def ch_algs(name, data):
        if name != "CH":
            return data
        weak = suite.alg_string.replace("AES-256-GCM", "AES-128-GCM").replace("SHA256", "SHA1").encode()
        return rewrite(data, wire.CLIENT_HELLO, {wire.F_ALGS: weak})
    ok, obs = expect_abort(lab, suite, ch_algs, server=lab.server(allowed=(suite,), replay_cache=ReplayCache()), expect=DowngradeError)
    cases.append(Case("ClientHello algorithm ids weakened", "AES-256-GCM->AES-128-GCM, SHA256->SHA1",
                      "rejected (ids must match the suite)", obs, ok))

    def ch_unknown(name, data):
        if name != "CH":
            return data
        return rewrite(data, wire.CLIENT_HELLO, {wire.F_SUITE: b"\xff\xff"})
    ok, obs = expect_abort(lab, suite, ch_unknown, server=lab.server(allowed=(suite,), replay_cache=ReplayCache()), expect=DowngradeError)
    cases.append(Case("unknown suite id 0xffff", "suite_id rewritten", "rejected", obs, ok))

    def ch_version(name, data):
        if name != "CH":
            return data
        return rewrite(data, wire.CLIENT_HELLO, {wire.F_VERSION: b"\x00"})
    ok, obs = expect_abort(lab, suite, ch_version, server=lab.server(allowed=(suite,), replay_cache=ReplayCache()), expect=DowngradeError)
    cases.append(Case("protocol version 1 -> 0", "version rewritten", "rejected", obs, ok))

    def sh_suite(name, data):
        if name != "SH":
            return data
        return rewrite(data, wire.SERVER_HELLO, {wire.F_SUITE: other.suite_id.to_bytes(2, "big")})
    ok, obs = expect_abort(lab, suite, sh_suite, server=lab.server(allowed=(suite,), replay_cache=ReplayCache()), expect=DowngradeError)
    cases.append(Case(f"ServerHello suite id -> {other.label}", "suite_id in server reply rewritten",
                      "rejected by Alice", obs, ok))

    def sh_algs(name, data):
        if name != "SH":
            return data
        weak = suite.alg_string.replace("AES-256-GCM", "AES-128-GCM").encode()
        return rewrite(data, wire.SERVER_HELLO, {wire.F_ALGS: weak})
    ok, obs = expect_abort(lab, suite, sh_algs, server=lab.server(allowed=(suite,), replay_cache=ReplayCache()), expect=DowngradeError)
    cases.append(Case("ServerHello algorithm ids weakened", "alg ids in server reply rewritten",
                      "rejected by Alice", obs, ok))

    if suite is not CLASSICAL:
        cases.append(_active_downgrade(lab, suite))
    return cases


def _active_downgrade(lab, suite) -> Case:
    """Full active MITM downgrade against a *migration-mode* Bob that also accepts CLASSICAL.

    Mallory replaces Alice's PQC ClientHello by a CLASSICAL one (same identities, Mallory's own
    X25519 share), so Bob accepts and signs a classical transcript. Mallory can then:
      (a) forward Bob's classical reply to Alice  -> Alice must reject (not what she offered)
      (b) try to finish with Bob as 'alice'       -> Bob must reject (no valid Alice signature)
    """
    alice = lab.client(suite)
    bob = lab.server(allowed=(suite, CLASSICAL), replay_cache=ReplayCache())
    ch = alice.client_hello()
    f = wire.decode(ch, wire.CLIENT_HELLO)
    m_x = x25519.X25519PrivateKey.generate()
    f[wire.F_SUITE] = CLASSICAL.suite_id.to_bytes(2, "big")
    f[wire.F_ALGS] = CLASSICAL.alg_string.encode()
    f[wire.F_CLIENT_KEY_ID] = lab.ids["alice"]["Ed25519"].key_id  # public information
    f[wire.F_KEM_PK] = m_x.public_key().public_bytes_raw()
    ch2 = wire.encode(wire.CLIENT_HELLO, f)
    obs = []
    sh, sv, sf = bob.handle_client_hello(ch2)
    obs.append("migration-mode Bob answered the downgraded ClientHello (expected: it cannot tell yet)")
    a_ok = False
    try:
        alice.handle_server_flight(sh, sv, sf)
    except DowngradeError as e:
        a_ok = alice.session is None
        obs.append("Alice: " + describe(e))
    # Mallory knows the X25519 secret, so she can compute keys and Finished - but not Alice's signature
    tr = Transcript()
    for m in (ch2, sh):
        th_sh = tr.add(m)
    shf = wire.decode(sh, wire.SERVER_HELLO)
    ss = m_x.exchange(x25519.X25519PublicKey.from_public_bytes(shf[wire.F_KEM_CT]))
    keys = HandshakeKeys(extract(f[wire.F_CLIENT_NONCE] + shf[wire.F_SERVER_NONCE], ss), CLASSICAL.suite_id, th_sh)
    tr.add(sv)
    th_sf = tr.add(sf)
    mal = lab.ids["mallory"]["Ed25519"]
    cv = wire.encode(wire.CLIENT_VERIFY, {wire.F_SIGNATURE: mal.sign(th_sf, CTX_CLIENT)})
    th_cv = tr.add(cv)
    cf = wire.encode(wire.CLIENT_FINISHED, {wire.F_FINISHED: finished_mac(keys.c_fin, th_cv)})
    b_ok = False
    try:
        bob.handle_client_auth(cv, cf)
        obs.append("Bob: COMPLETED downgraded session")
    except SignatureError as e:
        b_ok = bob.session is None
        obs.append("Bob: " + describe(e))
    return Case("active MITM downgrade to CLASSICAL vs migration-mode Bob",
                "CH replaced by CLASSICAL CH with attacker X25519 share; attacker completes with own key",
                "no session on either side (transcript binding + mutual auth)", " | ".join(obs), a_ok and b_ok)


TESTS = [
    ("T1", "Honest run", t1_honest),
    ("T2", "Handshake tampering", t2_handshake_tampering),
    ("T3", "Signature tampering", t3_signature_tampering),
    ("T4", "Ciphertext tampering", t4_ciphertext_tampering),
    ("T5", "Tag/AAD tampering", t5_tag_aad_tampering),
    ("T6", "Untrusted identity", t6_untrusted_identity),
    ("T7", "Identity swap", t7_identity_swap),
    ("T8", "Replay", t8_replay),
    ("T9", "Algorithm downgrade", t9_downgrade),
]

EXPECTED = {
    "T1": "handshake ok + identical keys + payloads decrypt byte-exact",
    "T2": "abort, no traffic key",
    "T3": "reject (InvalidSignature)",
    "T4": "InvalidTag, plaintext never released",
    "T5": "InvalidTag",
    "T6": "reject against trust anchor",
    "T7": "reject via transcript/identity binding",
    "T8": "reject (implemented)",
    "T9": "reject",
}


def make_lab():
    return Lab(server_suites=(PQC, CLASSICAL, HYBRID))


def run_test(test_id, lab, suite, payloads, **opts):
    fn = dict((t[0], t[2]) for t in TESTS)[test_id]
    return fn(lab, suite, payloads=payloads, **opts)


__all__ = ["TESTS", "EXPECTED", "Case", "make_lab", "run_test", "load_all", "SUITES", "PQC", "CLASSICAL",
           "HYBRID", "DecodeError", "FinishedError"]
