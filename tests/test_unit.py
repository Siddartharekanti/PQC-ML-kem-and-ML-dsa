"""Unit tests for the wire format, key schedule and record layer."""
import os

import pytest

from qsc import wire
from qsc.errors import DecodeError, RecordAuthError, ReplayError, SessionClosed
from qsc.lab import Lab
from qsc.record import RECORD_OVERHEAD
from qsc.suites import CLASSICAL, HYBRID, PQC

LAB = Lab(server_suites=(PQC, CLASSICAL, HYBRID))


@pytest.mark.parametrize("suite", [PQC, CLASSICAL, HYBRID], ids=lambda s: s.label)
def test_sizes_match_standards(suite):
    _, _, m = LAB.handshake(suite)
    f = wire.decode(m["CH"], wire.CLIENT_HELLO)
    assert len(f[wire.F_KEM_PK]) == suite.kem.pk_len
    assert len(wire.decode(m["SH"], wire.SERVER_HELLO)[wire.F_KEM_CT]) == suite.kem.ct_len
    assert len(wire.decode(m["SV"], wire.SERVER_VERIFY)[wire.F_SIGNATURE]) == suite.sig.sig_len
    if suite is PQC:
        assert (suite.kem.pk_len, suite.kem.ct_len, suite.sig.sig_len) == (1184, 1088, 3309)


def test_decode_rejects_trailing_and_truncated():
    _, _, m = LAB.handshake(PQC)
    with pytest.raises(DecodeError):
        wire.decode(m["CH"] + b"\x00", wire.CLIENT_HELLO)
    with pytest.raises(DecodeError):
        wire.decode(m["CH"][:-1], wire.CLIENT_HELLO)
    with pytest.raises(DecodeError):
        wire.decode(m["CH"], wire.SERVER_HELLO)


def test_split_flight_roundtrip():
    _, _, m = LAB.handshake(PQC)
    assert wire.split_flight(m["SH"] + m["SV"] + m["SF"]) == [m["SH"], m["SV"], m["SF"]]


def test_keys_differ_per_direction_and_session():
    c1, s1, _ = LAB.handshake(PQC)
    c2, _, _ = LAB.handshake(PQC)
    assert c1.key_fingerprint == s1.key_fingerprint != c2.key_fingerprint
    assert c1.exporter != c2.exporter


def test_record_overhead_and_fragmentation():
    c, s, _ = LAB.handshake(PQC)
    msg = os.urandom(40000)
    recs = c.send_message(msg, record_size=16384)
    assert len(recs) == 3 and sum(map(len, recs)) == len(msg) + 3 * RECORD_OVERHEAD == len(msg) + 90
    assert s.receive_message(recs) == msg
    assert s.receive_message(c.send_message(b"")) == b""


def test_record_failures_close_session():
    c, s, _ = LAB.handshake(PQC)
    r0, r1 = c.send_message(b"a")[0], c.send_message(b"b")[0]
    assert s.receive_message([r0]) == b"a"
    with pytest.raises(ReplayError):
        s.receive_message([r0])
    with pytest.raises(SessionClosed):
        s.receive_message([r1])
    c, s, _ = LAB.handshake(PQC)
    bad = bytearray(c.send_message(b"x")[0]); bad[-1] ^= 1
    with pytest.raises(RecordAuthError):
        s.receive_message([bytes(bad)])


def test_close_record():
    c, s, _ = LAB.handshake(PQC)
    with pytest.raises(SessionClosed):
        s.receive_message([c.close_record()])
