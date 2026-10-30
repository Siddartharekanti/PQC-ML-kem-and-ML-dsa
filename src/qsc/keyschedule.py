"""Transcript hash and key schedule (HKDF-SHA256, RFC 5869), modelled on TLS 1.3.

    salt      = client_nonce || server_nonce                     (64 B, fresh per session)
    PRK       = HKDF-Extract(salt, shared_secret)                (ML-KEM / X25519 / hybrid secret)
    TH(x)     = SHA-256(serialized handshake messages up to and including x)

    s_fin_key = HKDF-Expand(PRK, info("s finished", TH(SH)), 32)   ServerFinished key
    c_fin_key = HKDF-Expand(PRK, info("c finished", TH(SH)), 32)   ClientFinished key
    c2s_key   = HKDF-Expand(PRK, info("c2s key",    TH(CF)), 32)   Alice -> Bob AES-256-GCM key
    c2s_iv    = HKDF-Expand(PRK, info("c2s iv",     TH(CF)), 12)
    s2c_key   = HKDF-Expand(PRK, info("s2c key",    TH(CF)), 32)   Bob -> Alice AES-256-GCM key
    s2c_iv    = HKDF-Expand(PRK, info("s2c iv",     TH(CF)), 12)
    exporter  = HKDF-Expand(PRK, info("exporter",   TH(CF)), 32)   session id / channel binding

    info(label, th) = "QFF26-P1/v1" || suite_id (2 B) || len(label) || label || th

Traffic keys depend on the *complete* transcript (both identities, both signatures, the
algorithm identifiers and all key material), so any tampering that somehow survived the
signature checks would still yield unrelated keys.
"""
from __future__ import annotations

from cryptography.hazmat.primitives import constant_time, hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand

PROTOCOL_LABEL = b"QFF26-P1/v1"


class Transcript:
    """Running SHA-256 over the exact serialized handshake messages."""

    def __init__(self):
        self._h = hashes.Hash(hashes.SHA256())
        self.messages: list = []

    def add(self, msg: bytes) -> bytes:
        self._h.update(msg)
        self.messages.append(msg)
        return self.digest()

    def digest(self) -> bytes:
        return self._h.copy().finalize()


def _info(suite_id: int, label: bytes, th: bytes) -> bytes:
    return PROTOCOL_LABEL + suite_id.to_bytes(2, "big") + bytes([len(label)]) + label + th


def extract(salt: bytes, shared_secret: bytes) -> bytes:
    return HKDF.extract(hashes.SHA256(), salt, shared_secret)


def expand(prk: bytes, suite_id: int, label: bytes, th: bytes, length: int) -> bytes:
    return HKDFExpand(algorithm=hashes.SHA256(), length=length, info=_info(suite_id, label, th)).derive(prk)


def finished_mac(key: bytes, th: bytes) -> bytes:
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(th)
    return h.finalize()


def finished_ok(key: bytes, th: bytes, tag: bytes) -> bool:
    return constant_time.bytes_eq(finished_mac(key, th), tag)


class HandshakeKeys:
    def __init__(self, prk: bytes, suite_id: int, th_sh: bytes):
        self.prk, self.suite_id = prk, suite_id
        self.s_fin = expand(prk, suite_id, b"s finished", th_sh, 32)
        self.c_fin = expand(prk, suite_id, b"c finished", th_sh, 32)

    def traffic(self, th_full: bytes) -> dict:
        e = lambda label, n: expand(self.prk, self.suite_id, label, th_full, n)  # noqa: E731
        return {
            "c2s_key": e(b"c2s key", 32), "c2s_iv": e(b"c2s iv", 12),
            "s2c_key": e(b"s2c key", 32), "s2c_iv": e(b"s2c iv", 12),
            "exporter": e(b"exporter", 32),
        }

    def wipe(self):
        self.prk = self.s_fin = self.c_fin = None
