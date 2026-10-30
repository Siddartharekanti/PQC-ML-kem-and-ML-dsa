"""Record layer: AES-256-GCM (NIST SP 800-38D) with per-direction keys and sequence numbers.

    record := header (14 B) || AES-256-GCM ciphertext || tag (16 B)
    header := content_type (1) || flags (1) || seq (8, big-endian) || length (4)   -> the GCM AAD
    nonce  := static_iv XOR (0^4 || seq)        (12 B, derived, never transmitted - as in TLS 1.3)

* Separate key + IV per direction (c2s / s2c): a record can never be reflected back to its sender.
* seq starts at 0 and increments per record, so a (key, nonce) pair is never reused.
* The receiver accepts only seq == next expected value. A record whose seq was already
  consumed is rejected *before* decryption (ReplayError). The nonce is always computed from
  the receiver's own counter, so reordered / dropped records fail authentication (InvalidTag).
* The whole header is authenticated as AAD: any change -> InvalidTag.
* Fail-closed: any error closes the session; no plaintext is returned from a failed record.

Per-record overhead on the wire: 14 B header + 16 B tag = 30 B (nonce is implicit: 0 B).
"""
from __future__ import annotations

import hashlib
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import RecordAuthError, RecordError, ReplayError, SessionClosed

HDR = struct.Struct(">BBQI")
HEADER_LEN = HDR.size          # 14
TAG_LEN = 16
NONCE_LEN = 12
RECORD_OVERHEAD = HEADER_LEN + TAG_LEN

CT_APPLICATION = 0x17
CT_CLOSE = 0x15
FLAG_FINAL = 0x01              # last fragment of an application message

DEFAULT_RECORD_SIZE = 16 * 1024          # like TLS
MAX_RECORD_PLAINTEXT = 16 * 1024 * 1024  # hard upper bound per record
MAX_SEQ = 2**64 - 1


def _nonce(iv: bytes, seq: int) -> bytes:
    return (int.from_bytes(iv, "big") ^ seq).to_bytes(NONCE_LEN, "big")


class _Direction:
    def __init__(self, key: bytes, iv: bytes):
        self.aead = AESGCM(key)
        self.iv = iv
        self.seq = 0


class Session:
    """An established, mutually authenticated channel endpoint."""

    def __init__(self, role: str, suite, peer: str, keys: dict, transcript_hash: bytes):
        self.role, self.suite, self.peer = role, suite, peer
        self.transcript_hash = transcript_hash
        self.exporter = keys["exporter"]
        if role == "client":
            self._send = _Direction(keys["c2s_key"], keys["c2s_iv"])
            self._recv = _Direction(keys["s2c_key"], keys["s2c_iv"])
        else:
            self._send = _Direction(keys["s2c_key"], keys["s2c_iv"])
            self._recv = _Direction(keys["c2s_key"], keys["c2s_iv"])
        # fingerprint of all traffic keys, in canonical c2s||s2c order (identical on both sides)
        self.key_fingerprint = hashlib.sha256(
            keys["c2s_key"] + keys["c2s_iv"] + keys["s2c_key"] + keys["s2c_iv"]).hexdigest()
        self.closed = False
        self.close_reason = None
        self.records_sent = self.records_received = 0

    # ------------------------------------------------------------------ sending
    def seal(self, plaintext: bytes, final: bool = True, ctype: int = CT_APPLICATION) -> bytes:
        if self.closed:
            raise SessionClosed(f"session closed: {self.close_reason}")
        if len(plaintext) > MAX_RECORD_PLAINTEXT:
            raise RecordError("record too large")
        d = self._send
        if d.seq > MAX_SEQ:
            raise RecordError("sequence number exhausted - a new handshake is required")
        header = HDR.pack(ctype, FLAG_FINAL if final else 0, d.seq, len(plaintext) + TAG_LEN)
        ct = d.aead.encrypt(_nonce(d.iv, d.seq), plaintext, header)
        d.seq += 1
        self.records_sent += 1
        return header + ct

    def send_message(self, message: bytes, record_size: int = DEFAULT_RECORD_SIZE) -> list:
        """Fragment one application message into records (last one carries FLAG_FINAL)."""
        if record_size <= 0 or record_size > MAX_RECORD_PLAINTEXT:
            raise ValueError("invalid record size")
        mv = memoryview(message)
        n = max(1, -(-len(message) // record_size))
        return [self.seal(bytes(mv[i * record_size:(i + 1) * record_size]), final=(i == n - 1))
                for i in range(n)]

    # ------------------------------------------------------------------ receiving
    def _fail(self, exc: Exception):
        self.closed = True
        self.close_reason = f"{type(exc).__name__}: {exc}"
        raise exc

    def open(self, record: bytes):
        """Verify and decrypt one record. Returns (content_type, flags, plaintext)."""
        if self.closed:
            raise SessionClosed(f"session closed: {self.close_reason}")
        if len(record) < RECORD_OVERHEAD:
            self._fail(RecordError("record shorter than header + tag"))
        ctype, flags, seq, length = HDR.unpack_from(record, 0)
        d = self._recv
        if seq < d.seq:  # sequence number already consumed -> replay, rejected before decryption
            self._fail(ReplayError(f"record seq {seq} rejected: replayed (already received); "
                                   f"expected seq {d.seq}"))
        # The nonce is always built from the receiver's OWN expected counter and the header as
        # received is the AAD, so a modified header byte (type, flags, seq, length), a reordered
        # record, a dropped record or a record from another key/direction all fail the tag check.
        try:
            pt = d.aead.decrypt(_nonce(d.iv, d.seq), record[HEADER_LEN:], record[:HEADER_LEN])
        except InvalidTag as e:
            self.closed = True
            self.close_reason = "InvalidTag"
            hint = "" if seq == d.seq else f" (header seq {seq} != expected {d.seq}: reordered, dropped or tampered)"
            raise RecordAuthError(f"AES-256-GCM authentication failed on record (InvalidTag){hint}") from e
        if ctype not in (CT_APPLICATION, CT_CLOSE) or HEADER_LEN + length != len(record):
            self._fail(RecordError("malformed record from authenticated peer"))
        d.seq += 1
        self.records_received += 1
        return ctype, flags, pt

    def receive_message(self, records) -> bytes:
        """Reassemble one application message from an iterable of records."""
        parts = []
        for rec in records:
            ctype, flags, pt = self.open(rec)
            if ctype == CT_CLOSE:
                self.closed, self.close_reason = True, "peer closed"
                raise SessionClosed("peer closed the session")
            parts.append(pt)
            if flags & FLAG_FINAL:
                return b"".join(parts)
        raise RecordError("message incomplete: no final fragment")

    def close_record(self) -> bytes:
        rec = self.seal(b"", final=True, ctype=CT_CLOSE)
        self.closed, self.close_reason = True, "local close"
        return rec
