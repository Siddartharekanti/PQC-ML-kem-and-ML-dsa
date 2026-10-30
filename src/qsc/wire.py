"""Strict, canonical wire encoding for handshake messages.

    message := msg_type (1 B) || body_len (4 B, big-endian) || body
    body    := field*           (fixed order per message type, no extras, no trailing bytes)
    field   := field_id (1 B) || value_len (2 B, big-endian) || value

Every message has exactly one valid encoding, so the transcript hash over the raw bytes is
well defined, and *any* bit flip either breaks parsing (DecodeError) or changes a value that
is covered by the transcript signatures / Finished MACs.
"""
from __future__ import annotations

import struct

from .errors import DecodeError

# message types
CLIENT_HELLO = 0x01
SERVER_HELLO = 0x02
SERVER_VERIFY = 0x03
SERVER_FINISHED = 0x04
CLIENT_VERIFY = 0x05
CLIENT_FINISHED = 0x06

MSG_NAMES = {
    CLIENT_HELLO: "ClientHello",
    SERVER_HELLO: "ServerHello",
    SERVER_VERIFY: "ServerVerify",
    SERVER_FINISHED: "ServerFinished",
    CLIENT_VERIFY: "ClientVerify",
    CLIENT_FINISHED: "ClientFinished",
}
SHORT = {
    CLIENT_HELLO: "CH",
    SERVER_HELLO: "SH",
    SERVER_VERIFY: "SV",
    SERVER_FINISHED: "SF",
    CLIENT_VERIFY: "CV",
    CLIENT_FINISHED: "CF",
}

# field ids
F_VERSION = 0x01
F_SUITE = 0x02
F_ALGS = 0x03
F_CLIENT_ID = 0x04
F_CLIENT_KEY_ID = 0x05
F_SERVER_ID = 0x06
F_SERVER_KEY_ID = 0x07
F_CLIENT_NONCE = 0x08
F_SERVER_NONCE = 0x09
F_KEM_PK = 0x0A
F_KEM_CT = 0x0B
F_SIGNATURE = 0x0C
F_FINISHED = 0x0D

FIELD_NAMES = {
    F_VERSION: "version",
    F_SUITE: "suite_id",
    F_ALGS: "algorithm_ids",
    F_CLIENT_ID: "client_identity",
    F_CLIENT_KEY_ID: "client_key_id",
    F_SERVER_ID: "server_identity",
    F_SERVER_KEY_ID: "server_key_id",
    F_CLIENT_NONCE: "client_nonce",
    F_SERVER_NONCE: "server_nonce",
    F_KEM_PK: "kem_public_key",
    F_KEM_CT: "kem_ciphertext",
    F_SIGNATURE: "signature",
    F_FINISHED: "finished_mac",
}

# (field id, exact length or None, max length)
_SCHEMA = {
    CLIENT_HELLO: [
        (F_VERSION, 1, 1), (F_SUITE, 2, 2), (F_ALGS, None, 128), (F_CLIENT_ID, None, 64),
        (F_CLIENT_KEY_ID, 32, 32), (F_SERVER_ID, None, 64), (F_CLIENT_NONCE, 32, 32),
        (F_KEM_PK, None, 4096),
    ],
    SERVER_HELLO: [
        (F_VERSION, 1, 1), (F_SUITE, 2, 2), (F_ALGS, None, 128), (F_SERVER_ID, None, 64),
        (F_SERVER_KEY_ID, 32, 32), (F_CLIENT_ID, None, 64), (F_SERVER_NONCE, 32, 32),
        (F_KEM_CT, None, 4096),
    ],
    SERVER_VERIFY: [(F_SIGNATURE, None, 8192)],
    SERVER_FINISHED: [(F_FINISHED, 32, 32)],
    CLIENT_VERIFY: [(F_SIGNATURE, None, 8192)],
    CLIENT_FINISHED: [(F_FINISHED, 32, 32)],
}

MSG_HDR = struct.Struct(">BI")
FIELD_HDR = struct.Struct(">BH")
MAX_BODY = 64 * 1024


def encode(msg_type: int, values: dict) -> bytes:
    """Encode `values` (field id -> bytes) in the canonical order of the schema."""
    parts = []
    for fid, exact, maxlen in _SCHEMA[msg_type]:
        v = values[fid]
        if (exact is not None and len(v) != exact) or len(v) > maxlen:
            raise ValueError(f"bad length for {FIELD_NAMES[fid]}: {len(v)}")
        parts.append(FIELD_HDR.pack(fid, len(v)) + v)
    body = b"".join(parts)
    return MSG_HDR.pack(msg_type, len(body)) + body


def decode(data: bytes, expected_type: int) -> dict:
    """Strictly decode one message. Raises DecodeError on any deviation from the schema."""
    if len(data) < MSG_HDR.size:
        raise DecodeError("message shorter than header")
    mtype, blen = MSG_HDR.unpack_from(data, 0)
    if mtype != expected_type:
        raise DecodeError(f"expected {MSG_NAMES.get(expected_type)}, got message type 0x{mtype:02x}")
    if blen > MAX_BODY or MSG_HDR.size + blen != len(data):
        raise DecodeError(f"{MSG_NAMES[mtype]}: body length field {blen} does not match {len(data) - MSG_HDR.size}")
    out, pos = {}, MSG_HDR.size
    for fid, exact, maxlen in _SCHEMA[mtype]:
        if pos + FIELD_HDR.size > len(data):
            raise DecodeError(f"{MSG_NAMES[mtype]}: truncated before {FIELD_NAMES[fid]}")
        got_fid, vlen = FIELD_HDR.unpack_from(data, pos)
        if got_fid != fid:
            raise DecodeError(f"{MSG_NAMES[mtype]}: expected field {FIELD_NAMES[fid]}, got id 0x{got_fid:02x}")
        pos += FIELD_HDR.size
        if (exact is not None and vlen != exact) or vlen > maxlen or pos + vlen > len(data):
            raise DecodeError(f"{MSG_NAMES[mtype]}: invalid length {vlen} for {FIELD_NAMES[fid]}")
        out[fid] = data[pos:pos + vlen]
        pos += vlen
    if pos != len(data):
        raise DecodeError(f"{MSG_NAMES[mtype]}: {len(data) - pos} trailing bytes")
    return out


def field_spans(data: bytes) -> dict:
    """Map field name -> (start, end) byte offsets of each *value* inside an encoded message.

    Used by the tamper tests to flip bits in specific fields. Also returns the header spans.
    """
    mtype, _ = MSG_HDR.unpack_from(data, 0)
    spans = {"msg_type": (0, 1), "body_length": (1, 5)}
    pos = MSG_HDR.size
    for fid, _, _ in _SCHEMA[mtype]:
        _, vlen = FIELD_HDR.unpack_from(data, pos)
        spans[f"{FIELD_NAMES[fid]}.tlv_header"] = (pos, pos + FIELD_HDR.size)
        pos += FIELD_HDR.size
        spans[FIELD_NAMES[fid]] = (pos, pos + vlen)
        pos += vlen
    return spans


def split_flight(buf: bytes) -> list:
    """Split a byte string holding several concatenated messages (one flight)."""
    out, pos = [], 0
    while pos < len(buf):
        if pos + MSG_HDR.size > len(buf):
            raise DecodeError("truncated message header in flight")
        _, blen = MSG_HDR.unpack_from(buf, pos)
        end = pos + MSG_HDR.size + blen
        if end > len(buf) or blen > MAX_BODY:
            raise DecodeError("truncated message in flight")
        out.append(buf[pos:end])
        pos = end
    return out
