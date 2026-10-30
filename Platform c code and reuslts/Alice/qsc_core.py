#!/usr/bin/env python3
"""Shared QSC/1 protocol core for Alice, Mallory, and evaluation tools.

ML-KEM-768 establishes secrets, ML-DSA-65 authenticates the transcript,
HKDF-SHA256 derives directional keys, and AES-256-GCM protects records.
The classical comparison uses X25519 and Ed25519. Research prototype only.
"""
# =====================================================================================================
# QSC/1 PROTOCOL CORE  -  shared by Alice, Bob, Mallory and the evaluation tools.
# Wire-compatible with the repository implementation in src/qsc/ (same encoding, labels, key schedule).
# Only dependency: pip install cryptography==50.0.2   (all primitives come from this vetted library)
# =====================================================================================================
import csv
import datetime
import hashlib
import json
import os
import queue
import socket
import struct
import sys
import threading
import time

try:
    from cryptography.exceptions import InvalidSignature, InvalidTag
    from cryptography.hazmat.primitives import constant_time, hashes, hmac
    from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa, mlkem, x25519
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
except ImportError as _e:  # pragma: no cover
    sys.exit(f"cryptography with ML-KEM/ML-DSA is required: python -m pip install cryptography==50.0.2  ({_e})")

try:
    sys.stdout.reconfigure(errors="replace")
except Exception:  # noqa: BLE001
    pass
if os.name == "nt":
    os.system("")  # enable ANSI colours in Windows 10+ consoles

# ----------------------------------------------------------------------------------- console output
USE_COLOR = sys.stdout.isatty() and "NO_COLOR" not in os.environ
SHOW_SECRETS = True
_PLOCK = threading.Lock()


def col(code, s):
    return f"\033[{code}m{s}\033[0m" if USE_COLOR else str(s)


def say(*a):
    with _PLOCK:
        print(*a, flush=True)


def hx(b, n=24):
    b = bytes(b)
    return b.hex() if len(b) <= n else f"{b[:n].hex()}...({len(b)} B)"


def ms(ns):
    return f"{ns / 1e6:.3f} ms"


class Log:
    """Pretty, numbered, colour-coded step log for one party."""

    def __init__(self, who, color="36", enabled=True):
        self.who, self.color, self.enabled, self.n = who, color, enabled, 0

    def _p(self, s):
        if self.enabled:
            say(s)

    def banner(self, title, color=None):
        line = "=" * 92
        self._p(col(color or self.color, f"\n{line}\n  {title}\n{line}"))

    def step(self, title):
        self.n += 1
        self._p(col("1;" + self.color, f"\n[{self.who} {self.n:>2}] {title}"))

    def ok(self, msg):
        self._p("        " + col("32", "[OK] ") + msg)

    def info(self, msg):
        self._p("        " + msg)

    def warn(self, msg):
        self._p("        " + col("33", "[!]  ") + msg)

    def bad(self, msg):
        self._p("        " + col("1;31", "[X]  ") + col("31", msg))

    def kv(self, k, v):
        self._p(f"        {k:<34s} {v}")

    def secret(self, k, b):
        v = b.hex() if SHOW_SECRETS else f"<hidden, {len(b)} B>"
        self._p(f"        {k:<34s} " + col("35", v) + col("2", "   (SECRET - shown for the demo only)" if SHOW_SECRETS else ""))

    def fields(self, title, msg):
        try:
            f = decode(msg, msg[0])
        except Exception as e:  # noqa: BLE001
            self.warn(f"{title}: cannot decode ({e})")
            return
        self._p(f"        {col('1', title)}  type=0x{msg[0]:02x}  total {len(msg)} B on the wire")
        for fid, v in f.items():
            name = FIELD_NAMES[fid]
            shown = v.decode() if fid in TEXT_FIELDS else hx(v)
            self._p(f"          - {name:<18s} {len(v):>5d} B  {shown}")


# ----------------------------------------------------------------------------------- errors
class QSCError(Exception):
    pass


class HandshakeError(QSCError):
    pass


class DecodeError(HandshakeError):
    pass


class ProtocolStateError(HandshakeError):
    pass


class DowngradeError(HandshakeError):
    pass


class UntrustedIdentity(HandshakeError):
    pass


class IdentityMismatch(HandshakeError):
    pass


class SignatureError(HandshakeError):
    pass


class FinishedError(HandshakeError):
    pass


class KEMError(HandshakeError):
    pass


class HandshakeReplayError(HandshakeError):
    pass


class PeerAbort(HandshakeError):
    pass


class RecordError(QSCError):
    pass


class RecordAuthError(RecordError):
    pass


class ReplayError(RecordError):
    pass


class SessionClosed(RecordError):
    pass


WHY = {
    "SignatureError": "the signature does not verify over OUR transcript with the PINNED key -> handshake bytes "
                      "were modified, or the signature was forged (MITM)",
    "UntrustedIdentity": "the peer's key is not the pinned trust anchor -> impersonation attempt",
    "IdentityMismatch": "the message names a different party than this session is bound to -> identity swap / "
                        "misbinding",
    "DowngradeError": "suite / algorithm identifiers not allowed or not what was offered -> downgrade attempt",
    "DecodeError": "malformed or truncated message -> tampering on the wire",
    "FinishedError": "key-confirmation MAC mismatch -> the two sides do not hold the same keys",
    "KEMError": "KEM key/ciphertext rejected by the FIPS 203 / RFC 7748 input checks -> tampering",
    "HandshakeReplayError": "this ClientHello was already seen -> replayed handshake",
    "RecordAuthError": "AES-256-GCM tag check failed (InvalidTag) -> ciphertext or header modified, record "
                       "reordered/dropped, or wrong key; NO plaintext released",
    "ReplayError": "record sequence number already consumed -> replayed record",
    "PeerAbort": "the other side detected an attack and aborted the session",
    "ProtocolStateError": "message arrived in the wrong protocol state",
}


def is_security_attack(error):
    """Distinguish cryptographic/protocol attacks from ordinary mode/network faults."""
    return isinstance(error, (DecodeError, DowngradeError, UntrustedIdentity, IdentityMismatch,
                              SignatureError, FinishedError, KEMError, HandshakeReplayError,
                              RecordAuthError, ReplayError, PeerAbort))


def attack_detected(log, e):
    name = type(e).__name__
    log.banner(f"ATTACK DETECTED by {log.who}: {name}", "1;31")
    log._p(col("31", f"  error : {e}"))
    log._p(col("31", f"  why   : {WHY.get(name, 'protocol check failed')}"))
    log._p(col("31", "  result: connection aborted (fail-closed) - no traffic key is used, no data accepted"))


def save_attack_csv(path, role, phase, error, peer="", attempt="", successful_runs=""):
    """Append one detected attack/fault without overwriting earlier evidence."""
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    exists = os.path.exists(path) and os.path.getsize(path) > 0
    name = type(error).__name__
    row = {
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "role": role,
        "peer": peer,
        "phase": phase,
        "attempt": attempt,
        "successful_runs": successful_runs,
        "error_type": name,
        "error": str(error),
        "analysis": WHY.get(name, "connection interruption or protocol fault"),
        "action": "connection aborted; fresh session started; successful-run counter unchanged",
    }
    with open(path, "a", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=tuple(row))
        if not exists:
            writer.writeheader()
        writer.writerow(row)


# ----------------------------------------------------------------------------------- suites
class Suite:
    def __init__(self, sid, label, kem, sig, kem_pk_len, kem_ct_len, sig_len):
        self.sid, self.label, self.kem, self.sig = sid, label, kem, sig
        self.kem_pk_len, self.kem_ct_len, self.sig_len = kem_pk_len, kem_ct_len, sig_len

    @property
    def alg_string(self):
        return f"{self.kem},{self.sig},HKDF-SHA256,AES-256-GCM"


PQC = Suite(0x0101, "PQC", "ML-KEM-768", "ML-DSA-65", 1184, 1088, 3309)
CLASSICAL = Suite(0x0201, "CLASSICAL", "X25519", "Ed25519", 32, 32, 64)
SUITES = {s.sid: s for s in (PQC, CLASSICAL)}
BY_NAME = {"pqc": PQC, "classical": CLASSICAL}
SIG_ALGS = ("ML-DSA-65", "Ed25519")
CTX_SERVER = b"QFF26-P1/v1 server-verify"
CTX_CLIENT = b"QFF26-P1/v1 client-verify"
PROTOCOL_LABEL = b"QFF26-P1/v1"


def kem_keygen(s):
    if s is PQC:
        sk = mlkem.MLKEM768PrivateKey.generate()
    else:
        sk = x25519.X25519PrivateKey.generate()
    return sk, sk.public_key().public_bytes_raw()


def kem_encap(s, pk):
    try:
        if s is PQC:
            ss, ct = mlkem.MLKEM768PublicKey.from_public_bytes(pk).encapsulate()
            return ss, ct
        eph = x25519.X25519PrivateKey.generate()
        return eph.exchange(x25519.X25519PublicKey.from_public_bytes(pk)), eph.public_key().public_bytes_raw()
    except ValueError as e:
        raise KEMError(f"{s.kem} public key rejected: {e}") from e


def kem_decap(s, sk, ct):
    try:
        if s is PQC:
            return sk.decapsulate(ct)
        return sk.exchange(x25519.X25519PublicKey.from_public_bytes(ct))
    except ValueError as e:
        raise KEMError(f"{s.kem} ciphertext rejected: {e}") from e


def sig_sign(alg, sk, msg, ctx):
    if alg == "ML-DSA-65":
        return sk.sign(msg, ctx)  # FIPS 204 context string
    return sk.sign(bytes([len(ctx)]) + ctx + msg)


def sig_verify(alg, pk, sig, msg, ctx):
    try:
        if alg == "ML-DSA-65":
            mldsa.MLDSA65PublicKey.from_public_bytes(pk).verify(sig, msg, ctx)
        else:
            ed25519.Ed25519PublicKey.from_public_bytes(pk).verify(sig, bytes([len(ctx)]) + ctx + msg)
    except (InvalidSignature, ValueError) as e:
        raise SignatureError(f"{alg} public key or signature was rejected") from e


def key_id(pk):
    return hashlib.sha256(pk).digest()


# ----------------------------------------------------------------------------------- wire format
CH, SH, SV, SF, CV, CF, PUBLIC_KEYS, ALERT = 1, 2, 3, 4, 5, 6, 7, 0xFF
MSG_NAMES = {CH: "ClientHello", SH: "ServerHello", SV: "ServerVerify", SF: "ServerFinished",
             CV: "ClientVerify", CF: "ClientFinished", PUBLIC_KEYS: "PublicKeyAnnouncement", ALERT: "Alert"}
(F_VERSION, F_SUITE, F_ALGS, F_CLIENT_ID, F_CLIENT_KEY_ID, F_SERVER_ID, F_SERVER_KEY_ID, F_CLIENT_NONCE,
 F_SERVER_NONCE, F_KEM_PK, F_KEM_CT, F_SIGNATURE, F_FINISHED,
 F_IDENTITY, F_MLDSA_PUBLIC, F_ED25519_PUBLIC) = range(1, 17)
FIELD_NAMES = {F_VERSION: "version", F_SUITE: "suite_id", F_ALGS: "algorithm_ids", F_CLIENT_ID: "client_identity",
               F_CLIENT_KEY_ID: "client_key_id", F_SERVER_ID: "server_identity", F_SERVER_KEY_ID: "server_key_id",
               F_CLIENT_NONCE: "client_nonce", F_SERVER_NONCE: "server_nonce", F_KEM_PK: "kem_public_key",
               F_KEM_CT: "kem_ciphertext", F_SIGNATURE: "signature", F_FINISHED: "finished_mac",
               F_IDENTITY: "identity",
               F_MLDSA_PUBLIC: "ML-DSA-65_public_key", F_ED25519_PUBLIC: "Ed25519_public_key"}
TEXT_FIELDS = {F_ALGS, F_CLIENT_ID, F_SERVER_ID, F_IDENTITY}
SCHEMA = {
    CH: [(F_VERSION, 1, 1), (F_SUITE, 2, 2), (F_ALGS, None, 128), (F_CLIENT_ID, None, 64), (F_CLIENT_KEY_ID, 32, 32),
         (F_SERVER_ID, None, 64), (F_CLIENT_NONCE, 32, 32),
         (F_KEM_PK, None, 4096)],
    SH: [(F_VERSION, 1, 1), (F_SUITE, 2, 2), (F_ALGS, None, 128), (F_SERVER_ID, None, 64), (F_SERVER_KEY_ID, 32, 32),
         (F_CLIENT_ID, None, 64), (F_SERVER_NONCE, 32, 32), (F_KEM_CT, None, 4096)],
    SV: [(F_SIGNATURE, None, 8192)], SF: [(F_FINISHED, 32, 32)],
    CV: [(F_SIGNATURE, None, 8192)], CF: [(F_FINISHED, 32, 32)],
    PUBLIC_KEYS: [(F_IDENTITY, None, 64), (F_MLDSA_PUBLIC, 1952, 1952), (F_ED25519_PUBLIC, 32, 32)],
}
MSG_HDR = struct.Struct(">BI")
FIELD_HDR = struct.Struct(">BH")
MAX_BODY = 64 * 1024


def encode(mtype, values):
    parts = []
    for fid, exact, maxlen in SCHEMA[mtype]:
        v = values[fid]
        if (exact is not None and len(v) != exact) or len(v) > maxlen:
            raise ValueError(f"bad length for {FIELD_NAMES[fid]}")
        parts.append(FIELD_HDR.pack(fid, len(v)) + v)
    body = b"".join(parts)
    return MSG_HDR.pack(mtype, len(body)) + body


def decode(data, expected):
    if len(data) < MSG_HDR.size:
        raise DecodeError("message shorter than header")
    mtype, blen = MSG_HDR.unpack_from(data, 0)
    if mtype != expected:
        raise DecodeError(f"expected {MSG_NAMES.get(expected)}, got message type 0x{mtype:02x}")
    if blen > MAX_BODY or MSG_HDR.size + blen != len(data):
        raise DecodeError(f"{MSG_NAMES[mtype]}: body length field {blen} does not match {len(data) - 5}")
    out, pos = {}, MSG_HDR.size
    for fid, exact, maxlen in SCHEMA[mtype]:
        if pos + 3 > len(data):
            raise DecodeError(f"{MSG_NAMES[mtype]}: truncated before {FIELD_NAMES[fid]}")
        got, vlen = FIELD_HDR.unpack_from(data, pos)
        if got != fid:
            raise DecodeError(f"{MSG_NAMES[mtype]}: expected field {FIELD_NAMES[fid]}, got id 0x{got:02x}")
        pos += 3
        if (exact is not None and vlen != exact) or vlen > maxlen or pos + vlen > len(data):
            raise DecodeError(f"{MSG_NAMES[mtype]}: invalid length {vlen} for {FIELD_NAMES[fid]}")
        out[fid] = data[pos:pos + vlen]
        pos += vlen
    if pos != len(data):
        raise DecodeError(f"{MSG_NAMES[mtype]}: {len(data) - pos} trailing bytes")
    return out


def field_span(msg, fid):
    """(start, end) offsets of field `fid`'s value inside an encoded message."""
    pos = MSG_HDR.size
    for f, _, _ in SCHEMA[msg[0]]:
        _, vlen = FIELD_HDR.unpack_from(msg, pos)
        pos += 3
        if f == fid:
            return pos, pos + vlen
        pos += vlen
    raise KeyError(fid)


def flip_bit(data, index, bit=0):
    b = bytearray(data)
    b[index] ^= 1 << bit
    return bytes(b)


# ----------------------------------------------------------------------------------- transcript + key schedule
class Transcript:
    def __init__(self):
        self._h = hashes.Hash(hashes.SHA256())

    def add(self, msg):
        self._h.update(msg)
        return self.digest()

    def digest(self):
        return self._h.copy().finalize()


def hkdf_extract(salt, ss):
    return HKDF.extract(hashes.SHA256(), salt, ss)


def hkdf_expand(prk, sid, label, th, n):
    info = PROTOCOL_LABEL + sid.to_bytes(2, "big") + bytes([len(label)]) + label + th
    return HKDFExpand(algorithm=hashes.SHA256(), length=n, info=info).derive(prk)


def finished_mac(key, th):
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(th)
    return h.finalize()


def traffic_keys(prk, sid, th_full):
    e = lambda label, n: hkdf_expand(prk, sid, label, th_full, n)  # noqa: E731
    return {"c2s_key": e(b"c2s key", 32), "c2s_iv": e(b"c2s iv", 12), "s2c_key": e(b"s2c key", 32),
            "s2c_iv": e(b"s2c iv", 12), "exporter": e(b"exporter", 32)}


# ----------------------------------------------------------------------------------- record layer
REC_HDR = struct.Struct(">BBQI")   # content_type, flags, seq, length  (14 B, the AES-GCM AAD)
CT_APP, CT_CLOSE, FLAG_FINAL = 0x17, 0x15, 0x01
RECORD_SIZE = 16 * 1024


def _nonce(iv, seq):
    return (int.from_bytes(iv, "big") ^ seq).to_bytes(12, "big")


class Session:
    def __init__(self, role, suite, peer, keys, th_full):
        self.role, self.suite, self.peer, self.th = role, suite, peer, th_full
        self.keys = keys
        mine, theirs = ("c2s", "s2c") if role == "client" else ("s2c", "c2s")
        self.tx = [AESGCM(keys[f"{mine}_key"]), keys[f"{mine}_iv"], 0]
        self.rx = [AESGCM(keys[f"{theirs}_key"]), keys[f"{theirs}_iv"], 0]
        self.fingerprint = hashlib.sha256(keys["c2s_key"] + keys["c2s_iv"] + keys["s2c_key"] +
                                          keys["s2c_iv"]).hexdigest()
        self.closed, self.lock = False, threading.Lock()

    def seal(self, pt, final=True, ctype=CT_APP):
        if self.closed:
            raise SessionClosed("session closed")
        aead, iv, seq = self.tx
        hdr = REC_HDR.pack(ctype, FLAG_FINAL if final else 0, seq, len(pt) + 16)
        self.tx[2] += 1
        return hdr + aead.encrypt(_nonce(iv, seq), pt, hdr)

    def send_message(self, msg, record_size=RECORD_SIZE):
        n = max(1, -(-len(msg) // record_size))
        mv = memoryview(msg)
        return [self.seal(bytes(mv[i * record_size:(i + 1) * record_size]), i == n - 1) for i in range(n)]

    def open(self, rec):
        if self.closed:
            raise SessionClosed("session closed")
        if len(rec) < 30:
            self.closed = True
            raise RecordError("record shorter than header + tag")
        ctype, flags, seq, length = REC_HDR.unpack_from(rec, 0)
        aead, iv, exp = self.rx
        if seq < exp:
            self.closed = True
            raise ReplayError(f"record seq {seq} already received (expected seq {exp}) -> replay rejected "
                              f"BEFORE decryption")
        try:
            pt = aead.decrypt(_nonce(iv, exp), rec[14:], rec[:14])
        except InvalidTag as e:
            self.closed = True
            hint = "" if seq == exp else f"; header seq {seq} != expected {exp} (reordered, dropped or tampered)"
            raise RecordAuthError(f"AES-256-GCM InvalidTag on record seq {seq}{hint}") from e
        self.rx[2] += 1
        return ctype, flags, pt


# ----------------------------------------------------------------------------------- TCP framing
class Conn:
    def __init__(self, sock):
        self.sock, self.sent, self.received = sock, 0, 0
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass

    def send(self, data):
        self.sock.sendall(data)
        self.sent += len(data)

    def recv_exact(self, n):
        buf = bytearray()
        while len(buf) < n:
            chunk = self.sock.recv(min(n - len(buf), 1 << 20))
            if not chunk:
                raise ConnectionError("connection closed by peer")
            buf += chunk
        self.received += n
        return bytes(buf)

    def read_frame(self):
        """One frame of any kind: handshake message / alert (type 1-6, 0xFF) or record (0x17, 0x15)."""
        first = self.recv_exact(1)
        if first[0] in MSG_NAMES:
            rest = self.recv_exact(4)
            blen = struct.unpack(">I", rest)[0]
            if blen > MAX_BODY:
                raise DecodeError("frame too large")
            return first + rest + self.recv_exact(blen)
        hdr = first + self.recv_exact(13)
        length = REC_HDR.unpack(hdr)[3]
        if length > 16 * 1024 * 1024 + 16:
            raise RecordError("record too large")
        return hdr + self.recv_exact(length)

    def read_handshake(self):
        f = self.read_frame()
        if f[0] == ALERT:
            raise PeerAbort("peer aborted: " + f[5:].decode("utf-8", "replace"))
        if f[0] not in MSG_NAMES:
            raise DecodeError("expected a handshake message, got a record")
        return f

    def read_record(self):
        f = self.read_frame()
        if f[0] == ALERT:
            raise PeerAbort("peer aborted: " + f[5:].decode("utf-8", "replace"))
        if f[0] in MSG_NAMES:
            raise RecordError("unexpected handshake message after the handshake")
        return f

    def send_alert(self, reason):
        body = reason.encode()[:1024]
        try:
            self.send(struct.pack(">BI", ALERT, len(body)) + body)
        except OSError:
            pass

    def close(self):
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass


# ----------------------------------------------------------------------------------- identities + pins
def init_identity(name, directory="."):
    """Create <name>.key.json (PRIVATE - never share) and <name>.pub.json (public - give to peers)."""
    d = mldsa.MLDSA65PrivateKey.generate()
    e = ed25519.Ed25519PrivateKey.generate()
    pd, pe = d.public_key().public_bytes_raw(), e.public_key().public_bytes_raw()
    key_path = os.path.join(directory, f"{name}.key.json")
    pub_path = os.path.join(directory, f"{name}.pub.json")
    with open(key_path, "w") as f:
        json.dump({"name": name, "ML-DSA-65_seed": d.private_bytes_raw().hex(),
                   "Ed25519_private": e.private_bytes_raw().hex()}, f, indent=2)
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass
    with open(pub_path, "w") as f:
        json.dump({"name": name, "ML-DSA-65": pd.hex(), "Ed25519": pe.hex(),
                   "key_id_ML-DSA-65": key_id(pd).hex(), "key_id_Ed25519": key_id(pe).hex()}, f, indent=2)
    return key_path, pub_path


def load_identity(path):
    d = json.load(open(path))
    sk_d = mldsa.MLDSA65PrivateKey.from_seed_bytes(bytes.fromhex(d["ML-DSA-65_seed"]))
    sk_e = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(d["Ed25519_private"]))
    return d["name"], {"ML-DSA-65": (sk_d, sk_d.public_key().public_bytes_raw()),
                       "Ed25519": (sk_e, sk_e.public_key().public_bytes_raw())}


def load_pub(path):
    d = json.load(open(path))
    pins = {}
    for alg in SIG_ALGS:
        pk = bytes.fromhex(d[alg])
        if key_id(pk).hex() != d[f"key_id_{alg}"]:
            raise ValueError(f"{path}: corrupted public key file")
        pins[alg] = pk
    return d["name"], pins


def lookup_pin(pins, name, alg, claimed_kid):
    pk = pins.get((name, alg))
    if pk is None:
        raise UntrustedIdentity(f"identity '{name}' ({alg}) is not in my pinned trust store")
    if key_id(pk) != claimed_kid:
        raise UntrustedIdentity(f"key presented for '{name}' (key id {claimed_kid.hex()[:16]}...) does NOT match "
                                f"the pinned trust anchor (key id {key_id(pk).hex()[:16]}...)")
    return pk


def public_key_announcement(name, identities):
    """Encode both long-term verification keys for post-handshake synchronization."""
    return encode(PUBLIC_KEYS, {
        F_IDENTITY: name.encode(),
        F_MLDSA_PUBLIC: identities["ML-DSA-65"][1],
        F_ED25519_PUBLIC: identities["Ed25519"][1],
    })


def verify_public_key_announcement(message, expected_name, expected_pins, log):
    """Accept a session-protected announcement only when every key matches a pin."""
    fields = decode(message, PUBLIC_KEYS)
    announced_name = fields[F_IDENTITY].decode("utf-8", "replace")
    if announced_name != expected_name:
        raise IdentityMismatch(f"public-key announcement names '{announced_name}', expected '{expected_name}'")
    announced = {"ML-DSA-65": fields[F_MLDSA_PUBLIC], "Ed25519": fields[F_ED25519_PUBLIC]}
    for algorithm, public_key in announced.items():
        pinned = expected_pins.get(algorithm)
        if pinned is None or not constant_time.bytes_eq(public_key, pinned):
            raise UntrustedIdentity(f"session-delivered {algorithm} key for '{expected_name}' does not match "
                                    "the pinned trust anchor")
        log.ok(f"session-delivered {algorithm} key for '{expected_name}' matches pinned fingerprint "
               f"{key_id(public_key).hex()}")
    return announced


def check_suite_fields(s, f, who):
    if f[F_VERSION] != b"\x01":
        raise DowngradeError(f"{who}: unsupported protocol version {f[F_VERSION].hex()}")
    if f[F_ALGS] != s.alg_string.encode():
        raise DowngradeError(f"{who}: algorithm identifiers {f[F_ALGS]!r} do not match suite 0x{s.sid:04x} "
                             f"({s.alg_string})")


# ----------------------------------------------------------------------------------- the handshake (client)
def client_handshake(conn, my_name, my_ids, server_name, server_pins, suite, log):
    """Alice's side. server_pins = {alg: pinned public key of the intended server}."""
    tr = Transcript()
    sig_sk, sig_pk = my_ids[suite.sig]
    T = time.perf_counter_ns
    t_start = T()
    try:
        log.step(f"Generate ephemeral {suite.kem} key pair (fresh for THIS session -> forward secrecy)")
        t = T()
        dk, ek = kem_keygen(suite)
        log.kv("encapsulation key ek (public)", f"{hx(ek)}")
        log.kv("decapsulation key dk", "kept in memory only, never sent")
        log.kv("time", ms(T() - t))
        nonce_a = os.urandom(32)
        log.kv("client nonce (32 random bytes)", hx(nonce_a, 32))

        log.step("Send ClientHello  (Alice -> Bob)")
        ch = encode(CH, {F_VERSION: b"\x01", F_SUITE: suite.sid.to_bytes(2, "big"),
                         F_ALGS: suite.alg_string.encode(), F_CLIENT_ID: my_name.encode(),
                         F_CLIENT_KEY_ID: key_id(sig_pk), F_SERVER_ID: server_name.encode(),
                         F_CLIENT_NONCE: nonce_a, F_KEM_PK: ek})
        log.fields("ClientHello", ch)
        th = tr.add(ch)
        log.kv("transcript hash TH(CH)", hx(th, 32))
        conn.send(ch)

        log.step("Receive Bob's flight: ServerHello + ServerVerify + ServerFinished")
        sh = conn.read_handshake()
        sv = conn.read_handshake()
        sf = conn.read_handshake()
        log.fields("ServerHello", sh)
        f = decode(sh, SH)

        log.step("Check ServerHello: suite, algorithms, identities, pinned key")
        if int.from_bytes(f[F_SUITE], "big") != suite.sid:
            raise DowngradeError(f"server selected suite 0x{f[F_SUITE].hex()}, I offered 0x{suite.sid:04x} only")
        check_suite_fields(suite, f, "ServerHello")
        log.ok(f"suite 0x{suite.sid:04x} and algorithm ids '{suite.alg_string}' = exactly what I offered")
        sname = f[F_SERVER_ID].decode("utf-8", "replace")
        if sname != server_name:
            raise IdentityMismatch(f"ServerHello is from '{sname}', this session is bound to '{server_name}'")
        if f[F_CLIENT_ID] != my_name.encode():
            raise IdentityMismatch(f"ServerHello names client '{f[F_CLIENT_ID].decode('utf-8', 'replace')}', "
                                   f"not me ('{my_name}')")
        log.ok(f"server identity = '{sname}' (intended peer); client identity echoed = '{my_name}'")
        pins = {(server_name, a): pk for a, pk in server_pins.items()}
        bob_pk = lookup_pin(pins, sname, suite.sig, f[F_SERVER_KEY_ID])
        log.ok(f"server key id {f[F_SERVER_KEY_ID].hex()[:32]}... matches my PINNED {suite.sig} key for '{sname}'")
        if len(f[F_KEM_CT]) != suite.kem_ct_len:
            raise DecodeError(f"KEM ciphertext must be {suite.kem_ct_len} B")
        th_sh = tr.add(sh)
        log.kv("transcript hash TH(CH,SH)", hx(th_sh, 32))

        log.step(f"{suite.kem} Decapsulate Bob's ciphertext -> shared secret")
        t = T()
        ss = kem_decap(suite, dk, f[F_KEM_CT])
        dk = None
        log.kv("ciphertext ct", hx(f[F_KEM_CT]))
        log.secret("shared secret ss", ss)
        log.kv("time", ms(T() - t))

        log.step("HKDF-SHA256 key schedule (handshake keys)")
        prk = hkdf_extract(nonce_a + f[F_SERVER_NONCE], ss)
        s_fin = hkdf_expand(prk, suite.sid, b"s finished", th_sh, 32)
        c_fin = hkdf_expand(prk, suite.sid, b"c finished", th_sh, 32)
        log.kv("salt", "client_nonce || server_nonce (64 B)")
        log.secret("PRK = HKDF-Extract(salt, ss)", prk)
        log.secret("server-finished key", s_fin)
        log.secret("client-finished key", c_fin)

        log.step(f"Verify Bob's {suite.sig} signature over TH(CH,SH) with the PINNED key")
        sig = decode(sv, SV)[F_SIGNATURE]
        if len(sig) != suite.sig_len:
            raise DecodeError(f"server signature must be {suite.sig_len} B")
        t = T()
        sig_verify(suite.sig, bob_pk, sig, th_sh, CTX_SERVER)
        log.kv("signature", hx(sig))
        log.ok(f"ServerVerify signature VALID ({ms(T() - t)}) -> Bob is authenticated and bound to this transcript")
        th_sv = tr.add(sv)

        log.step("Verify ServerFinished (HMAC-SHA256 key confirmation)")
        if not constant_time.bytes_eq(finished_mac(s_fin, th_sv), decode(sf, SF)[F_FINISHED]):
            raise FinishedError("ServerFinished MAC mismatch")
        log.ok("ServerFinished VALID -> Bob derived the same shared secret")
        th_sf = tr.add(sf)

        log.step(f"Send ClientVerify ({suite.sig} signature by Alice) + ClientFinished  (Alice -> Bob)")
        t = T()
        cv = encode(CV, {F_SIGNATURE: sig_sign(suite.sig, sig_sk, th_sf, CTX_CLIENT)})
        log.kv("my signature over TH(CH..SF)", f"{hx(decode(cv, CV)[F_SIGNATURE])}  ({ms(T() - t)})")
        th_cv = tr.add(cv)
        cf = encode(CF, {F_FINISHED: finished_mac(c_fin, th_cv)})
        log.kv("ClientFinished MAC", hx(cf[8:], 32))
        th_full = tr.add(cf)
        conn.send(cv + cf)

        log.step("Derive traffic keys from the FULL transcript hash TH(CH..CF)")
        keys = traffic_keys(prk, suite.sid, th_full)
        for k in ("c2s_key", "c2s_iv", "s2c_key", "s2c_iv", "exporter"):
            log.secret(k, keys[k])
        session = Session("client", suite, sname, keys, th_full)
        session.stats = {"handshake_ms": (T() - t_start) / 1e6, "sent": conn.sent, "received": conn.received}
        return session
    except HandshakeError as e:
        if not isinstance(e, PeerAbort):
            conn.send_alert(f"{type(e).__name__}: {e}")
        raise


# ----------------------------------------------------------------------------------- the handshake (server)
class ReplayCache:
    def __init__(self, cap=100_000):
        self.seen, self.cap = {}, cap

    def check_and_add(self, nonce):
        if nonce in self.seen:
            raise HandshakeReplayError("ClientHello nonce already seen -> replayed handshake rejected")
        self.seen[nonce] = None
        if len(self.seen) > self.cap:
            self.seen.pop(next(iter(self.seen)))


def server_handshake(conn, my_name, my_ids, client_pins, policy, replay_cache, log, ch=None):
    """Bob's side. client_pins = {(name, alg): pk}. policy = allowed suite ids."""
    tr = Transcript()
    T = time.perf_counter_ns
    try:
        log.step("Receive ClientHello")
        ch = ch or conn.read_handshake()
        t_start = T()
        log.fields("ClientHello", ch)
        f = decode(ch, CH)

        log.step("Check ClientHello: policy, algorithms, identities, pinned client key ID, replay")
        sid = int.from_bytes(f[F_SUITE], "big")
        if sid not in policy:
            known = SUITES[sid].label + " " if sid in SUITES else ""
            raise DowngradeError(f"suite {known}0x{sid:04x} not permitted by my policy "
                                 f"(allowed: {', '.join(SUITES[x].label for x in sorted(policy))})")
        s = SUITES[sid]
        check_suite_fields(s, f, "ClientHello")
        log.ok(f"suite {s.label} 0x{sid:04x} allowed by policy; algorithm ids '{s.alg_string}' consistent")
        if f[F_SERVER_ID] != my_name.encode():
            raise IdentityMismatch(f"ClientHello is addressed to '{f[F_SERVER_ID].decode('utf-8', 'replace')}', "
                                   f"not to me ('{my_name}')")
        log.ok(f"ClientHello is addressed to me ('{my_name}')")
        cname = f[F_CLIENT_ID].decode("utf-8", "replace")
        client_pk = lookup_pin(client_pins, cname, s.sig, f[F_CLIENT_KEY_ID])
        log.ok(f"client '{cname}' key id {f[F_CLIENT_KEY_ID].hex()[:32]}... matches my PINNED {s.sig} key")
        if len(f[F_KEM_PK]) != s.kem_pk_len:
            raise DecodeError(f"KEM public key must be {s.kem_pk_len} B, got {len(f[F_KEM_PK])}")
        if replay_cache is not None:
            replay_cache.check_and_add(f[F_CLIENT_NONCE])
            log.ok("client nonce never seen before (replay cache)")
        tr.add(ch)

        log.step(f"{s.kem} Encapsulate to Alice's ephemeral key -> shared secret + ciphertext")
        t = T()
        ss, ct = kem_encap(s, f[F_KEM_PK])
        log.kv("ciphertext ct (public)", hx(ct))
        log.secret("shared secret ss", ss)
        log.kv("time", ms(T() - t))
        nonce_b = os.urandom(32)
        sig_sk, sig_pk = my_ids[s.sig]
        sh = encode(SH, {F_VERSION: b"\x01", F_SUITE: f[F_SUITE], F_ALGS: s.alg_string.encode(),
                         F_SERVER_ID: my_name.encode(), F_SERVER_KEY_ID: key_id(sig_pk),
                         F_CLIENT_ID: f[F_CLIENT_ID],
                         F_SERVER_NONCE: nonce_b, F_KEM_CT: ct})
        th_sh = tr.add(sh)

        log.step("HKDF-SHA256 key schedule (handshake keys)")
        prk = hkdf_extract(f[F_CLIENT_NONCE] + nonce_b, ss)
        s_fin = hkdf_expand(prk, sid, b"s finished", th_sh, 32)
        c_fin = hkdf_expand(prk, sid, b"c finished", th_sh, 32)
        log.secret("PRK = HKDF-Extract(salt, ss)", prk)
        log.secret("server-finished key", s_fin)
        log.secret("client-finished key", c_fin)

        log.step(f"Sign TH(CH,SH) with my {s.sig} identity key; send ServerHello + ServerVerify + ServerFinished")
        t = T()
        sv = encode(SV, {F_SIGNATURE: sig_sign(s.sig, sig_sk, th_sh, CTX_SERVER)})
        log.kv("signature", f"{hx(sv[8:])}  ({ms(T() - t)})")
        th_sv = tr.add(sv)
        sf = encode(SF, {F_FINISHED: finished_mac(s_fin, th_sv)})
        tr.add(sf)
        log.fields("ServerHello", sh)
        log.kv("ServerVerify / ServerFinished", f"{len(sv)} B / {len(sf)} B")
        conn.send(sh + sv + sf)

        log.step("Receive ClientVerify + ClientFinished")
        cv = conn.read_handshake()
        cf = conn.read_handshake()
        th_sf = tr.digest()
        sig = decode(cv, CV)[F_SIGNATURE]
        if len(sig) != s.sig_len:
            raise DecodeError(f"client signature must be {s.sig_len} B")
        t = T()
        sig_verify(s.sig, client_pk, sig, th_sf, CTX_CLIENT)
        log.ok(f"ClientVerify signature VALID with Alice's PINNED key ({ms(T() - t)}) "
               "-> mutual authentication")
        th_cv = tr.add(cv)
        if not constant_time.bytes_eq(finished_mac(c_fin, th_cv), decode(cf, CF)[F_FINISHED]):
            raise FinishedError("ClientFinished MAC mismatch")
        log.ok("ClientFinished VALID -> Alice derived the same shared secret")
        th_full = tr.add(cf)

        log.step("Derive traffic keys from the FULL transcript hash TH(CH..CF)")
        keys = traffic_keys(prk, sid, th_full)
        for k in ("c2s_key", "c2s_iv", "s2c_key", "s2c_iv", "exporter"):
            log.secret(k, keys[k])
        session = Session("server", s, cname, keys, th_full)
        session.peer_pinned = (cname, s.sig) in client_pins
        session.stats = {"handshake_ms": (T() - t_start) / 1e6, "sent": conn.sent, "received": conn.received}
        return session
    except HandshakeError as e:
        if not isinstance(e, PeerAbort):
            conn.send_alert(f"{type(e).__name__}: {e}")
        raise


def established_banner(log, session, peer_label):
    s = session
    log.banner(f"SECURE CHANNEL ESTABLISHED with '{s.peer}' ({peer_label})", "1;32")
    log._p(f"  suite              : {s.suite.label}  ({s.suite.alg_string})")
    log._p("  authentication     : MUTUAL (both sides signed the transcript, peer key checked against a pin)")
    log._p(f"  handshake time     : {s.stats['handshake_ms']:.2f} ms (my side)")
    log._p(f"  bytes sent / recv  : {s.stats['sent']:,} B / {s.stats['received']:,} B")
    log._p(f"  transcript hash    : {s.th.hex()}")
    log._p("  SESSION FINGERPRINT: " + col("1;32", " ".join(s.fingerprint[i:i + 4] for i in range(0, 32, 4))))
    log._p(col("2", "  (Alice and Bob must see the SAME fingerprint - compare them out loud)"))


# ----------------------------------------------------------------------------------- application messages
PAYLOADS = {"payload_1KB.bin": 1024, "payload_100KB.bin": 100 * 1024, "payload_10MB.bin": 10 * 1024 * 1024}
MAX_FILE_SIZE = 64 * 1024 * 1024
OFFICIAL_SHA256 = {
    "payload_1KB.bin": "b581f87af96e450e8d49e13990d2753f6b4317f2228481c2d0f086c1463f084d",
    "payload_100KB.bin": "56d1e88b9066a2effcb2c6a97f6af99fc28c82b022902b996711fb15dcd59f04",
    "payload_10MB.bin": "c6bf29308ba5a7412a3a92a97d9618073da01eb68d57b6a9eb4b01819358c716",
}


def make_payload(name):
    """Same bytes as the kit's gen_payloads.py: SHAKE-256('QFF2026-P1-<name>')."""
    return hashlib.shake_256(f"QFF2026-P1-{name}".encode()).digest(PAYLOADS[name])


def send_app(conn, session, kind, body, log=None):
    """kind: b'T' text, b'P' payload/file, b'R' receipt. Returns number of records."""
    t = time.perf_counter_ns()
    with session.lock:
        recs = session.send_message(kind + body)
        wire = b"".join(recs)
        conn.send(wire)
    if log:
        log._p(col("2", f"        -> encrypted {len(body) + 1:,} B into {len(recs)} AES-256-GCM record(s), "
                        f"{len(wire):,} B on the wire (overhead {len(wire) - len(body) - 1} B = {len(recs)} x 30 B), "
                        f"seq {session.tx[2] - len(recs)}..{session.tx[2] - 1}, {ms(time.perf_counter_ns() - t)}"))
    return len(recs)


def recv_app(conn, session):
    parts, nrec = [], 0
    while True:
        rec = conn.read_record()
        ctype, flags, pt = session.open(rec)
        nrec += 1
        if ctype == CT_CLOSE:
            session.closed = True
            raise SessionClosed("peer closed the session")
        parts.append(pt)
        if flags & FLAG_FINAL:
            msg = b"".join(parts)
            return msg[:1], msg[1:], nrec


def client_secure_public_key_exchange(conn, session, my_name, my_ids, server_name, server_pins, log):
    """Exchange full identity keys only after the authenticated traffic keys exist."""
    log.step("Send my identity public keys inside the encrypted session  (Alice -> Bob)")
    mine = public_key_announcement(my_name, my_ids)
    send_app(conn, session, b"K", mine, log)
    log.step("Receive Bob's identity public keys inside the encrypted session")
    kind, theirs, _ = recv_app(conn, session)
    if kind != b"K":
        raise RecordError("expected Bob's encrypted public-key bundle")
    log.fields("Decrypted Bob public-key bundle", theirs)
    verified = verify_public_key_announcement(theirs, server_name, server_pins, log)
    session.stats["sent"], session.stats["received"] = conn.sent, conn.received
    return verified


def server_secure_public_key_exchange(conn, session, my_name, my_ids, client_pins, log):
    """Receive Alice's encrypted key bundle, verify pins, then return Bob's bundle."""
    log.step("Receive Alice's identity public keys inside the encrypted session")
    kind, theirs, _ = recv_app(conn, session)
    if kind != b"K":
        raise RecordError("expected Alice's encrypted public-key bundle")
    log.fields("Decrypted Alice public-key bundle", theirs)
    expected = {algorithm: client_pins.get((session.peer, algorithm)) for algorithm in SIG_ALGS}
    verify_public_key_announcement(theirs, session.peer, expected, log)
    log.step("Send my identity public keys inside the encrypted session  (Bob -> Alice)")
    mine = public_key_announcement(my_name, my_ids)
    send_app(conn, session, b"K", mine, log)
    session.stats["sent"], session.stats["received"] = conn.sent, conn.received


def pack_named(name, data):
    nb = name.encode()[:200]
    return bytes([len(nb)]) + nb + data


def unpack_named(body):
    n = body[0]
    return body[1:1 + n].decode("utf-8", "replace"), body[1 + n:]


def send_official_payload_batch(conn, session, log):
    """Send all official payloads and require byte-exact SHA-256 receipts."""
    pending = {}
    for name in PAYLOADS:
        data = make_payload(name)
        pending[name] = hashlib.sha256(data).hexdigest()
        log.info(f"sending official payload '{name}' ({len(data):,} bytes)")
        send_app(conn, session, b"P", pack_named(name, data), log)
    while pending:
        kind, body, _ = recv_app(conn, session)
        if kind != b"R":
            raise ProtocolStateError(f"expected payload receipt, received application kind {kind!r}")
        name, separator, digest = body.decode("ascii", "strict").partition("|")
        expected = pending.get(name)
        if not separator or expected is None:
            raise RecordError(f"unexpected or duplicate receipt for '{name}'")
        if not constant_time.bytes_eq(digest.encode(), expected.encode()):
            raise RecordError(f"SHA-256 receipt mismatch for '{name}': {digest}, expected {expected}")
        pending.pop(name)
        log.ok(f"receipt verified for '{name}': {digest}")


def receive_official_payload_batch(conn, session, log):
    """Receive each official payload once, validate it, and return receipts."""
    pending = set(PAYLOADS)
    while pending:
        kind, body, nrec = recv_app(conn, session)
        if kind == b"T":
            log.warn("authenticated text received during payload-only mode; ignored (configuration mismatch, not attack)")
            continue
        if kind != b"P":
            raise ProtocolStateError(f"expected official payload, received application kind {kind!r}")
        name, data = unpack_named(body)
        if name not in pending:
            raise RecordError(f"unexpected or duplicate official payload '{name}'")
        digest = hashlib.sha256(data).hexdigest()
        expected = OFFICIAL_SHA256[name]
        if len(data) != PAYLOADS[name] or not constant_time.bytes_eq(digest.encode(), expected.encode()):
            raise RecordError(f"official payload '{name}' failed size/SHA-256 validation")
        log.ok(f"received '{name}' byte-exact in {nrec} record(s): SHA-256 {digest}")
        send_app(conn, session, b"R", f"{name}|{digest}".encode(), log)
        pending.remove(name)


def exchange_official_payloads(conn, session, log, client_first):
    """Deterministic bidirectional exchange that avoids full-duplex buffer deadlocks."""
    if client_first:
        send_official_payload_batch(conn, session, log)
        receive_official_payload_batch(conn, session, log)
    else:
        receive_official_payload_batch(conn, session, log)
        send_official_payload_batch(conn, session, log)


def _save_received_file(receive_dir, name, data):
    """Save under receive_dir without allowing paths or overwriting an existing file."""
    os.makedirs(receive_dir, exist_ok=True)
    safe_name = os.path.basename(name) or "received.bin"
    root, ext = os.path.splitext(safe_name)
    path = os.path.join(receive_dir, safe_name)
    counter = 1
    while os.path.exists(path):
        path = os.path.join(receive_dir, f"{root}.{counter}{ext}")
        counter += 1
    with open(path, "xb") as output:
        output.write(data)
    return path


def rx_loop(conn, session, log, me, events=None, auto_reply=False, sent_hashes=None, receive_dir=None):
    """Receive + decrypt + print every application message until the session ends."""
    try:
        while True:
            kind, body, nrec = recv_app(conn, session)
            if kind == b"T":
                log._p(col("1;33", f"\n  <{session.peer}> ") + body.decode("utf-8", "replace") +
                       col("2", f"   [decrypted from {nrec} record(s), authenticated]"))
                if auto_reply:
                    reply = f"{me} received your {len(body)}-byte message intact (sha256 {hashlib.sha256(body).hexdigest()[:16]}...)"
                    send_app(conn, session, b"T", reply.encode())
            elif kind == b"P":
                name, data = unpack_named(body)
                h = hashlib.sha256(data).hexdigest()
                official = OFFICIAL_SHA256.get(name)
                verdict = ("MATCHES the official SHA-256" if h == official else
                           "MISMATCH vs official SHA-256!" if official else "(not an official payload)")
                log._p(col("1;33", f"\n  <{session.peer}> sent file '{name}' ({len(data):,} B in {nrec} records)"))
                log._p(f"        SHA-256 {h}  -> " + col("32" if h == official else "33", verdict))
                if receive_dir:
                    try:
                        saved_path = _save_received_file(receive_dir, name, data)
                        log._p(col("32", f"        saved as {saved_path}"))
                    except OSError as e:
                        log.bad(f"could not save received file: {e}")
                send_app(conn, session, b"R", f"{name}|{h}".encode())
            elif kind == b"R":
                name, _, h = body.decode().partition("|")
                expected = sent_hashes.pop(name, None) if sent_hashes is not None else None
                expected = expected or OFFICIAL_SHA256.get(name)
                good = h == expected
                log._p(col("32" if good else "31", f"\n  [receipt] {session.peer} decrypted '{name}' byte-exact: "
                                                   f"sha256 {h[:24]}... "
                                                   f"{'(hash OK)' if good else '(hash MISMATCH)'}"))
                if events is not None:
                    events.put(name)
    except (SessionClosed, ConnectionError, OSError) as e:
        log._p(col("2", f"\n  [session with {session.peer} ended: {e}]"))
    except (RecordError, PeerAbort) as e:
        if not isinstance(e, PeerAbort):
            conn.send_alert(f"{type(e).__name__}: {e}")
        attack_detected(log, e)
    finally:
        session.closed = True
        if events is not None:
            events.put(None)


_STDIN_Q = queue.Queue()
_STDIN_STARTED = False


def stdin_lines():
    """Thread-fed stdin queue so the main loop can notice a closed session (works on Windows too)."""
    global _STDIN_STARTED
    if not _STDIN_STARTED:
        def reader():
            for line in sys.stdin:
                _STDIN_Q.put(line.rstrip("\r\n"))
            _STDIN_Q.put(None)
        threading.Thread(target=reader, daemon=True).start()
        _STDIN_STARTED = True
    return _STDIN_Q
# ============================================ END OF PROTOCOL CORE ============================================


