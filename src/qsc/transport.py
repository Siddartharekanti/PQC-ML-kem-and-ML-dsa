"""TCP transport for the channel (loopback benchmarks, two-machine demo, Platform D link emulation).

Framing on the stream is the protocol's own encoding - nothing else is added:
  handshake message : type (1) || body_len (4) || body
  abort alert       : 0xFF || len (4) || UTF-8 reason   (sent by the side that aborts, then close)
  record            : 14-byte header (contains its length) || ciphertext || tag

Byte counters on Conn give the exact application-layer bytes per direction
(TCP/IP headers are not included and are identical for both suites).
"""
from __future__ import annotations

import socket
import struct
import time

from . import wire
from .errors import DecodeError, HandshakeError, RecordError, SessionClosed
from .handshake import ClientHandshake, ServerConfig, ServerHandshake
from .record import HDR as REC_HDR, MAX_RECORD_PLAINTEXT, TAG_LEN

ALERT = 0xFF


class PeerAbort(HandshakeError):
    code = "peer_abort"


class Conn:
    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.sent = self.received = 0
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass

    def send(self, data: bytes) -> None:
        self.sock.sendall(data)
        self.sent += len(data)

    def recv_exact(self, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = self.sock.recv(min(n - len(buf), 1 << 20))
            if not chunk:
                raise ConnectionError("connection closed by peer")
            buf += chunk
        self.received += n
        return bytes(buf)

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass

    # --- framing -----------------------------------------------------------------
    def read_handshake(self) -> bytes:
        hdr = self.recv_exact(wire.MSG_HDR.size)
        mtype, blen = wire.MSG_HDR.unpack(hdr)
        if blen > wire.MAX_BODY:
            raise DecodeError("handshake message too large")
        body = self.recv_exact(blen)
        if mtype == ALERT:
            raise PeerAbort("peer aborted the handshake: " + body.decode("utf-8", "replace"))
        return hdr + body

    def send_alert(self, reason: str) -> None:
        body = reason.encode()[:1024]
        try:
            self.send(struct.pack(">BI", ALERT, len(body)) + body)
        except OSError:
            pass

    def read_record(self) -> bytes:
        first = self.recv_exact(1)
        if first[0] == ALERT:  # peer aborted (e.g. Bob rejected our ClientVerify / ClientFinished)
            blen = struct.unpack(">I", self.recv_exact(4))[0]
            reason = self.recv_exact(min(blen, 1024)).decode("utf-8", "replace")
            raise PeerAbort("peer aborted: " + reason)
        hdr = first + self.recv_exact(REC_HDR.size - 1)
        length = REC_HDR.unpack(hdr)[3]
        if length > MAX_RECORD_PLAINTEXT + TAG_LEN:
            raise RecordError("record too large")
        return hdr + self.recv_exact(length)

    def send_message(self, session, message: bytes, record_size: int = 16384) -> int:
        recs = session.send_message(message, record_size)
        self.send(b"".join(recs))
        return len(recs)

    def receive_message(self, session) -> bytes:
        def gen():
            while True:
                yield self.read_record()
        return session.receive_message(gen())


# ------------------------------------------------------------------------- client side
def client_handshake(conn: Conn, hs: ClientHandshake) -> dict:
    """Run Alice's side over `conn`. Returns timing/bytes stats; hs.session is established."""
    t0 = time.perf_counter_ns()
    conn.send(hs.client_hello())
    sh, sv, sf = conn.read_handshake(), conn.read_handshake(), conn.read_handshake()
    try:
        cv, cf = hs.handle_server_flight(sh, sv, sf)
    except HandshakeError as e:
        conn.send_alert(f"{type(e).__name__}: {e}")
        raise
    conn.send(cv + cf)
    t1 = time.perf_counter_ns()
    return {"handshake_ns": t1 - t0, "c2s_bytes": conn.sent, "s2c_bytes": conn.received}


def connect(host: str, port: int, hs: ClientHandshake, timeout: float = 30.0):
    t0 = time.perf_counter_ns()
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(None)  # Remove timeout so session does not suddenly drop during idle
    t1 = time.perf_counter_ns()
    conn = Conn(sock)
    stats = client_handshake(conn, hs)
    stats["tcp_connect_ns"] = t1 - t0
    return hs.session, conn, stats


# ------------------------------------------------------------------------- server side
def server_handshake(conn: Conn, cfg: ServerConfig):
    hs = ServerHandshake(cfg)
    try:
        ch = conn.read_handshake()
        conn.send(b"".join(hs.handle_client_hello(ch)))
        cv, cf = conn.read_handshake(), conn.read_handshake()
        return hs.handle_client_auth(cv, cf)
    except HandshakeError as e:
        if not isinstance(e, PeerAbort):
            conn.send_alert(f"{type(e).__name__}: {e}")
        raise


def echo_handler(session, conn: Conn):
    """Default application: reply to each message with its SHA-256 (proves byte-exact receipt)."""
    import hashlib
    while True:
        try:
            msg = conn.receive_message(session)
        except (ConnectionError, SessionClosed):
            return
        conn.send_message(session, hashlib.sha256(msg).hexdigest().encode())


def serve(cfg: ServerConfig, host="127.0.0.1", port=0, handler=echo_handler, ready=None, max_conns=None,
          log=None):
    """Sequential accept loop (one connection at a time; enough for benchmarks and the demo)."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(64)
    if ready is not None:
        ready.put(srv.getsockname()[1])
    n = 0
    try:
        while max_conns is None or n < max_conns:
            sock, addr = srv.accept()
            n += 1
            conn = Conn(sock)
            try:
                session = server_handshake(conn, cfg)
                if log:
                    log(f"[bob] authenticated session with '{session.peer}' from {addr[0]} "
                        f"({session.suite.label}, keys {session.key_fingerprint[:16]}...)")
                handler(session, conn)
            except (HandshakeError, ConnectionError, OSError, RecordError) as e:
                if log:
                    log(f"[bob] connection from {addr[0]} rejected: {type(e).__name__}: {e}")
            finally:
                conn.close()
    finally:
        srv.close()
