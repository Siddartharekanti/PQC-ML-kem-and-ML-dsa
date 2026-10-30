"""Mutually authenticated quantum-safe handshake (SIGMA / TLS 1.3 style, 1 round trip).

Roles: Alice = client / initiator, Bob = server / responder. Both are authenticated.

    Alice                                                         Bob
    CH = ClientHello(ver, suite, alg_ids, Alice, kid_A, Bob,
                     nonce_A, ek_A)                 ---->
                                                           check policy, pin(Alice), replay cache
                                                           (ss, ct) = KEM.Encaps(ek_A)
                                                    <----  SH = ServerHello(ver, suite, alg_ids, Bob,
                                                                 kid_B, Alice, nonce_B, ct)
                                                    <----  SV = Sign_B(ctx_s, TH(CH..SH))
                                                    <----  SF = HMAC(s_fin_key, TH(CH..SV))
    check suite echo, identities, pin(Bob)
    ss = KEM.Decaps(dk_A, ct); verify SV, SF
    CV = Sign_A(ctx_c, TH(CH..SF))                  ---->
    CF = HMAC(c_fin_key, TH(CH..CV))                ---->  verify CV, CF
    [traffic keys from TH(CH..CF)]                         [traffic keys from TH(CH..CF)]
    AES-256-GCM records  <==========================================>  AES-256-GCM records

* ek_A is a fresh ephemeral ML-KEM-768 key per session -> forward secrecy for traffic keys.
* Signatures use distinct FIPS 204 contexts for the two roles (no reflection / role swap) and
  cover the hash of the *whole* transcript so far: both identities, both key ids, both nonces,
  the suite id + algorithm identifiers, the KEM public key and the KEM ciphertext.
* Finished MACs give explicit key confirmation in both directions.
* Every check failure aborts the handshake (fail-closed) and wipes all secrets; a Session
  object (and therefore any traffic key) only exists after the final check succeeded.
"""
from __future__ import annotations

import os
from collections import OrderedDict

from . import wire
from .errors import (DecodeError, DowngradeError, HandshakeError, HandshakeReplayError,
                     IdentityMismatch, FinishedError, ProtocolStateError, QSCError)
from .identity import Identity, TrustStore
from .keyschedule import HandshakeKeys, Transcript, extract, finished_mac, finished_ok
from .record import Session
from .suites import PQC, SIG_ALGS, SUITES, Suite

PROTOCOL_VERSION = 1
CTX_SERVER = b"QFF26-P1/v1 server-verify"
CTX_CLIENT = b"QFF26-P1/v1 client-verify"
NONCE_LEN = 32


def _fail_closed(method):
    def wrapper(self, *a, **kw):
        if self.state == "FAILED":
            raise ProtocolStateError(f"handshake already failed: {self.error}")
        try:
            return method(self, *a, **kw)
        except Exception as e:  # noqa: BLE001
            self._abort(e)
            if isinstance(e, QSCError):
                raise
            raise HandshakeError(f"{type(e).__name__}: {e}") from e
    wrapper.__name__ = method.__name__
    wrapper.__doc__ = method.__doc__
    return wrapper


class _Base:
    state = "INIT"
    error = None
    session = None

    def _abort(self, e):
        self.state = "FAILED"
        self.error = f"{type(e).__name__}: {e}"
        self.session = None
        if getattr(self, "_keys", None):
            self._keys.wipe()
        self._keys = None
        self._kem_sk = None

    def _check_state(self, expected):
        if self.state != expected:
            raise ProtocolStateError(f"unexpected message in state {self.state} (expected {expected})")


def _suite_fields_ok(suite: Suite, f: dict, who: str):
    if f[wire.F_VERSION] != bytes([PROTOCOL_VERSION]):
        raise DowngradeError(f"{who}: unsupported protocol version {f[wire.F_VERSION].hex()}")
    if f[wire.F_ALGS] != suite.alg_string.encode():
        raise DowngradeError(f"{who}: algorithm identifiers {f[wire.F_ALGS]!r} do not match suite "
                             f"0x{suite.suite_id:04x} ({suite.alg_string})")


# =============================================================================== client
class ClientHandshake(_Base):
    """Alice. One object per connection attempt."""

    def __init__(self, identity: Identity, trust: TrustStore, server_name: str, suite: Suite = PQC):
        if identity.sig_alg != suite.sig_name:
            raise ValueError(f"identity uses {identity.sig_alg}, suite needs {suite.sig_name}")
        self.identity, self.trust, self.server_name, self.suite = identity, trust, server_name, suite
        self.transcript = Transcript()

    @_fail_closed
    def client_hello(self) -> bytes:
        self._check_state("INIT")
        self._nonce = os.urandom(NONCE_LEN)
        self._kem_sk, ek = self.suite.kem.keygen()
        ch = wire.encode(wire.CLIENT_HELLO, {
            wire.F_VERSION: bytes([PROTOCOL_VERSION]),
            wire.F_SUITE: self.suite.suite_id.to_bytes(2, "big"),
            wire.F_ALGS: self.suite.alg_string.encode(),
            wire.F_CLIENT_ID: self.identity.name.encode(),
            wire.F_CLIENT_KEY_ID: self.identity.key_id,
            wire.F_SERVER_ID: self.server_name.encode(),
            wire.F_CLIENT_NONCE: self._nonce,
            wire.F_KEM_PK: ek,
        })
        self.transcript.add(ch)
        self.state = "WAIT_SERVER_FLIGHT"
        return ch

    @_fail_closed
    def handle_server_flight(self, sh: bytes, sv: bytes, sf: bytes):
        """Process ServerHello, ServerVerify, ServerFinished; return (ClientVerify, ClientFinished)."""
        self._check_state("WAIT_SERVER_FLIGHT")
        s = self.suite
        f = wire.decode(sh, wire.SERVER_HELLO)
        if int.from_bytes(f[wire.F_SUITE], "big") != s.suite_id:
            raise DowngradeError(f"server selected suite 0x{f[wire.F_SUITE].hex()}, "
                                 f"client offered 0x{s.suite_id:04x} only")
        _suite_fields_ok(s, f, "ServerHello")
        server_id = f[wire.F_SERVER_ID].decode("utf-8", "replace")
        if server_id != self.server_name:
            raise IdentityMismatch(f"ServerHello is from '{server_id}', this session is bound to "
                                   f"'{self.server_name}'")
        if f[wire.F_CLIENT_ID] != self.identity.name.encode():
            raise IdentityMismatch(f"ServerHello names client '{f[wire.F_CLIENT_ID].decode('utf-8', 'replace')}',"
                                   f" not '{self.identity.name}'")
        server_pk = self.trust.lookup(server_id, s.sig_name, f[wire.F_SERVER_KEY_ID])
        if len(f[wire.F_KEM_CT]) != s.kem.ct_len:
            raise DecodeError(f"KEM ciphertext must be {s.kem.ct_len} B, got {len(f[wire.F_KEM_CT])}")
        th_sh = self.transcript.add(sh)

        ss = s.kem.decap(self._kem_sk, f[wire.F_KEM_CT])
        self._kem_sk = None
        self._keys = HandshakeKeys(extract(self._nonce + f[wire.F_SERVER_NONCE], ss), s.suite_id, th_sh)

        sig = wire.decode(sv, wire.SERVER_VERIFY)[wire.F_SIGNATURE]
        if len(sig) != s.sig.sig_len:
            raise DecodeError(f"server signature must be {s.sig.sig_len} B, got {len(sig)}")
        SIG_ALGS[s.sig_name].verify(server_pk, sig, th_sh, CTX_SERVER)
        th_sv = self.transcript.add(sv)

        if not finished_ok(self._keys.s_fin, th_sv, wire.decode(sf, wire.SERVER_FINISHED)[wire.F_FINISHED]):
            raise FinishedError("ServerFinished MAC mismatch (key confirmation failed)")
        th_sf = self.transcript.add(sf)

        cv = wire.encode(wire.CLIENT_VERIFY, {wire.F_SIGNATURE: self.identity.sign(th_sf, CTX_CLIENT)})
        th_cv = self.transcript.add(cv)
        cf = wire.encode(wire.CLIENT_FINISHED, {wire.F_FINISHED: finished_mac(self._keys.c_fin, th_cv)})
        th_full = self.transcript.add(cf)

        self.session = Session("client", s, server_id, self._keys.traffic(th_full), th_full)
        self._keys.wipe()
        self._keys = None
        self.state = "ESTABLISHED"
        return cv, cf

    def peer_aborted(self, reason: str) -> None:
        """Bob rejected our ClientVerify/ClientFinished and sent an abort alert (1-RTT, as in
        TLS 1.3 the client derives keys before the server has checked its authentication).
        Tear the provisional session down so its traffic keys can never be used."""
        if self.session is not None:
            self.session.closed, self.session.close_reason = True, f"peer aborted: {reason}"
        self._abort(HandshakeError(f"peer aborted: {reason}"))


# =============================================================================== server
class ReplayCache:
    """Bounded cache of ClientHello nonces already seen by this server (handshake replay)."""

    def __init__(self, capacity: int = 100_000):
        self.capacity = capacity
        self._seen: OrderedDict = OrderedDict()

    def check_and_add(self, nonce: bytes):
        if nonce in self._seen:
            raise HandshakeReplayError("ClientHello nonce already seen: replayed handshake rejected")
        self._seen[nonce] = None
        if len(self._seen) > self.capacity:
            self._seen.popitem(last=False)


class ServerConfig:
    """Bob's long-lived configuration (shared by all connections)."""

    def __init__(self, name: str, identities, trust: TrustStore, allowed_suites=(PQC,),
                 replay_cache: ReplayCache | None = None):
        self.name = name
        self.identities = {i.sig_alg: i for i in identities}
        self.trust = trust
        self.allowed = {s.suite_id: s for s in allowed_suites}
        self.replay_cache = replay_cache if replay_cache is not None else ReplayCache()


class ServerHandshake(_Base):
    """Bob. One object per incoming connection."""

    def __init__(self, config: ServerConfig):
        self.cfg = config
        self.transcript = Transcript()
        self.suite = None

    @_fail_closed
    def handle_client_hello(self, ch: bytes):
        """Process ClientHello; return the server flight (ServerHello, ServerVerify, ServerFinished)."""
        self._check_state("INIT")
        f = wire.decode(ch, wire.CLIENT_HELLO)
        sid = int.from_bytes(f[wire.F_SUITE], "big")
        if sid not in self.cfg.allowed:
            known = f"{SUITES[sid].label} " if sid in SUITES else ""
            raise DowngradeError(f"suite {known}0x{sid:04x} not permitted by server policy "
                                 f"(allowed: {', '.join(f'0x{x:04x}' for x in self.cfg.allowed)})")
        s = self.suite = self.cfg.allowed[sid]
        _suite_fields_ok(s, f, "ClientHello")
        if f[wire.F_SERVER_ID] != self.cfg.name.encode():
            raise IdentityMismatch(f"ClientHello is addressed to "
                                   f"'{f[wire.F_SERVER_ID].decode('utf-8', 'replace')}', not '{self.cfg.name}'")
        if s.sig_name not in self.cfg.identities:
            raise DowngradeError(f"server has no {s.sig_name} identity")
        client_id = f[wire.F_CLIENT_ID].decode("utf-8", "replace")
        self._client_pk = self.cfg.trust.lookup(client_id, s.sig_name, f[wire.F_CLIENT_KEY_ID])
        self._client_id = client_id
        if len(f[wire.F_KEM_PK]) != s.kem.pk_len:
            raise DecodeError(f"KEM public key must be {s.kem.pk_len} B, got {len(f[wire.F_KEM_PK])}")
        self.cfg.replay_cache.check_and_add(f[wire.F_CLIENT_NONCE])
        self.transcript.add(ch)

        ss, ct = s.kem.encap(f[wire.F_KEM_PK])
        nonce_s = os.urandom(NONCE_LEN)
        me = self.cfg.identities[s.sig_name]
        sh = wire.encode(wire.SERVER_HELLO, {
            wire.F_VERSION: bytes([PROTOCOL_VERSION]),
            wire.F_SUITE: s.suite_id.to_bytes(2, "big"),
            wire.F_ALGS: s.alg_string.encode(),
            wire.F_SERVER_ID: self.cfg.name.encode(),
            wire.F_SERVER_KEY_ID: me.key_id,
            wire.F_CLIENT_ID: f[wire.F_CLIENT_ID],
            wire.F_SERVER_NONCE: nonce_s,
            wire.F_KEM_CT: ct,
        })
        th_sh = self.transcript.add(sh)
        self._keys = HandshakeKeys(extract(f[wire.F_CLIENT_NONCE] + nonce_s, ss), s.suite_id, th_sh)
        sv = wire.encode(wire.SERVER_VERIFY, {wire.F_SIGNATURE: me.sign(th_sh, CTX_SERVER)})
        th_sv = self.transcript.add(sv)
        sf = wire.encode(wire.SERVER_FINISHED, {wire.F_FINISHED: finished_mac(self._keys.s_fin, th_sv)})
        self.transcript.add(sf)
        self.state = "WAIT_CLIENT_AUTH"
        return sh, sv, sf

    @_fail_closed
    def handle_client_auth(self, cv: bytes, cf: bytes) -> Session:
        """Process ClientVerify + ClientFinished; return the established Session."""
        self._check_state("WAIT_CLIENT_AUTH")
        s = self.suite
        th_sf = self.transcript.digest()
        sig = wire.decode(cv, wire.CLIENT_VERIFY)[wire.F_SIGNATURE]
        if len(sig) != s.sig.sig_len:
            raise DecodeError(f"client signature must be {s.sig.sig_len} B, got {len(sig)}")
        SIG_ALGS[s.sig_name].verify(self._client_pk, sig, th_sf, CTX_CLIENT)
        th_cv = self.transcript.add(cv)
        if not finished_ok(self._keys.c_fin, th_cv, wire.decode(cf, wire.CLIENT_FINISHED)[wire.F_FINISHED]):
            raise FinishedError("ClientFinished MAC mismatch (key confirmation failed)")
        th_full = self.transcript.add(cf)
        self.session = Session("server", s, self._client_id, self._keys.traffic(th_full), th_full)
        self._keys.wipe()
        self._keys = None
        self.state = "ESTABLISHED"
        return self.session


# =============================================================================== in-process driver
def run_handshake(client: ClientHandshake, server: ServerHandshake, tamper=None):
    """Run a complete handshake in-process. `tamper(name, bytes) -> bytes` models a MITM.

    Returns (client_session, server_session, messages) where messages maps short names
    (CH, SH, SV, SF, CV, CF) to the bytes actually delivered. Raises on any abort.
    """
    t = tamper or (lambda name, b: b)
    msgs = {}
    msgs["CH"] = t("CH", client.client_hello())
    sh, sv, sf = server.handle_client_hello(msgs["CH"])
    msgs["SH"], msgs["SV"], msgs["SF"] = t("SH", sh), t("SV", sv), t("SF", sf)
    cv, cf = client.handle_server_flight(msgs["SH"], msgs["SV"], msgs["SF"])
    msgs["CV"], msgs["CF"] = t("CV", cv), t("CF", cf)
    try:
        server.handle_client_auth(msgs["CV"], msgs["CF"])
    except HandshakeError as e:  # Bob's abort alert reaches Alice
        client.peer_aborted(f"{type(e).__name__}: {e}")
        raise
    return client.session, server.session, msgs
